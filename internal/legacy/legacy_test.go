package legacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func build(t *testing.T, pw string, plaintext []byte) []byte {
	t.Helper()
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 4, 32)
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	ct := g.Seal(nil, nonce, plaintext, nil)
	out, _ := json.Marshal(map[string]string{
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
	})
	return out
}

func TestRoundTrip(t *testing.T) {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	pt, _ := json.Marshal(map[string]any{
		"version": 2,
		"data": map[string]any{
			"work": map[string]any{"API": map[string]any{"value": "s3cret", "updated_at": ts}},
		},
	})
	got, err := Decrypt(build(t, "pw", pt), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	s := got["work"]["API"]
	if s.Value != "s3cret" || !s.UpdatedAt.Equal(ts) {
		t.Fatalf("%+v", s)
	}
}

func TestOldPlainStrings(t *testing.T) {
	pt := []byte(`{"version":1,"data":{"g":{"k":"plain"}}}`)
	got, err := Decrypt(build(t, "pw", pt), []byte("pw"))
	if err != nil || got["g"]["k"].Value != "plain" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestWrongPassword(t *testing.T) {
	f := build(t, "pw", []byte(`{"version":1,"data":{}}`))
	if _, err := Decrypt(f, []byte("nope")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("got %v", err)
	}
}

func TestMalformedInputs(t *testing.T) {
	good := build(t, "pw", []byte(`{"version":1,"data":{}}`))
	var f map[string]string
	if err := json.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	with := func(k, v string) []byte {
		g := map[string]string{}
		for kk, vv := range f {
			g[kk] = vv
		}
		g[k] = v
		b, _ := json.Marshal(g)
		return b
	}
	b64 := base64.StdEncoding.EncodeToString
	cases := []struct {
		name, wantMsg string
		data          []byte
	}{
		{"not json", "not a v1 vault", []byte("this is not json")},
		{"empty", "not a v1 vault", nil},
		{"bad salt base64", "bad base64", with("salt", "!!!")},
		{"bad nonce base64", "bad base64", with("nonce", "!!!")},
		{"bad ciphertext base64", "bad base64", with("ciphertext", "!!!")},
		{"short nonce", "bad nonce", with("nonce", b64([]byte("short")))},
		{"empty nonce", "bad nonce", with("nonce", "")},
	}
	for _, c := range cases {
		got, err := Decrypt(c.data, []byte("pw"))
		if err == nil || got != nil || !strings.Contains(err.Error(), c.wantMsg) {
			t.Errorf("%s: got %v, %v; want error containing %q", c.name, got, err, c.wantMsg)
		}
	}
}

func TestShortOrTamperedCiphertextIsAuthFailure(t *testing.T) {
	good := build(t, "pw", []byte(`{"version":1,"data":{}}`))
	var f map[string]string
	_ = json.Unmarshal(good, &f)
	for name, ct := range map[string]string{
		"empty":     "",
		"too short": base64.StdEncoding.EncodeToString([]byte("abc")),
	} {
		f["ciphertext"] = ct
		b, _ := json.Marshal(f)
		if _, err := Decrypt(b, []byte("pw")); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// flip a bit in a valid ciphertext
	_ = json.Unmarshal(good, &f)
	raw, _ := base64.StdEncoding.DecodeString(f["ciphertext"])
	raw[0] ^= 1
	f["ciphertext"] = base64.StdEncoding.EncodeToString(raw)
	b, _ := json.Marshal(f)
	if _, err := Decrypt(b, []byte("pw")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("tampered: got %v", err)
	}
}

func TestBadPayloadAfterDecrypt(t *testing.T) {
	if _, err := Decrypt(build(t, "pw", []byte("not json")), []byte("pw")); err == nil ||
		!strings.Contains(err.Error(), "decode v1 payload") {
		t.Fatalf("got %v", err)
	}
	// an entry that is neither a string nor an object
	_, err := Decrypt(build(t, "pw", []byte(`{"data":{"g":{"k":123}}}`)), []byte("pw"))
	if err == nil || !strings.Contains(err.Error(), "g/k") {
		t.Fatalf("got %v", err)
	}
	// a bad timestamp inside an object entry
	_, err = Decrypt(build(t, "pw", []byte(`{"data":{"g":{"k":{"value":"v","updated_at":"yesterday"}}}}`)), []byte("pw"))
	if err == nil || !strings.Contains(err.Error(), "g/k") {
		t.Fatalf("got %v", err)
	}
}

func TestEmptyAndMixedGroups(t *testing.T) {
	pt := []byte(`{"version":2,"data":{"empty":{},"g":{"a":"x","b":{"value":"y"}}}}`)
	got, err := Decrypt(build(t, "pw", pt), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := got["empty"]; !ok || len(m) != 0 {
		t.Fatalf("empty group lost: %+v", got)
	}
	if got["g"]["a"].Value != "x" || got["g"]["b"].Value != "y" || !got["g"]["b"].UpdatedAt.IsZero() {
		t.Fatalf("%+v", got["g"])
	}
}

func TestCipherConstructionFailureIsReturned(t *testing.T) {
	good := build(t, "pw", []byte(`{"version":1,"data":{}}`))
	old := newBlock
	boom := errors.New("no aes")
	newBlock = func([]byte) (cipher.Block, error) { return nil, boom }
	t.Cleanup(func() { newBlock = old })
	if _, err := Decrypt(good, []byte("pw")); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}
