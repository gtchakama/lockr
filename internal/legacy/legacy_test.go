package legacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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
