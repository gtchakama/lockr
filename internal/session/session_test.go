package session

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/gtchakama/lockr/internal/vault"
	"github.com/zalando/go-keyring"
)

func TestSessionLifecycle(t *testing.T) {
	keyring.MockInit()
	id := vault.ID{1, 2, 3}
	now := time.Now()

	if _, _, err := Load(id, now); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	dek := []byte("0123456789abcdef0123456789abcdef")
	if err := Save(id, dek, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	got, exp, err := Load(id, now.Add(time.Minute))
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("load: %v %q", err, got)
	}
	if !exp.Equal(now.Add(time.Hour)) {
		t.Fatalf("expires %v", exp)
	}
	if _, _, err := Load(id, now.Add(2*time.Hour)); !errors.Is(err, ErrLocked) {
		t.Fatalf("expired: %v", err)
	}
	// expired entry was deleted
	if _, err := keyring.Get(service(id), user); err == nil {
		t.Fatal("expired entry not deleted")
	}
}

func TestClearAndGarbage(t *testing.T) {
	keyring.MockInit()
	id := vault.ID{9}
	if err := Clear(id); err != nil {
		t.Fatal(err)
	}
	_ = keyring.Set(service(id), user, "!!notbase64")
	if _, _, err := Load(id, time.Now()); !errors.Is(err, ErrLocked) {
		t.Fatalf("garbage: %v", err)
	}
	if err := Save(id, []byte("k"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := Clear(id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(id, time.Now()); !errors.Is(err, ErrLocked) {
		t.Fatal("still unlocked")
	}
}

func setRaw(t *testing.T, id vault.ID, raw string) {
	t.Helper()
	if err := keyring.Set(service(id), user, raw); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsMalformedEntries(t *testing.T) {
	keyring.MockInit()
	id := vault.ID{4}
	enc := base64.StdEncoding.EncodeToString
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	cases := map[string]string{
		"valid base64, not json": enc([]byte("not json")),
		"bad dek base64":         enc([]byte(`{"dek":"!!!","expires_at":"` + future + `"}`)),
		"empty dek":              enc([]byte(`{"dek":"","expires_at":"` + future + `"}`)),
		"missing expiry":         enc([]byte(`{"dek":"` + enc([]byte("k")) + `"}`)),
	}
	for name, raw := range cases {
		setRaw(t, id, raw)
		dek, exp, err := Load(id, time.Now())
		if !errors.Is(err, ErrLocked) || dek != nil || !exp.IsZero() {
			t.Errorf("%s: dek=%q exp=%v err=%v", name, dek, exp, err)
		}
	}
}

func TestLoadExpiryBoundary(t *testing.T) {
	keyring.MockInit()
	id := vault.ID{5}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := Save(id, []byte("k"), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(id, now.Add(time.Hour-time.Nanosecond)); err != nil {
		t.Fatalf("just before expiry: %v", err)
	}
	// expiry instant itself counts as expired
	if _, _, err := Load(id, now.Add(time.Hour)); !errors.Is(err, ErrLocked) {
		t.Fatalf("at expiry: %v", err)
	}
}

func TestSessionsAreIsolatedPerVault(t *testing.T) {
	keyring.MockInit()
	a, b := vault.ID{1}, vault.ID{2}
	now := time.Now()
	if err := Save(a, []byte("key-a"), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(b, now); !errors.Is(err, ErrLocked) {
		t.Fatalf("vault b saw vault a's session: %v", err)
	}
	if err := Clear(b); err != nil {
		t.Fatal(err)
	}
	if got, _, err := Load(a, now); err != nil || string(got) != "key-a" {
		t.Fatalf("clearing b affected a: %q %v", got, err)
	}
}

func TestKeyringFailuresSurface(t *testing.T) {
	boom := errors.New("keychain unavailable")
	keyring.MockInitWithError(boom)
	t.Cleanup(keyring.MockInit)
	id := vault.ID{6}
	now := time.Now()
	if err := Save(id, []byte("k"), time.Hour, now); !errors.Is(err, boom) {
		t.Fatalf("Save: %v", err)
	}
	if err := Clear(id); !errors.Is(err, boom) {
		t.Fatalf("Clear should surface non-NotFound errors: %v", err)
	}
	// An unreadable keychain means locked, never a different error.
	if _, _, err := Load(id, now); !errors.Is(err, ErrLocked) {
		t.Fatalf("Load: %v", err)
	}
}

func TestSaveRejectsUnencodableExpiry(t *testing.T) {
	keyring.MockInit()
	id := vault.ID{7}
	// Years beyond 9999 cannot be marshalled as RFC 3339.
	far := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	if err := Save(id, []byte("k"), 24*time.Hour, far); err == nil {
		t.Fatal("expected marshal error")
	}
	if _, err := keyring.Get(service(id), user); err == nil {
		t.Fatal("nothing should have been stored")
	}
}
