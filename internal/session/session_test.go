package session

import (
	"bytes"
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
