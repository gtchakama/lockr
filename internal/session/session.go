// Package session caches an unlocked vault's DEK in the OS keychain for a
// fixed TTL. Boundary: it knows nothing about vault contents or crypto; it only
// stores, loads and expires an opaque key keyed by vault ID.
package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/gtchakama/lockr/internal/vault"
	"github.com/zalando/go-keyring"
)

// ErrLocked means no valid session exists for the vault.
var ErrLocked = errors.New("vault is locked")

const user = "session"

type payload struct {
	DEK       string    `json:"dek"`
	ExpiresAt time.Time `json:"expires_at"`
}

func service(id vault.ID) string { return "lockr:" + id.String() }

// Save stores the DEK with an expiry of now+ttl.
func Save(id vault.ID, dek []byte, ttl time.Duration, now time.Time) error {
	b, err := json.Marshal(payload{
		DEK:       base64.StdEncoding.EncodeToString(dek),
		ExpiresAt: now.Add(ttl).UTC(),
	})
	if err != nil {
		return err
	}
	return keyring.Set(service(id), user, base64.StdEncoding.EncodeToString(b))
}

// Load returns the cached DEK, or ErrLocked if missing, undecodable or expired.
// Expired entries are deleted.
func Load(id vault.ID, now time.Time) ([]byte, time.Time, error) {
	raw, err := keyring.Get(service(id), user)
	if err != nil {
		return nil, time.Time{}, ErrLocked
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, time.Time{}, ErrLocked
	}
	var p payload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, time.Time{}, ErrLocked
	}
	dek, err := base64.StdEncoding.DecodeString(p.DEK)
	if err != nil || len(dek) == 0 {
		return nil, time.Time{}, ErrLocked
	}
	if !now.Before(p.ExpiresAt) {
		_ = Clear(id)
		return nil, time.Time{}, ErrLocked
	}
	return dek, p.ExpiresAt, nil
}

// Clear removes the session; nil if nothing was stored.
func Clear(id vault.ID) error {
	err := keyring.Delete(service(id), user)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
