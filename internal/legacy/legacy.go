// Package legacy decrypts a Lockr v1 vault so it can be migrated. Boundary:
// read-only support for the old file format; v2 never writes this format.
package legacy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

// Secret is one v1 value.
type Secret struct {
	Value     string
	UpdatedAt time.Time
}

// ErrWrongPassword is returned when authentication of the v1 file fails.
var ErrWrongPassword = errors.New("wrong password or corrupted v1 vault")

type file struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type plain struct {
	Version int                                   `json:"version"`
	Data    map[string]map[string]json.RawMessage `json:"data"`
}

// Decrypt decrypts a v1 vault file and returns group -> key -> secret.
func Decrypt(data, password []byte) (map[string]map[string]Secret, error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("not a v1 vault: %w", err)
	}
	salt, err1 := base64.StdEncoding.DecodeString(f.Salt)
	nonce, err2 := base64.StdEncoding.DecodeString(f.Nonce)
	ct, err3 := base64.StdEncoding.DecodeString(f.Ciphertext)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("not a v1 vault: bad base64")
	}
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("not a v1 vault: bad nonce")
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}
	var p plain
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, fmt.Errorf("decode v1 payload: %w", err)
	}
	out := make(map[string]map[string]Secret, len(p.Data))
	for g, keys := range p.Data {
		m := make(map[string]Secret, len(keys))
		for k, raw := range keys {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				m[k] = Secret{Value: s}
				continue
			}
			var obj struct {
				Value     string    `json:"value"`
				UpdatedAt time.Time `json:"updated_at"`
			}
			if err := json.Unmarshal(raw, &obj); err != nil {
				return nil, fmt.Errorf("decode v1 entry %s/%s: %w", g, k, err)
			}
			m[k] = Secret{Value: obj.Value, UpdatedAt: obj.UpdatedAt}
		}
		out[g] = m
	}
	return out, nil
}
