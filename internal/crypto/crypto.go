// Package crypto holds Lockr's primitives: Argon2id key derivation and
// XChaCha20-Poly1305 authenticated encryption. Callers own key lifetimes and
// should Zero keys when done.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var randReader io.Reader = rand.Reader

// KeySize is the size of every symmetric key (KEK and DEK).
const KeySize = chacha20poly1305.KeySize

// NonceSize is the XChaCha20-Poly1305 nonce size; 192 bits makes random
// nonces safe for the lifetime of a vault.
const NonceSize = chacha20poly1305.NonceSizeX

// Overhead is the authentication tag size.
const Overhead = chacha20poly1305.Overhead

// SaltSize is the Argon2id salt size.
const SaltSize = 16

// KDFParams are Argon2id cost parameters. Memory is in KiB.
type KDFParams struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// DefaultKDF follows RFC 9106's second recommended option (256 MiB, t=3).
var DefaultKDF = KDFParams{Memory: 256 * 1024, Time: 3, Threads: 1}

const (
	minKDFMemory  = 8 * 1024
	maxKDFMemory  = 2 * 1024 * 1024 // 2 GiB (RFC 9106 high-memory option)
	minKDFTime    = 1
	maxKDFTime    = 64
	minKDFThreads = 1
	maxKDFThreads = 64
)

// Validate rejects parameters too weak (downgrade) or too large (DoS) to be
// accepted from a vault header or passed to vault creation.
func (p KDFParams) Validate() error {
	if p.Memory < minKDFMemory || p.Time < minKDFTime || p.Threads < minKDFThreads {
		return fmt.Errorf("KDF parameters too weak: m=%dKiB t=%d p=%d", p.Memory, p.Time, p.Threads)
	}
	if p.Memory > maxKDFMemory || p.Time > maxKDFTime || p.Threads > maxKDFThreads {
		return fmt.Errorf("KDF parameters exceed maximum: m=%dKiB t=%d p=%d", p.Memory, p.Time, p.Threads)
	}
	return nil
}

// DeriveKEK derives the key-encryption key from a password and salt.
func DeriveKEK(password, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, KeySize)
}

// Random returns n cryptographically random bytes.
func Random(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("invalid random length %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return nil, fmt.Errorf("reading randomness: %w", err)
	}
	return b, nil
}

// ErrAuth means ciphertext failed authentication: wrong key or tampering.
var ErrAuth = errors.New("authentication failed")

// Seal encrypts plaintext under key with a fresh random nonce, binding aad.
func Seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	if nonce, err = Random(NonceSize); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates ciphertext.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce length %d: want %d", len(nonce), NonceSize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// Zero overwrites b. Go may still hold copies; this limits, not eliminates,
// how long key material stays in memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
