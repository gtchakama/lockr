// Package crypto encapsulates all cryptographic operations for Lockr,
// including key derivation (Argon2) and symmetric encryption (AES-256-GCM).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"golang.org/x/crypto/argon2"
)

// GenerateSalt returns a cryptographically secure random 16-byte salt.
// This is used alongside the user's master password to derive the encryption key.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKey derives a 32-byte encryption key from a master password and salt.
// It uses Argon2id, which is resistant to both GPU and side-channel attacks.
func DeriveKey(password string, salt []byte) []byte {
	// Parameters: time=1, memory=64MB, threads=4, keyLen=32 bytes
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// Encrypt secures the given plaintext using AES-256-GCM.
// It returns the resulting ciphertext and the randomly generated nonce used,
// both of which must be saved to decrypt the data later.
func Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	
	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	
	// Seal encrypts and authenticates the plaintext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt opens and authenticates AES-256-GCM ciphertext.
// It requires the correct 32-byte key and the exact nonce used during encryption.
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Open decrypts and verifies the ciphertext
	return gcm.Open(nil, nonce, ciphertext, nil)
}
