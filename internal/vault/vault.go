// Package vault reads and writes the encrypted vault file.
//
// Layout (all integers big-endian):
//
//	magic "LOCKR" | version 0x02 | vault id (16) | kdf mem u32, time u32,
//	threads u8, 3 pad | salt (16) | wrap nonce (24) | wrapped DEK (48) |
//	body nonce (24) | body ciphertext + tag
//
// The password derives a KEK (Argon2id) that wraps a random DEK; the DEK
// encrypts the body. Both AEAD operations bind the header as associated
// data, so tampering with any header field makes decryption fail. A Sealed
// value never exposes plaintext; an Unlocked value can only be obtained by
// presenting the password or a DEK that authenticates.
package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gtchakama/lockr/internal/crypto"
	"github.com/gtchakama/lockr/internal/model"
)

const (
	magic   = "LOCKR"
	version = 2

	idSize       = 16
	kdfSize      = 12
	prefixSize   = len(magic) + 1 + idSize + kdfSize + crypto.SaltSize // AAD for DEK wrap
	wrappedSize  = crypto.KeySize + crypto.Overhead
	headerSize   = prefixSize + crypto.NonceSize + wrappedSize // AAD for body
	minFileSize  = headerSize + crypto.NonceSize + crypto.Overhead
	fileMode     = 0o600
	dirMode      = 0o700
	defaultDir   = ".lockr"
	defaultFile  = "vault.lockr"
	envVaultPath = "LOCKR_VAULT"
)

// Errors callers map to exit codes.
var (
	ErrNoVault       = errors.New("no vault found: run `lockr init`")
	ErrExists        = errors.New("a vault already exists at this path")
	ErrWrongPassword = errors.New("wrong password or corrupted vault")
	ErrLegacy        = errors.New("this is a Lockr v1 vault: run `lockr import-v1` to migrate it")
	ErrPermissions   = errors.New("vault file is readable by other users: run `chmod 600` on it")
)

// ID identifies a vault; sessions are keyed by it.
type ID [idSize]byte

// String renders the ID as hex.
func (id ID) String() string { return fmt.Sprintf("%x", id[:]) }

// DefaultPath returns $LOCKR_VAULT or ~/.lockr/vault.lockr.
func DefaultPath() (string, error) {
	if p := os.Getenv(envVaultPath); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, defaultDir, defaultFile), nil
}

type header struct {
	id         ID
	kdf        crypto.KDFParams
	salt       []byte
	wrapNonce  []byte
	wrappedDEK []byte
}

func (h header) prefix() []byte {
	var b bytes.Buffer
	b.WriteString(magic)
	b.WriteByte(version)
	b.Write(h.id[:])
	_ = binary.Write(&b, binary.BigEndian, h.kdf.Memory)
	_ = binary.Write(&b, binary.BigEndian, h.kdf.Time)
	b.Write([]byte{h.kdf.Threads, 0, 0, 0})
	b.Write(h.salt)
	return b.Bytes()
}

func (h header) bytes() []byte {
	out := h.prefix()
	out = append(out, h.wrapNonce...)
	return append(out, h.wrappedDEK...)
}

// Sealed is a vault read from disk but not decrypted.
type Sealed struct {
	path      string
	hdr       header
	bodyNonce []byte
	bodyCT    []byte
}

// ID returns the vault's identifier.
func (s *Sealed) ID() ID { return s.hdr.id }

// Path returns where the vault was read from.
func (s *Sealed) Path() string { return s.path }

// Read loads and parses a vault file without decrypting it.
func Read(path string) (*Sealed, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoVault
	}
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrPermissions
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := parse(data)
	if err != nil {
		return nil, err
	}
	s.path = path
	return s, nil
}

func parse(data []byte) (*Sealed, error) {
	if len(bytes.TrimSpace(data)) > 0 && bytes.TrimSpace(data)[0] == '{' {
		return nil, ErrLegacy
	}
	if len(data) < minFileSize || string(data[:len(magic)]) != magic {
		return nil, errors.New("not a Lockr vault file")
	}
	if v := data[len(magic)]; v != version {
		return nil, fmt.Errorf("unsupported vault version %d", v)
	}
	off := len(magic) + 1
	var h header
	copy(h.id[:], data[off:off+idSize])
	off += idSize
	h.kdf.Memory = binary.BigEndian.Uint32(data[off:])
	h.kdf.Time = binary.BigEndian.Uint32(data[off+4:])
	h.kdf.Threads = data[off+8]
	off += kdfSize
	h.salt = clone(data[off : off+crypto.SaltSize])
	off += crypto.SaltSize
	h.wrapNonce = clone(data[off : off+crypto.NonceSize])
	off += crypto.NonceSize
	h.wrappedDEK = clone(data[off : off+wrappedSize])
	off += wrappedSize
	if err := h.kdf.Validate(); err != nil {
		return nil, err
	}
	return &Sealed{
		hdr:       h,
		bodyNonce: clone(data[off : off+crypto.NonceSize]),
		bodyCT:    clone(data[off+crypto.NonceSize:]),
	}, nil
}

// Unlock decrypts the vault with the master password.
func (s *Sealed) Unlock(password []byte) (*Unlocked, error) {
	kek := crypto.DeriveKEK(password, s.hdr.salt, s.hdr.kdf)
	defer crypto.Zero(kek)
	dek, err := crypto.Open(kek, s.hdr.wrapNonce, s.hdr.wrappedDEK, s.hdr.prefix())
	if err != nil {
		return nil, ErrWrongPassword
	}
	return s.open(dek)
}

// UnlockWithDEK decrypts the vault with a cached data key (from a session).
func (s *Sealed) UnlockWithDEK(dek []byte) (*Unlocked, error) {
	return s.open(clone(dek))
}

func (s *Sealed) open(dek []byte) (*Unlocked, error) {
	pt, err := crypto.Open(dek, s.bodyNonce, s.bodyCT, s.hdr.bytes())
	if err != nil {
		crypto.Zero(dek)
		return nil, ErrWrongPassword
	}
	defer crypto.Zero(pt)
	body := model.NewBody()
	if err := json.Unmarshal(pt, body); err != nil {
		crypto.Zero(dek)
		return nil, fmt.Errorf("decoding vault body: %w", err)
	}
	if body.Projects == nil {
		body.Projects = map[model.Name]map[model.Name]*model.Item{}
	}
	return &Unlocked{path: s.path, hdr: s.hdr, dek: dek, Body: body}, nil
}

// Unlocked is a decrypted vault. Call Close when done to zero the DEK.
type Unlocked struct {
	path string
	hdr  header
	dek  []byte
	Body *model.Body
}

// ID returns the vault's identifier.
func (u *Unlocked) ID() ID { return u.hdr.id }

// DEK returns a copy of the data key for caching in a session.
func (u *Unlocked) DEK() []byte { return clone(u.dek) }

// Close zeroes the data key.
func (u *Unlocked) Close() { crypto.Zero(u.dek) }

// Create makes a new vault at path. It fails if one already exists.
func Create(path string, password []byte, kdf crypto.KDFParams) (*Unlocked, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, ErrExists
	}
	if err := kdf.Validate(); err != nil {
		return nil, err
	}
	idb, err := crypto.Random(idSize)
	if err != nil {
		return nil, err
	}
	dek, err := crypto.Random(crypto.KeySize)
	if err != nil {
		return nil, err
	}
	u := &Unlocked{path: path, dek: dek, Body: model.NewBody()}
	copy(u.hdr.id[:], idb)
	if err := u.wrap(password, kdf); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, err
	}
	return u, u.Save()
}

// wrap derives a new KEK from password with a fresh salt and re-wraps the DEK.
func (u *Unlocked) wrap(password []byte, kdf crypto.KDFParams) error {
	salt, err := crypto.Random(crypto.SaltSize)
	if err != nil {
		return err
	}
	h := header{id: u.hdr.id, kdf: kdf, salt: salt}
	kek := crypto.DeriveKEK(password, salt, kdf)
	defer crypto.Zero(kek)
	if h.wrapNonce, h.wrappedDEK, err = crypto.Seal(kek, u.dek, h.prefix()); err != nil {
		return err
	}
	u.hdr = h
	return nil
}

// ChangePassword re-wraps the DEK under a new password and saves. The body
// is re-encrypted with the same DEK, so existing sessions stay valid.
func (u *Unlocked) ChangePassword(password []byte, kdf crypto.KDFParams) error {
	if err := kdf.Validate(); err != nil {
		return err
	}
	if err := u.wrap(password, kdf); err != nil {
		return err
	}
	return u.Save()
}

// Save encrypts the body with a fresh nonce and writes the file atomically,
// keeping the previous version as <path>.bak.
func (u *Unlocked) Save() error {
	pt, err := json.Marshal(u.Body)
	if err != nil {
		return err
	}
	defer crypto.Zero(pt)
	hdr := u.hdr.bytes()
	nonce, ct, err := crypto.Seal(u.dek, pt, hdr)
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(hdr)+len(nonce)+len(ct))
	out = append(append(append(out, hdr...), nonce...), ct...)
	return writeAtomic(u.path, out)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if old, err := os.ReadFile(path); err == nil {
		if err := writeFileSync(path+".bak", old); err != nil {
			return fmt.Errorf("writing backup: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := writeFileSync(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func writeFileSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, fileMode)
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
