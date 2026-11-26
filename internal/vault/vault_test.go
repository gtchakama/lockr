package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gtchakama/lockr/internal/crypto"
	"github.com/gtchakama/lockr/internal/model"
)

var testKDF = crypto.KDFParams{Memory: 8 * 1024, Time: 1, Threads: 1}

func TestDefaultPath(t *testing.T) {
	t.Run("env override", func(t *testing.T) {
		t.Setenv(envVaultPath, "/custom/path/vault.lockr")
		got, err := DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath() unexpected error: %v", err)
		}
		if got != "/custom/path/vault.lockr" {
			t.Fatalf("DefaultPath() = %q, want /custom/path/vault.lockr", got)
		}
	})

	t.Run("default home dir", func(t *testing.T) {
		t.Setenv(envVaultPath, "")
		home := t.TempDir()
		t.Setenv("HOME", home)
		got, err := DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath() unexpected error: %v", err)
		}
		want := filepath.Join(home, defaultDir, defaultFile)
		if got != want {
			t.Fatalf("DefaultPath() = %q, want %q", got, want)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("missing HOME", func(t *testing.T) {
			t.Setenv(envVaultPath, "")
			t.Setenv("HOME", "")
			if _, err := DefaultPath(); err == nil {
				t.Fatalf("DefaultPath() with empty HOME succeeded, want error")
			}
		})
	}
}

func TestCreateReadUnlockRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "vault.lockr")
	pw := []byte("correct-horse-battery-staple")

	u, err := Create(path, pw, testKDF)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	origID := u.ID()
	if len(origID.String()) != idSize*2 {
		t.Fatalf("ID().String() = %q, want %d hex chars", origID.String(), idSize*2)
	}

	now := time.Now().UTC().Truncate(time.Second)
	u.Body.Projects["stripe"] = map[model.Name]*model.Item{
		"live": {
			Kind:      model.KindSecret,
			Env:       "STRIPE_API_KEY",
			Secret:    []byte("sk_live_123456"),
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	u.Body.Projects["github"] = map[model.Name]*model.Item{
		"work": {
			Kind:      model.KindLogin,
			URL:       "https://github.com",
			Username:  "alice",
			Secret:    []byte("p@ssw0rd"),
			TOTPSeed:  "GEZDGNBVGY3TQOJQ",
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	if err := u.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%q) error: %v", path, err)
		}
		if info.Mode().Perm() != fileMode {
			t.Fatalf("vault perms = %o, want %o", info.Mode().Perm(), fileMode)
		}
	}

	dek := u.DEK()
	if len(dek) != crypto.KeySize {
		t.Fatalf("len(DEK) = %d, want %d", len(dek), crypto.KeySize)
	}
	// Mutating returned DEK copy must not affect Unlocked.
	dekCopy := append([]byte(nil), dek...)
	dekCopy[0] ^= 0xff
	if bytes.Equal(u.DEK(), dekCopy) {
		t.Fatalf("DEK() did not return a defensive copy")
	}

	// Close zeroes key and prevents subsequent saves / password changes.
	u.Close()
	if u.DEK() != nil {
		t.Fatalf("DEK() after Close() = %x, want nil", u.DEK())
	}
	if err := u.Save(); err == nil {
		t.Fatalf("Save() after Close() succeeded, want error")
	}
	if err := u.ChangePassword([]byte("newpw"), testKDF); err == nil {
		t.Fatalf("ChangePassword() after Close() succeeded, want error")
	}

	// Read and unlock with password.
	s, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if s.ID() != origID {
		t.Fatalf("Sealed.ID() = %s, want %s", s.ID(), origID)
	}
	if s.Path() != path {
		t.Fatalf("Sealed.Path() = %q, want %q", s.Path(), path)
	}

	// Wrong password fails.
	if _, err := s.Unlock([]byte("wrong-password")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unlock(wrong) err = %v, want ErrWrongPassword", err)
	}

	// Correct password succeeds and restores body.
	u2, err := s.Unlock(pw)
	if err != nil {
		t.Fatalf("Unlock(correct) error: %v", err)
	}
	defer u2.Close()

	it, err := u2.Body.Item(model.Ref{Project: "github", Item: "work"})
	if err != nil {
		t.Fatalf("Body.Item error: %v", err)
	}
	if it.Username != "alice" || string(it.Secret) != "p@ssw0rd" || it.TOTPSeed != "GEZDGNBVGY3TQOJQ" {
		t.Fatalf("restored item mismatch: %+v", it)
	}

	// UnlockWithDEK works with cached DEK and rejects wrong/bad-length DEKs.
	u3, err := s.UnlockWithDEK(dek)
	if err != nil {
		t.Fatalf("UnlockWithDEK(valid) error: %v", err)
	}
	defer u3.Close()
	if !reflect.DeepEqual(u3.Body, u2.Body) {
		t.Fatalf("UnlockWithDEK body mismatch:\ngot  %+v\nwant %+v", u3.Body, u2.Body)
	}

	wrongDEK := append([]byte(nil), dek...)
	wrongDEK[0] ^= 0x01
	if _, err := s.UnlockWithDEK(wrongDEK); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("UnlockWithDEK(wrong) err = %v, want ErrWrongPassword", err)
	}
	if _, err := s.UnlockWithDEK([]byte("short")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("UnlockWithDEK(short) err = %v, want ErrWrongPassword", err)
	}
}

func TestChangePassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.lockr")
	oldPW := []byte("old-password")
	newPW := []byte("new-password")

	u, err := Create(path, oldPW, testKDF)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	defer u.Close()

	u.Body.Projects["app"] = map[model.Name]*model.Item{
		"key": {Kind: model.KindSecret, Secret: []byte("val")},
	}
	if err := u.Save(); err != nil {
		t.Fatalf("Save error: %v", err)
	}
	origDEK := u.DEK()
	origID := u.ID()

	// Invalid KDF rejected without changing password.
	if err := u.ChangePassword(newPW, crypto.KDFParams{Memory: 1, Time: 1, Threads: 1}); err == nil {
		t.Fatalf("ChangePassword with weak KDF succeeded, want error")
	}

	// Rollback header if Save fails (read-only dir on Unix).
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		err := u.ChangePassword([]byte("failed-pw"), testKDF)
		_ = os.Chmod(dir, 0o700)
		if err == nil {
			t.Fatalf("ChangePassword in read-only dir succeeded, want error")
		}
		// Header must have rolled back so subsequent Save still uses oldPW.
		if err := u.Save(); err != nil {
			t.Fatalf("Save after rollback error: %v", err)
		}
		sCheck, err := Read(path)
		if err != nil {
			t.Fatal(err)
		}
		uCheck, err := sCheck.Unlock(oldPW)
		if err != nil {
			t.Fatalf("Unlock(oldPW) after failed ChangePassword rollback failed: %v", err)
		}
		uCheck.Close()
	}

	// Valid ChangePassword: old fails, new works, DEK and ID unchanged.
	if err := u.ChangePassword(newPW, testKDF); err != nil {
		t.Fatalf("ChangePassword error: %v", err)
	}
	if !bytes.Equal(u.DEK(), origDEK) {
		t.Fatalf("ChangePassword mutated DEK")
	}
	if u.ID() != origID {
		t.Fatalf("ChangePassword mutated ID")
	}

	s, err := Read(path)
	if err != nil {
		t.Fatalf("Read after ChangePassword error: %v", err)
	}
	if _, err := s.Unlock(oldPW); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unlock(oldPW) err = %v, want ErrWrongPassword", err)
	}
	uNew, err := s.Unlock(newPW)
	if err != nil {
		t.Fatalf("Unlock(newPW) error: %v", err)
	}
	uNew.Close()

	uDEK, err := s.UnlockWithDEK(origDEK)
	if err != nil {
		t.Fatalf("UnlockWithDEK(origDEK) after ChangePassword error: %v", err)
	}
	defer uDEK.Close()
	it, err := uDEK.Body.Item(model.Ref{Project: "app", Item: "key"})
	if err != nil || string(it.Secret) != "val" {
		t.Fatalf("item mismatch after ChangePassword: %+v, err=%v", it, err)
	}
}

func TestTamperEveryHeaderAndBodyRegion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.lockr")
	pw := []byte("hunter2")

	u, err := Create(path, pw, testKDF)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	dek := u.DEK()
	u.Body.Projects["p"] = map[model.Name]*model.Item{
		"i": {Kind: model.KindSecret, Secret: []byte("secret-value")},
	}
	if err := u.Save(); err != nil {
		t.Fatalf("Save error: %v", err)
	}
	u.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	// Offsets from vault layout:
	// [0:5]     magic "LOCKR"
	// [5]       version 0x02
	// [6:22]    id (16)
	// [22:26]   kdf memory (u32 BE)
	// [26:30]   kdf time (u32 BE)
	// [30]      kdf threads (u8)
	// [31:34]   kdf pad (3 zero bytes)
	// [34:50]   salt (16)
	// [50:74]   wrap nonce (24)
	// [74:122]  wrapped DEK (48)
	// [122:146] body nonce (24)
	// [146:]    body ciphertext + tag
	tests := []struct {
		name           string
		offset         int
		xorMask        byte
		wantParseError bool
	}{
		{name: "magic", offset: 0, xorMask: 0x01, wantParseError: true},
		{name: "version", offset: 5, xorMask: 0x01, wantParseError: true},
		{name: "id start", offset: 6, xorMask: 0x01},
		{name: "id end", offset: 21, xorMask: 0x80},
		{name: "kdf memory valid-range bit flip", offset: 25, xorMask: 0x01},
		{name: "kdf memory high bit DoS", offset: 22, xorMask: 0x80, wantParseError: true},
		{name: "kdf time valid-range bit flip", offset: 29, xorMask: 0x02},
		{name: "kdf time high bit DoS", offset: 26, xorMask: 0x80, wantParseError: true},
		{name: "kdf threads valid-range bit flip", offset: 30, xorMask: 0x02},
		{name: "kdf threads zero", offset: 30, xorMask: 0x01, wantParseError: true},
		{name: "kdf pad byte 0", offset: 31, xorMask: 0x01, wantParseError: true},
		{name: "kdf pad byte 1", offset: 32, xorMask: 0x01, wantParseError: true},
		{name: "kdf pad byte 2", offset: 33, xorMask: 0x01, wantParseError: true},
		{name: "salt start", offset: 34, xorMask: 0x01},
		{name: "salt end", offset: 49, xorMask: 0x80},
		{name: "wrap nonce start", offset: 50, xorMask: 0x01},
		{name: "wrap nonce end", offset: 73, xorMask: 0x80},
		{name: "wrapped DEK start", offset: 74, xorMask: 0x01},
		{name: "wrapped DEK tag", offset: 121, xorMask: 0x80},
		{name: "body nonce start", offset: 122, xorMask: 0x01},
		{name: "body nonce end", offset: 145, xorMask: 0x80},
		{name: "body ciphertext", offset: 146, xorMask: 0x01},
		{name: "body tag", offset: len(raw) - 1, xorMask: 0x01},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]byte(nil), raw...)
			tampered[tc.offset] ^= tc.xorMask

			s, err := parse(tampered)
			if tc.wantParseError {
				if err == nil {
					t.Fatalf("parse succeeded on tampered %s (offset %d), want error", tc.name, tc.offset)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse unexpected error on %s: %v", tc.name, err)
			}
			if _, err := s.Unlock(pw); !errors.Is(err, ErrWrongPassword) {
				t.Fatalf("Unlock on tampered %s err = %v, want ErrWrongPassword", tc.name, err)
			}
			if _, err := s.UnlockWithDEK(dek); !errors.Is(err, ErrWrongPassword) {
				t.Fatalf("UnlockWithDEK on tampered %s err = %v, want ErrWrongPassword", tc.name, err)
			}
		})
	}
}

func TestParseMalformedAndLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.lockr")
	u, err := Create(path, []byte("pw"), testKDF)
	if err != nil {
		t.Fatal(err)
	}
	u.Close()
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Truncated files at every boundary below minFileSize.
	for _, n := range []int{0, 1, 4, 5, 6, 21, 22, 33, 34, 49, 50, 73, 74, 121, 122, 145, 146, minFileSize - 1} {
		if _, err := parse(valid[:n]); err == nil {
			t.Fatalf("parse(valid[:%d]) succeeded, want error", n)
		}
	}

	// Bad magic (full length).
	badMagic := append([]byte(nil), valid...)
	copy(badMagic[:5], "WRONG")
	if _, err := parse(badMagic); err == nil {
		t.Fatalf("parse(badMagic) succeeded, want error")
	}

	// Unsupported versions (both short and full length).
	for _, v := range []byte{0, 1, 3, 255} {
		badVer := append([]byte(nil), valid...)
		badVer[5] = v
		if _, err := parse(badVer); err == nil || !strings.Contains(err.Error(), "unsupported vault version") {
			t.Fatalf("parse(version=%d) err = %v, want unsupported vault version", v, err)
		}
		shortBadVer := []byte{'L', 'O', 'C', 'K', 'R', v}
		if _, err := parse(shortBadVer); err == nil || !strings.Contains(err.Error(), "unsupported vault version") {
			t.Fatalf("parse(short version=%d) err = %v, want unsupported vault version", v, err)
		}
	}

	// Legacy v1 JSON detection.
	for _, raw := range []string{`{"version":1}`, "  \n\t{\"entries\":[]}"} {
		if _, err := parse([]byte(raw)); !errors.Is(err, ErrLegacy) {
			t.Fatalf("parse(%q) err = %v, want ErrLegacy", raw, err)
		}
	}

	// KDF downgrade below floor rejected on parse.
	weakMem := append([]byte(nil), valid...)
	binary.BigEndian.PutUint32(weakMem[22:26], 1024)
	if _, err := parse(weakMem); err == nil {
		t.Fatalf("parse(weak KDF memory) succeeded, want error")
	}
}

func TestReadErrorsAndPermissions(t *testing.T) {
	dir := t.TempDir()

	// ErrNoVault.
	if _, err := Read(filepath.Join(dir, "missing.lockr")); !errors.Is(err, ErrNoVault) {
		t.Fatalf("Read(missing) err = %v, want ErrNoVault", err)
	}

	path := filepath.Join(dir, "vault.lockr")
	u, err := Create(path, []byte("pw"), testKDF)
	if err != nil {
		t.Fatal(err)
	}
	u.Close()

	if runtime.GOOS != "windows" {
		for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(path); !errors.Is(err, ErrPermissions) {
				t.Fatalf("Read(mode %o) err = %v, want ErrPermissions", mode, err)
			}
		}
		// Restore 0600 -> succeeds.
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err != nil {
			t.Fatalf("Read(mode 0600) unexpected error: %v", err)
		}

		// Unreadable file (0200) -> open error (not ErrNoVault / ErrPermissions).
		if err := os.Chmod(path, 0o200); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		if _, err := Read(path); err == nil || errors.Is(err, ErrNoVault) || errors.Is(err, ErrPermissions) {
			t.Fatalf("Read(mode 0200) err = %v, want permission open error", err)
		}

		// Directory with 0700 -> io.ReadAll error.
		subDir := filepath.Join(dir, "adir")
		if err := os.Mkdir(subDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(subDir); err == nil {
			t.Fatalf("Read(directory) succeeded, want error")
		}
	}

	// Malformed content on disk -> parse error returned through Read.
	badFile := filepath.Join(dir, "bad.lockr")
	if err := os.WriteFile(badFile, []byte("not-a-vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(badFile); err == nil {
		t.Fatalf("Read(badFile) succeeded, want error")
	}
}

func TestBackupAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.lockr")
	bakPath := path + ".bak"
	pw := []byte("pw")

	u, err := Create(path, pw, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	// No .bak after initial Create.
	if _, err := os.Stat(bakPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no .bak after Create, stat err = %v", err)
	}
	firstBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Second save creates .bak equal to the first version.
	u.Body.Projects["p"] = map[model.Name]*model.Item{
		"one": {Kind: model.KindSecret, Secret: []byte("v2")},
	}
	if err := u.Save(); err != nil {
		t.Fatalf("second Save error: %v", err)
	}
	bakBytes, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("ReadFile(.bak) error: %v", err)
	}
	if !bytes.Equal(bakBytes, firstBytes) {
		t.Fatalf(".bak content does not match previous vault version")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(bakPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != fileMode {
			t.Fatalf(".bak perms = %o, want %o", info.Mode().Perm(), fileMode)
		}
	}

	// No leftover .tmp files in dir.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %q", e.Name())
		}
	}

	// Error paths in writeAtomic / writeAtomicFile.
	if runtime.GOOS != "windows" {
		// Existing vault unreadable -> backup read error.
		if err := os.Chmod(path, 0o200); err != nil {
			t.Fatal(err)
		}
		err = u.Save()
		_ = os.Chmod(path, 0o600)
		if err == nil {
			t.Fatalf("Save with unreadable existing vault succeeded, want error")
		}
	}

	// Backup path is a non-empty directory -> rename fails, temp cleaned up.
	_ = os.Remove(bakPath)
	if err := os.Mkdir(bakPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bakPath, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := u.Save(); err == nil {
		t.Fatalf("Save when .bak is a non-empty directory succeeded, want error")
	}
	_ = os.RemoveAll(bakPath)

	// Verify temp file was cleaned up after rename failure.
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file %q not cleaned up after failed rename", e.Name())
		}
	}
}

func TestCreateErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.lockr")

	u, err := Create(path, []byte("pw"), testKDF)
	if err != nil {
		t.Fatal(err)
	}
	u.Close()

	// ErrExists.
	if got, err := Create(path, []byte("pw"), testKDF); !errors.Is(err, ErrExists) || got != nil {
		t.Fatalf("Create(existing) = (%v, %v), want (nil, ErrExists)", got, err)
	}

	// Invalid KDF.
	if got, err := Create(filepath.Join(dir, "weak.lockr"), []byte("pw"), crypto.KDFParams{}); err == nil || got != nil {
		t.Fatalf("Create(weak KDF) = (%v, %v), want (nil, error)", got, err)
	}

	// Path under a regular file -> Stat error.
	if got, err := Create(filepath.Join(path, "child.lockr"), []byte("pw"), testKDF); err == nil || got != nil {
		t.Fatalf("Create(under file) = (%v, %v), want (nil, error)", got, err)
	}

	if runtime.GOOS != "windows" {
		roDir := filepath.Join(dir, "ro")
		if err := os.Mkdir(roDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })

		// MkdirAll fails inside read-only dir.
		if got, err := Create(filepath.Join(roDir, "sub", "vault.lockr"), []byte("pw"), testKDF); err == nil || got != nil {
			t.Fatalf("Create(mkdir fail) = (%v, %v), want (nil, error)", got, err)
		}

		// Save fails inside existing read-only dir (must return nil Unlocked and error).
		if got, err := Create(filepath.Join(roDir, "vault.lockr"), []byte("pw"), testKDF); err == nil || got != nil {
			t.Fatalf("Create(save fail) = (%v, %v), want (nil, error)", got, err)
		}
	}

	// RNG failure at each stage of Create (ID, DEK, wrap salt).
	boom := errors.New("rng boom")
	for failOnCall := 1; failOnCall <= 3; failOnCall++ {
		orig := randBytes
		calls := 0
		randBytes = func(n int) ([]byte, error) {
			calls++
			if calls == failOnCall {
				return nil, boom
			}
			return orig(n)
		}
		got, err := Create(filepath.Join(dir, "rng-fail.lockr"), []byte("pw"), testKDF)
		randBytes = orig
		if !errors.Is(err, boom) || got != nil {
			t.Fatalf("Create(failOnCall=%d) = (%v, %v), want (nil, %v)", failOnCall, got, err, boom)
		}
	}
}

type fakeSyncFile struct {
	writeErr error
	syncErr  error
	closeErr error
	closed   bool
	synced   bool
	buf      bytes.Buffer
}

func (f *fakeSyncFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.buf.Write(p)
}

func (f *fakeSyncFile) Sync() error {
	f.synced = true
	return f.syncErr
}

func (f *fakeSyncFile) Close() error {
	f.closed = true
	return f.closeErr
}

func TestWriteSyncClose(t *testing.T) {
	writeErr := errors.New("write err")
	syncErr := errors.New("sync err")
	closeErr := errors.New("close err")

	tests := []struct {
		name    string
		f       *fakeSyncFile
		wantErr error
	}{
		{name: "success", f: &fakeSyncFile{}},
		{name: "write fails and closes", f: &fakeSyncFile{writeErr: writeErr}, wantErr: writeErr},
		{name: "sync fails and closes", f: &fakeSyncFile{syncErr: syncErr}, wantErr: syncErr},
		{name: "close fails", f: &fakeSyncFile{closeErr: closeErr}, wantErr: closeErr},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := writeSyncClose(tc.f, []byte("payload"))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("writeSyncClose err = %v, want %v", err, tc.wantErr)
			}
			if !tc.f.closed {
				t.Fatalf("writeSyncClose did not close file")
			}
			if tc.wantErr == nil && (!tc.f.synced || tc.f.buf.String() != "payload") {
				t.Fatalf("writeSyncClose did not write+sync payload")
			}
		})
	}
}

func TestOpenMalformedAndNullProjectsBody(t *testing.T) {
	makeSealed := func(plaintext []byte) (*Sealed, []byte) {
		dek, err := crypto.Random(crypto.KeySize)
		if err != nil {
			t.Fatal(err)
		}
		salt, err := crypto.Random(crypto.SaltSize)
		if err != nil {
			t.Fatal(err)
		}
		h := header{kdf: testKDF, salt: salt}
		kek := crypto.DeriveKEK([]byte("pw"), salt, testKDF)
		defer crypto.Zero(kek)
		h.wrapNonce, h.wrappedDEK, err = crypto.Seal(kek, dek, h.prefix())
		if err != nil {
			t.Fatal(err)
		}
		nonce, ct, err := crypto.Seal(dek, plaintext, h.bytes())
		if err != nil {
			t.Fatal(err)
		}
		return &Sealed{hdr: h, bodyNonce: nonce, bodyCT: ct}, dek
	}

	// Corrupt JSON inside valid ciphertext.
	sBad, dekBad := makeSealed([]byte("{not valid json"))
	if _, err := sBad.UnlockWithDEK(dekBad); err == nil || !strings.Contains(err.Error(), "decoding vault body") {
		t.Fatalf("UnlockWithDEK(bad JSON) err = %v, want decoding error", err)
	}

	// Explicit null projects map gets initialized to non-nil empty map.
	sNull, dekNull := makeSealed([]byte(`{"schema_version":1,"projects":null}`))
	u, err := sNull.UnlockWithDEK(dekNull)
	if err != nil {
		t.Fatalf("UnlockWithDEK(null projects) unexpected error: %v", err)
	}
	defer u.Close()
	if u.Body.Projects == nil {
		t.Fatalf("UnlockWithDEK(null projects) left Body.Projects nil")
	}
}

func TestLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.lockr")

	unlock1, err := Lock(path)
	if err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	if runtime.GOOS != "windows" {
		acquired := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			unlock2, err := Lock(path)
			if err != nil {
				done <- err
				return
			}
			close(acquired)
			unlock2()
			done <- nil
		}()

		select {
		case <-acquired:
			t.Fatalf("second Lock acquired while first lock still held")
		case <-time.After(50 * time.Millisecond):
		}

		unlock1()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("second Lock error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("second Lock did not acquire after first released")
		}

		// Lock in missing directory fails.
		if _, err := Lock(filepath.Join(dir, "no-such-dir", "vault.lockr")); err == nil {
			t.Fatalf("Lock in nonexistent dir succeeded, want error")
		}
	} else {
		unlock1()
	}
}

func TestVaultRoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(2026))
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

	randName := func() model.Name {
		n := 1 + rng.Intn(16)
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return model.Name(b)
	}

	dir := t.TempDir()
	for iter := 0; iter < 15; iter++ {
		path := filepath.Join(dir, "prop-"+string(rune('a'+iter))+".lockr")
		pw := make([]byte, 1+rng.Intn(32))
		rng.Read(pw)

		u, err := Create(path, pw, testKDF)
		if err != nil {
			t.Fatalf("iter %d Create error: %v", iter, err)
		}

		nProjects := rng.Intn(4)
		for p := 0; p < nProjects; p++ {
			proj := randName()
			if u.Body.Projects[proj] == nil {
				u.Body.Projects[proj] = map[model.Name]*model.Item{}
			}
			nItems := 1 + rng.Intn(3)
			for i := 0; i < nItems; i++ {
				itemName := randName()
				secret := make([]byte, rng.Intn(64))
				rng.Read(secret)
				kind := model.KindSecret
				if rng.Intn(2) == 0 {
					kind = model.KindLogin
				}
				u.Body.Projects[proj][itemName] = &model.Item{
					Kind:      kind,
					URL:       "https://example.com/" + string(itemName),
					Username:  "user_" + string(itemName),
					Secret:    secret,
					CreatedAt: time.Unix(int64(1700000000+iter), 0).UTC(),
					UpdatedAt: time.Unix(int64(1700000100+iter), 0).UTC(),
				}
			}
		}

		if err := u.Save(); err != nil {
			u.Close()
			t.Fatalf("iter %d Save error: %v", iter, err)
		}
		wantBody := u.Body
		dek := u.DEK()
		u.Close()

		s, err := Read(path)
		if err != nil {
			t.Fatalf("iter %d Read error: %v", iter, err)
		}
		u2, err := s.Unlock(pw)
		if err != nil {
			t.Fatalf("iter %d Unlock error: %v", iter, err)
		}
		if !reflect.DeepEqual(u2.Body, wantBody) {
			u2.Close()
			t.Fatalf("iter %d round-trip body mismatch", iter)
		}
		u2.Close()

		wrongPW := append([]byte(nil), pw...)
		wrongPW[0] ^= 0xff
		if _, err := s.Unlock(wrongPW); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("iter %d wrong password err = %v, want ErrWrongPassword", iter, err)
		}

		u3, err := s.UnlockWithDEK(dek)
		if err != nil {
			t.Fatalf("iter %d UnlockWithDEK error: %v", iter, err)
		}
		if !reflect.DeepEqual(u3.Body, wantBody) {
			u3.Close()
			t.Fatalf("iter %d UnlockWithDEK body mismatch", iter)
		}
		u3.Close()
	}
}

func FuzzParse(f *testing.F) {
	// Seed with empty, legacy, short, bad version, and a real valid vault header/file.
	f.Add([]byte{})
	f.Add([]byte(`{"entries":[]}`))
	f.Add([]byte("LOCKR\x01"))
	f.Add([]byte("LOCKR\x02"))
	f.Add([]byte("LOCKR\x03" + strings.Repeat("A", 200)))

	// Synthesize a valid-looking minimal file for the seed corpus.
	seed := make([]byte, minFileSize)
	copy(seed[:5], magic)
	seed[5] = version
	binary.BigEndian.PutUint32(seed[22:26], testKDF.Memory)
	binary.BigEndian.PutUint32(seed[26:30], testKDF.Time)
	seed[30] = testKDF.Threads
	f.Add(seed)

	// Non-zero padding seed.
	badPad := append([]byte(nil), seed...)
	badPad[31] = 1
	f.Add(badPad)

	zeroDEK := make([]byte, crypto.KeySize)
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := parse(data)
		if err != nil {
			return
		}
		if len(s.hdr.salt) != crypto.SaltSize {
			t.Fatalf("unexpected salt len %d", len(s.hdr.salt))
		}
		if len(s.hdr.wrapNonce) != crypto.NonceSize {
			t.Fatalf("unexpected wrapNonce len %d", len(s.hdr.wrapNonce))
		}
		if len(s.hdr.wrappedDEK) != wrappedSize {
			t.Fatalf("unexpected wrappedDEK len %d", len(s.hdr.wrappedDEK))
		}
		if len(s.bodyNonce) != crypto.NonceSize {
			t.Fatalf("unexpected bodyNonce len %d", len(s.bodyNonce))
		}
		if len(s.bodyCT) < crypto.Overhead {
			t.Fatalf("unexpected bodyCT len %d", len(s.bodyCT))
		}
		if err := s.hdr.kdf.Validate(); err != nil {
			t.Fatalf("parse accepted invalid KDF: %v", err)
		}
		// Must never panic when attempting body open / header serialization.
		_, _ = s.UnlockWithDEK(zeroDEK)
	})
}
