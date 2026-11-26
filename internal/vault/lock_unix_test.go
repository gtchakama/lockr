//go:build !windows

package vault

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLockFlockEINTRAndError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.lockr")

	t.Run("retries on EINTR", func(t *testing.T) {
		orig := flock
		t.Cleanup(func() { flock = orig })
		attempts := 0
		flock = func(fd int, how int) error {
			attempts++
			if how == syscall.LOCK_EX && attempts == 1 {
				return syscall.EINTR
			}
			return orig(fd, how)
		}
		unlock, err := Lock(path)
		if err != nil {
			t.Fatalf("Lock after EINTR unexpected error: %v", err)
		}
		unlock()
		if attempts < 2 {
			t.Fatalf("expected flock retry on EINTR, got %d attempts", attempts)
		}
	})

	t.Run("returns non-EINTR error", func(t *testing.T) {
		orig := flock
		t.Cleanup(func() { flock = orig })
		flock = func(int, int) error { return syscall.EIO }
		if _, err := Lock(path); !errors.Is(err, syscall.EIO) {
			t.Fatalf("Lock err = %v, want EIO", err)
		}
	})
}
