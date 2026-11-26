//go:build !windows

// Advisory file locking so concurrent lockr writers cannot interleave a
// read-modify-write of the vault.
package vault

import (
	"os"
	"syscall"
)

// Lock takes an exclusive advisory lock on <path>.lock and returns a release
// function. Readers do not lock: writes are atomic renames.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
