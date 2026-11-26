//go:build !windows

// Advisory file locking so concurrent lockr writers cannot interleave a
// read-modify-write of the vault.
package vault

import (
	"errors"
	"os"
	"syscall"
)

var flock = syscall.Flock

// Lock takes an exclusive advisory lock on <path>.lock and returns a release
// function. Readers do not lock: writes are atomic renames.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, err
	}
	for {
		err = flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
