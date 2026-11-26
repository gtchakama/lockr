// Helpers that turn the vault path plus a session (or an interactive
// password) into an unlocked vault. Boundary: the only code that decides
// whether a command may prompt or must fail with "locked".
package cmd

import (
	"errors"
	"path/filepath"

	"fmt"
	"github.com/gtchakama/lockr/internal/audit"
	"github.com/gtchakama/lockr/internal/crypto"
	"github.com/gtchakama/lockr/internal/session"
	"github.com/gtchakama/lockr/internal/vault"
	"os"
)

func vaultPath() (string, error) { return vault.DefaultPath() }

// unlockSealed opens s with the session DEK; if there is no session and
// prompting is allowed on a TTY, asks for the password and caches a session.
func unlockSealed(s *vault.Sealed, allowPrompt bool) (*vault.Unlocked, error) {
	dek, _, err := session.Load(s.ID(), now())
	if err == nil {
		u, uerr := s.UnlockWithDEK(dek)
		crypto.Zero(dek)
		if uerr == nil {
			return u, nil
		}
		// Stale session (e.g. vault recreated): fall through as locked.
		_ = session.Clear(s.ID())
	} else if !errors.Is(err, session.ErrLocked) {
		return nil, err
	}
	if !allowPrompt || !stdinIsTTY() {
		return nil, errLocked()
	}
	pw, err := readPassword("Master password: ")
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(pw)
	u, err := s.Unlock(pw)
	if err != nil {
		return nil, err
	}
	dek = u.DEK()
	defer crypto.Zero(dek)
	if err := session.Save(u.ID(), dek, defaultTTL, now()); err != nil {
		fmt.Fprintf(stderr, "lockr: warning: could not cache session: %v\n", err)
	}
	return u, nil
}

// openRead unlocks the vault for a read-only command.
func openRead(allowPrompt bool) (*vault.Unlocked, string, error) {
	path, err := vaultPath()
	if err != nil {
		return nil, "", err
	}
	s, err := vault.Read(path)
	if err != nil {
		return nil, "", err
	}
	u, err := unlockSealed(s, allowPrompt)
	return u, path, err
}

// withWrite locks the vault file, unlocks it, runs fn and saves on success.
func withWrite(fn func(u *vault.Unlocked) error) error {
	path, err := vaultPath()
	if err != nil {
		return err
	}
	if _, err := vault.Read(path); err != nil {
		return err
	}
	release, err := vault.Lock(path)
	if err != nil {
		return err
	}
	defer release()
	s, err := vault.Read(path)
	if err != nil {
		return err
	}
	u, err := unlockSealed(s, true)
	if err != nil {
		return err
	}
	defer u.Close()
	if err := fn(u); err != nil {
		return err
	}
	return u.Save()
}

// recordAudit appends an audit entry next to the vault; failures only warn.
func recordAudit(path, command, ref string) {
	cwd, _ := os.Getwd()
	e := audit.Entry{Time: now().UTC(), Cmd: command, Ref: ref, Parent: audit.ParentChain(), CWD: cwd}
	if err := audit.Append(filepath.Join(filepath.Dir(path), "audit.jsonl"), e); err != nil {
		fmt.Fprintf(stderr, "lockr: warning: audit log: %v\n", err)
	}
}
