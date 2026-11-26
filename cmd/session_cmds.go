// init, unlock, lock, status, passwd and destroy: commands that manage the
// vault file and its session rather than items. Interactive-only where a
// password is involved, so an agent can never unlock the vault itself.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gtchakama/lockr/internal/crypto"
	"github.com/gtchakama/lockr/internal/session"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a new vault",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireTTY("init"); err != nil {
				return err
			}
			path, err := vaultPath()
			if err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil {
				return vault.ErrExists
			}
			pw, err := newPassword("New master password")
			if err != nil {
				return err
			}
			defer crypto.Zero(pw)
			u, err := vault.Create(path, pw, kdf)
			if err != nil {
				return err
			}
			defer u.Close()
			dek := u.DEK()
			defer crypto.Zero(dek)
			if err := session.Save(u.ID(), dek, defaultTTL, now()); err != nil {
				fmt.Fprintf(stderr, "lockr: warning: could not cache session: %v\n", err)
			}
			fmt.Fprintf(stdout, "Created vault at %s (unlocked for %s)\n", path, defaultTTL)
			return nil
		},
	}
}

func newUnlockCmd() *cobra.Command {
	var ttl time.Duration
	c := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault for a period (interactive only)",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			if !stdinIsTTY() {
				return errors.New("unlock must be run by the user in an interactive terminal; agents must not unlock the vault")
			}
			if ttl <= 0 {
				return usageErr("--ttl must be positive")
			}
			path, err := vaultPath()
			if err != nil {
				return err
			}
			s, err := vault.Read(path)
			if err != nil {
				return err
			}
			pw, err := readPassword("Master password: ")
			if err != nil {
				return err
			}
			defer crypto.Zero(pw)
			u, err := s.Unlock(pw)
			if err != nil {
				return err
			}
			defer u.Close()
			dek := u.DEK()
			defer crypto.Zero(dek)
			if err := session.Save(u.ID(), dek, ttl, now()); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Unlocked until %s\n", now().Add(ttl).Format(time.RFC3339))
			return nil
		},
	}
	c.Flags().DurationVar(&ttl, "ttl", defaultTTL, "how long the session lasts")
	return c
}

func newLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "End the current session",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			path, err := vaultPath()
			if err != nil {
				return err
			}
			s, err := vault.Read(path)
			if err != nil {
				return err
			}
			if err := session.Clear(s.ID()); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "Locked")
			return nil
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the vault is locked (never shows values)",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			path, err := vaultPath()
			if err != nil {
				return err
			}
			s, err := vault.Read(path)
			if err != nil {
				return err
			}
			dek, exp, err := session.Load(s.ID(), now())
			switch {
			case errors.Is(err, session.ErrLocked):
				fmt.Fprintf(stdout, "locked\nvault: %s\n", path)
			case err != nil:
				return err
			default:
				crypto.Zero(dek)
				fmt.Fprintf(stdout, "unlocked (expires %s)\nvault: %s\n", exp.Format(time.RFC3339), path)
			}
			return nil
		},
	}
}

func newPasswdCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd",
		Short: "Change the master password",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireTTY("passwd"); err != nil {
				return err
			}
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
			cur, err := readPassword("Current master password: ")
			if err != nil {
				return err
			}
			defer crypto.Zero(cur)
			u, err := s.Unlock(cur)
			if err != nil {
				return err
			}
			defer u.Close()
			pw, err := newPassword("New master password")
			if err != nil {
				return err
			}
			defer crypto.Zero(pw)
			if err := u.ChangePassword(pw, kdf); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "Password changed")
			return nil
		},
	}
}

func newDestroyCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "destroy",
		Short: "Permanently delete the vault, its backup and session",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			path, err := vaultPath()
			if err != nil {
				return err
			}
			if !yes {
				if err := requireTTY("destroy"); err != nil {
					return err
				}
				ans, err := readLine(fmt.Sprintf("This permanently deletes %s. Type \"destroy\" to confirm: ", path))
				if err != nil {
					return err
				}
				if strings.TrimSpace(ans) != "destroy" {
					return errors.New("aborted")
				}
			}
			if s, err := vault.Read(path); err == nil {
				if err := session.Clear(s.ID()); err != nil {
					fmt.Fprintf(stderr, "lockr: warning: could not clear session: %v\n", err)
				}
			}
			for _, p := range []string{path, path + ".bak", path + ".lock"} {
				if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			fmt.Fprintln(stdout, "Vault destroyed")
			return nil
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "skip the confirmation")
	return c
}
