// Root command, exit-code mapping and the injectable I/O seams used by every
// subcommand. Boundary: this is the only place that turns errors into process
// exit codes and stderr messages.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gtchakama/lockr/internal/model"
	"github.com/gtchakama/lockr/internal/session"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

// Exit codes. Agents rely on these to decide what to tell the user.
const (
	codeOK       = 0
	codeGeneric  = 1
	codeLocked   = 3
	codeNotFound = 4
	codeTTY      = 5
	codeUsage    = 64
)

const lockedMsg = "vault is locked — ask the user to run: lockr unlock"

// exitError carries an exit code. A nil err means "exit silently" (used to
// propagate a child's exit status from `lockr run`).
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

func usageErr(format string, a ...any) error {
	return &exitError{code: codeUsage, err: fmt.Errorf(format, a...)}
}

func usageWrap(err error) error {
	if err == nil {
		return nil
	}
	return &exitError{code: codeUsage, err: err}
}

func errLocked() error { return &exitError{code: codeLocked, err: errors.New(lockedMsg)} }

// usageArgs wraps a cobra positional-args validator so violations exit 64.
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error { return usageWrap(v(c, args)) }
}

// exitCode classifies an error returned by a command.
func exitCode(err error) int {
	var ee *exitError
	switch {
	case err == nil:
		return codeOK
	case errors.As(err, &ee):
		return ee.code
	case errors.Is(err, session.ErrLocked):
		return codeLocked
	case errors.Is(err, model.ErrNotFound), errors.Is(err, vault.ErrNoVault):
		return codeNotFound
	case strings.HasPrefix(err.Error(), "unknown command"):
		return codeUsage
	}
	return codeGeneric
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "lockr",
		Short: "Local encrypted secret vault for humans and agents",
		Long: `Lockr stores credentials in a local encrypted vault.

Agents should consume secrets without seeing them:
  curl -H "Authorization: Bearer $(lockr get myproj/api-key)" ...
  lockr run myproj -- npm test`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageWrap(err) })
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetIn(stdin)
	root.AddCommand(
		newInitCmd(), newUnlockCmd(), newLockCmd(), newStatusCmd(),
		newProjectCmd(), newAddCmd(), newEditCmd(), newRmCmd(), newMvCmd(),
		newListCmd(), newGetCmd(), newRunCmd(), newPasswdCmd(), newSkillCmd(),
		newImportV1Cmd(), newDestroyCmd(),
	)
	return root
}

// run executes the CLI with args and returns the process exit code.
func run(args []string) int {
	root := newRootCmd()
	root.SetArgs(args)
	err := root.Execute()
	code := exitCode(err)
	if err != nil {
		var ee *exitError
		if !errors.As(err, &ee) || ee.err != nil {
			fmt.Fprintf(stderr, "lockr: %s\n", err)
		}
	}
	return code
}

// Execute runs the CLI and exits the process with the mapped exit code.
func Execute() {
	os.Exit(run(os.Args[1:]))
}

// helpOnly lets a command group validate its Args (so `lockr project bogus`
// exits 64 instead of silently printing help) while still showing help when
// called bare. Cobra skips Args validation on commands without a Run.
func helpOnly(c *cobra.Command, _ []string) error { return c.Help() }
