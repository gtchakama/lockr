// `lockr run`: execute a child with a project's env-mapped secrets injected,
// so values reach the program without passing through the caller.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/gtchakama/lockr/internal/model"
	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run <project> -- <command> [args...]",
		Short: "Run a command with the project's secrets as env vars",
		Args: usageArgs(func(c *cobra.Command, args []string) error {
			if c.ArgsLenAtDash() != 1 || len(args) < 2 {
				return errors.New("usage: lockr run <project> -- <command> [args...]")
			}
			return nil
		}),
		RunE: func(_ *cobra.Command, args []string) error {
			project, err := model.ParseName(args[0])
			if err != nil {
				return usageWrap(err)
			}
			u, path, err := openRead(false)
			if err != nil {
				return err
			}
			items, ok := u.Body.Projects[project]
			if !ok {
				u.Close()
				return fmt.Errorf("project %q %w", project, model.ErrNotFound)
			}
			env := os.Environ()
			for _, n := range sortedNames(items) {
				if it := items[n]; it.Env != "" {
					env = append(env, string(it.Env)+"="+string(it.Secret))
				}
			}
			u.Close()
			recordAudit(path, "run", string(project))

			child := exec.Command(args[1], args[2:]...)
			child.Env = env
			child.Stdin, child.Stdout, child.Stderr = stdin, stdout, stderr
			if err := child.Start(); err != nil {
				return err
			}
			sigs := make(chan os.Signal, 2)
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
			done := make(chan struct{})
			go func() {
				for {
					select {
					case s := <-sigs:
						_ = child.Process.Signal(s)
					case <-done:
						return
					}
				}
			}()
			err = child.Wait()
			signal.Stop(sigs)
			close(done)
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code := ee.ExitCode()
				if code < 0 {
					code = codeGeneric
				}
				return &exitError{code: code}
			}
			return err
		},
	}
}
