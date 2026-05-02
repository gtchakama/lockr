package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(runCmd)
}

var runCmd = &cobra.Command{
	Use:                "run <key-or-group> -- <command> [args...]",
	Short:              "Run a command with secrets injected as environment variables",
	Args:               cobra.MinimumNArgs(2),
	DisableFlagParsing: false,
	RunE: func(cmd *cobra.Command, args []string) error {
		rawInput := args[0]
		commandArgs := args[1:]
		if len(commandArgs) == 0 {
			return fmt.Errorf("no command provided")
		}

		vaultPath, err := getVaultPath()
		if err != nil {
			return err
		}

		password, err := getOrPromptPassword()
		if err != nil {
			return err
		}

		v, err := vault.Load(vaultPath, password)
		if err != nil {
			return err
		}

		envVars, err := resolveEnvVars(v, rawInput)
		if err != nil {
			return err
		}

		run := exec.Command(commandArgs[0], commandArgs[1:]...)
		run.Stdin = os.Stdin
		run.Stdout = os.Stdout
		run.Stderr = os.Stderr
		run.Env = append(os.Environ(), envPairs(envVars)...)

		if err := run.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					os.Exit(status.ExitStatus())
				}
				os.Exit(1)
			}
			return err
		}

		return nil
	},
}
