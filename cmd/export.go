package cmd

import (
	"fmt"

	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(exportCmd)
}

var exportCmd = &cobra.Command{
	Use:   "export <key-or-group>",
	Short: "Export a secret or group as env vars",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rawInput := args[0]

		vaultPath, err := getVaultPath()
		if err != nil { return err }

		password, err := getOrPromptPassword()
		if err != nil { return err }

		v, err := vault.Load(vaultPath, password)
		if err != nil { return err }

		envVars, err := resolveEnvVars(v, rawInput)
		if err != nil {
			return err
		}

		for _, pair := range envPairs(envVars) {
			fmt.Println(pair)
		}
		return nil
	},
}
