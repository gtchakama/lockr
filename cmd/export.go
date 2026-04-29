package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gtchakama/lockr/internal/config"
	"github.com/gtchakama/lockr/internal/parser"
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

		dir, err := config.GetDir()
		if err != nil { return err }
		vaultPath := filepath.Join(dir, config.VaultFile)

		password, err := getOrPromptPassword()
		if err != nil { return err }

		v, err := vault.Load(vaultPath, password)
		if err != nil { return err }

		group, key := parser.ParseKey(rawInput)

		// Check if it's a specific key
		if groupData, groupExists := v.Data[group]; groupExists {
			if secret, keyExists := groupData[key]; keyExists {
				fmt.Printf("%s=%s\n", strings.ToUpper(key), secret.Value)
				return nil
			}
		}

		// Otherwise, treat the input as a whole group (e.g. `lockr export work`)
		// The parser sets group="default" and key="work" if input is just "work"
		targetGroup := rawInput
		if groupData, groupExists := v.Data[targetGroup]; groupExists {
			for k, secret := range groupData {
				fmt.Printf("%s=%s\n", strings.ToUpper(k), secret.Value)
			}
			return nil
		}

		return fmt.Errorf("no matching key or group found")
	},
}
