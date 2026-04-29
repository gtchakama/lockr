package cmd

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/gtchakama/lockr/internal/config"
	"github.com/gtchakama/lockr/internal/parser"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(setCmd)
}

var setCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Store a secret",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		rawKey := args[0]
		value := args[1]

		dir, err := config.GetDir()
		if err != nil { return err }
		vaultPath := filepath.Join(dir, config.VaultFile)

		password, err := getOrPromptPassword()
		if err != nil { return err }

		v, err := vault.Load(vaultPath, password)
		if err != nil { return err }

		group, key := parser.ParseKey(rawKey)
		if _, exists := v.Data[group]; !exists {
			v.Data[group] = make(map[string]vault.Secret)
		}
		
		v.Data[group][key] = vault.Secret{
			Value:     value,
			UpdatedAt: time.Now(),
		}

		if err := v.Save(vaultPath, password); err != nil {
			return err
		}

		fmt.Printf("Successfully saved '%s' to group '%s'\n", key, group)
		return nil
	},
}
