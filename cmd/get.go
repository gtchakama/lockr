package cmd

import (
	"fmt"

	"github.com/atotto/clipboard"
	"github.com/gtchakama/lockr/internal/parser"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

var copyToClipboard bool

func init() {
	getCmd.Flags().BoolVarP(&copyToClipboard, "copy", "c", false, "Copy value to clipboard instead of printing")
	rootCmd.AddCommand(getCmd)
}

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Retrieve a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rawKey := args[0]

		vaultPath, err := getVaultPath()
		if err != nil { return err }

		password, err := getOrPromptPassword()
		if err != nil { return err }

		v, err := vault.Load(vaultPath, password)
		if err != nil { return err }

		group, key := parser.ParseKey(rawKey)
		
		groupData, groupExists := v.Data[group]
		if !groupExists {
			return fmt.Errorf("group '%s' not found", group)
		}

		secret, keyExists := groupData[key]
		if !keyExists {
			return fmt.Errorf("key '%s' not found in group '%s'", key, group)
		}

		if copyToClipboard {
			if err := clipboard.WriteAll(secret.Value); err != nil {
				return fmt.Errorf("failed to copy to clipboard: %w", err)
			}
			fmt.Println("Secret copied to clipboard.")
		} else {
			fmt.Println(secret.Value)
		}
		
		return nil
	},
}
