package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/gtchakama/lockr/internal/config"
	"github.com/gtchakama/lockr/internal/parser"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

var deleteGroup bool

func init() {
	deleteCmd.Flags().BoolVarP(&deleteGroup, "group", "g", false, "Delete an entire group instead of a specific key")
	rootCmd.AddCommand(deleteCmd)
}

var deleteCmd = &cobra.Command{
	Use:   "delete <key-or-group>",
	Short: "Delete a secret or an entire group",
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

		// Handle deleting an entire group
		if deleteGroup {
			if _, groupExists := v.Data[rawInput]; groupExists {
				delete(v.Data, rawInput)
				if err := v.Save(vaultPath, password); err != nil {
					return err
				}
				fmt.Printf("Successfully deleted entire group '%s'\n", rawInput)
				return nil
			}
			return fmt.Errorf("group '%s' not found", rawInput)
		}

		// Handle deleting a single key
		group, key := parser.ParseKey(rawInput)
		
		if groupData, groupExists := v.Data[group]; groupExists {
			if _, keyExists := groupData[key]; keyExists {
				delete(groupData, key)
				
				// Clean up group if empty
				if len(groupData) == 0 {
					delete(v.Data, group)
				}
				
				if err := v.Save(vaultPath, password); err != nil {
					return err
				}
				fmt.Printf("Successfully deleted '%s' from group '%s'\n", key, group)
				return nil
			}
		}

		return fmt.Errorf("secret not found")
	},
}
