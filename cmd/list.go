package cmd

import (
	"fmt"
	"time"

	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listCmd)
}

// maskValue hides the middle of the string
func maskValue(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	prefix := val[:2]
	suffix := val[len(val)-2:]
	return prefix + "****" + suffix
}

var listCmd = &cobra.Command{
	Use:   "list [group]",
	Short: "List secrets",
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultPath, err := getVaultPath()
		if err != nil { return err }

		password, err := getOrPromptPassword()
		if err != nil { return err }

		v, err := vault.Load(vaultPath, password)
		if err != nil { return err }

		targetGroup := ""
		if len(args) > 0 {
			targetGroup = args[0]
		}

		for group, keys := range v.Data {
			if targetGroup != "" && group != targetGroup {
				continue
			}
			
			if len(keys) == 0 {
				continue
			}

			fmt.Printf("[%s]\n", group)
			for key, secret := range keys {
				warn := ""
				// Warn if older than 90 days
				if time.Since(secret.UpdatedAt) > 90*24*time.Hour {
					warn = " (⚠️ >90 days old)"
				}
				fmt.Printf("  %s %s%s\n", key, maskValue(secret.Value), warn)
			}
			fmt.Println()
		}
		return nil
	},
}
