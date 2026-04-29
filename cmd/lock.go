package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

func init() {
	rootCmd.AddCommand(lockCmd)
}

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault by removing the password from the OS keychain",
	Run: func(cmd *cobra.Command, args []string) {
		_ = keyring.Delete(keyringService, keyringUser)
		fmt.Println("Vault locked. You will be prompted for your password next time.")
	},
}
