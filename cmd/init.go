package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gtchakama/lockr/internal/config"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

func init() {
	rootCmd.AddCommand(initCmd)
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the Lockr vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := config.GetDir()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}

		vaultPath := filepath.Join(dir, config.VaultFile)
		if _, err := os.Stat(vaultPath); err == nil {
			fmt.Println("Vault already initialized at", vaultPath)
			return nil
		}

		password, err := promptPassword()
		if err != nil || password == "" {
			return fmt.Errorf("invalid password")
		}

		fmt.Print("Confirm master password: ")
		confirmPassword, err := promptPassword()
		if err != nil || password != confirmPassword {
			return fmt.Errorf("passwords do not match")
		}

		v := vault.NewVaultData()
		if err := v.Save(vaultPath, password); err != nil {
			return err
		}
		
		// Cache the password automatically on init
		_ = keyring.Set(keyringService, keyringUser, password)

		fmt.Println("Vault successfully initialized at", vaultPath)
		return nil
	},
}
