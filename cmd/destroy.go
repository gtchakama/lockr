package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

var destroyForce bool

func init() {
	destroyCmd.Flags().BoolVarP(&destroyForce, "force", "f", false, "Skip confirmation prompt")
	rootCmd.AddCommand(destroyCmd)
}

var destroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Permanently delete the vault and all stored secrets",
	Long: `Removes the active Lockr vault (project-level or global) and clears the cached
master password from the OS keychain. This action is irreversible — all stored
secrets will be lost.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultPath, err := getVaultPath()
		if err != nil {
			return err
		}

		dir, err := vaultDir()
		if err != nil {
			return err
		}

		if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
			fmt.Println("No vault found. Nothing to destroy.")
			return nil
		}

		scope := "project"
		if !isProjectVault() {
			scope = "global"
		}

		if !destroyForce {
			fmt.Printf("This will permanently delete the %s vault at %s and all stored secrets.\n", scope, dir)
			fmt.Print("Type 'destroy' to confirm: ")
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			if strings.TrimSpace(input) != "destroy" {
				fmt.Println("Aborted.")
				return nil
			}
		}

		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("failed to remove vault directory: %w", err)
		}

		_ = keyring.Delete(keyringService, keyringUser)

		fmt.Printf("%s vault destroyed.\n", strings.Title(scope))
		return nil
	},
}
