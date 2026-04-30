package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gtchakama/lockr/internal/config"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const keyringService = "lockr-vault"
const keyringUser = "master-key"

// getVaultPath returns the path to the active vault, preferring a project-level
// vault over the global one.
func getVaultPath() (string, error) {
	return config.GetVaultPath()
}

// vaultDir returns the directory containing the active vault file.
func vaultDir() (string, error) {
	path, err := getVaultPath()
	if err != nil {
		return "", err
	}
	return filepath.Dir(path), nil
}

// isProjectVault returns true if the active vault is project-level.
func isProjectVault() bool {
	_, found := config.FindProjectDir()
	return found
}

// getOrPromptPassword checks the OS keychain first. If not found, it prompts and saves it.
func getOrPromptPassword() (string, error) {
	pw, err := keyring.Get(keyringService, keyringUser)
	if err == nil && pw != "" {
		return pw, nil
	}

	fmt.Print("Enter master password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}

	strPw := string(bytePassword)
	// Cache it in the OS keychain for seamless future use
	_ = keyring.Set(keyringService, keyringUser, strPw)

	return strPw, nil
}

// promptPassword is used for strict prompts (like init) without checking cache
func promptPassword() (string, error) {
	fmt.Print("Enter master password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytePassword), nil
}
