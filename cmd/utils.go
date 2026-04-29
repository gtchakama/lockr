package cmd

import (
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const keyringService = "lockr-vault"
const keyringUser = "master-key"

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
