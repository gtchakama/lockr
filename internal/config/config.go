package config

import (
	"os"
	"path/filepath"
)

const (
	DirName   = ".lockr"
	VaultFile = "vault.enc"
	ConfFile  = "config.json"
)

func GetDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DirName), nil
}
