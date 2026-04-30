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

// GetDir returns the global Lockr directory in the user's home folder.
func GetDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DirName), nil
}

// FindProjectDir walks up from the current working directory looking for a
// .lockr directory containing a vault.enc file. Returns the path to that
// .lockr directory and true if found, or an empty string and false.
func FindProjectDir() (string, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", false
	}

	for dir := cwd; dir != "/" && dir != filepath.VolumeName(dir)+"\\"; dir = filepath.Dir(dir) {
		lockrDir := filepath.Join(dir, DirName)
		vaultPath := filepath.Join(lockrDir, VaultFile)
		if info, err := os.Stat(vaultPath); err == nil && !info.IsDir() {
			return lockrDir, true
		}
	}
	return "", false
}

// GetVaultPath returns the path to the active vault file.
// It prefers a project-level vault (found by walking up from the current
// directory) and falls back to the global vault in the user's home directory.
func GetVaultPath() (string, error) {
	if projectDir, found := FindProjectDir(); found {
		return filepath.Join(projectDir, VaultFile), nil
	}
	globalDir, err := GetDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(globalDir, VaultFile), nil
}
