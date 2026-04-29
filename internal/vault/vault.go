package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/gtchakama/lockr/internal/crypto"
)

type EncryptedVault struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Secret struct {
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type VaultData struct {
	Version int                            `json:"version"`
	Data    map[string]map[string]Secret   `json:"data"`
}

func NewVaultData() *VaultData {
	return &VaultData{
		Version: 2, // Upgraded version for Secret struct
		Data:    make(map[string]map[string]Secret),
	}
}

func (v *VaultData) Save(path, password string) error {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}
	key := crypto.DeriveKey(password, salt)
	plaintext, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return err
	}
	encVault := EncryptedVault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.MarshalIndent(encVault, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func Load(path, password string) (*VaultData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var encVault EncryptedVault
	if err := json.Unmarshal(data, &encVault); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(encVault.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(encVault.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encVault.Ciphertext)
	if err != nil {
		return nil, err
	}
	key := crypto.DeriveKey(password, salt)
	plaintext, err := crypto.Decrypt(key, nonce, ciphertext)
	if err != nil {
		return nil, errors.New("decryption failed: incorrect password or corrupted file")
	}
	
	var vaultData VaultData
	if err := json.Unmarshal(plaintext, &vaultData); err != nil {
		return nil, err
	}
	return &vaultData, nil
}
