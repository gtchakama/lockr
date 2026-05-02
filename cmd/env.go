package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gtchakama/lockr/internal/parser"
	"github.com/gtchakama/lockr/internal/vault"
)

func resolveEnvVars(v *vault.VaultData, rawInput string) (map[string]string, error) {
	group, key := parser.ParseKey(rawInput)

	if groupData, groupExists := v.Data[group]; groupExists {
		if secret, keyExists := groupData[key]; keyExists {
			return map[string]string{strings.ToUpper(key): secret.Value}, nil
		}
	}

	if groupData, groupExists := v.Data[rawInput]; groupExists {
		envVars := make(map[string]string, len(groupData))
		for key, secret := range groupData {
			envVars[strings.ToUpper(key)] = secret.Value
		}
		return envVars, nil
	}

	return nil, fmt.Errorf("no matching key or group found")
}

func envPairs(envVars map[string]string) []string {
	keys := make([]string, 0, len(envVars))
	for key := range envVars {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%s", key, envVars[key]))
	}

	return pairs
}
