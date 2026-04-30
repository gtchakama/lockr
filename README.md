# Lockr

**Lockr** is a local-first CLI tool for securely storing, organizing, and retrieving API keys and secrets using strong encryption. It eliminates reliance on cloud-based secret managers for individual developers and small teams by keeping all data encrypted and stored locally.

## Features

- **Local-first storage:** All secrets are kept on your machine. No cloud sync, no remote backups.
- **Strong Encryption:** Uses AES-256-GCM for encryption and Argon2id for key derivation.
- **Group-based organization:** Store secrets in logical groups (e.g., `work/stripe_key`).
- **OS Keychain Integration:** Caches your master password securely in your OS keychain so you don't have to type it every time.
- **Clipboard Support:** Copy secrets directly to your clipboard to prevent shoulder surfing.
- **Secret Rotation Reminders:** Automatically flags secrets older than 90 days.
- **Seamless Exporting:** Easily export single secrets or entire groups as environment variables (`eval $(lockr export work)`).

## Installationnn### Option 1: Homebrew (macOS / Linux)n```bashnbrew install gtchakama/tap/lockrn```nn### Option 2: Go Install (Cross-platform)nIf you have Go installed, you can build and install directly from source:n```bashngo install github.com/gtchakama/lockr@latestn```nn### Option 3: Direct DownloadnDownload the pre-compiled binary for your OS and architecture from the [GitHub Releases](https://github.com/gtchakama/lockr/releases) page.nn
## Usage

### Initialize Vault
```bash
lockr init
```
*Prompts for a master password and initializes `~/.lockr/vault.enc`. Saves the password to your OS keychain.*

### Lock Vault
```bash
lockr lock
```
*Removes the cached master password from the OS keychain, requiring you to type it again on the next command.*

### Store a Secret
```bash
lockr set work/stripe_key sk_test_123
lockr set github_token ghp_xxx
```
*(If no group is provided, it defaults to the `default` group).*

### Retrieve a Secret
```bash
lockr get work/stripe_key

# Or copy directly to clipboard without printing to terminal:
lockr get work/stripe_key --copy
lockr get work/stripe_key -c
```

### List Secrets
```bash
lockr list
lockr list work
```
*Note: Passwords are automatically masked. Secrets older than 90 days will show a warning.*

### Delete Secrets
```bash
# Delete a single secret:
lockr delete work/stripe_key

# Delete an entire group:
lockr delete --group work
lockr delete -g work
```

### Destroy Vault
```bash
# Permanently delete the vault and all stored secrets:
lockr destroy

# Skip the confirmation prompt:
lockr destroy --force
lockr destroy -f
```
*Removes `~/.lockr/` and clears the cached master password from the OS keychain. This is irreversible.*

### Export Secrets
```bash
# Export a single secret:
eval $(lockr export work/stripe_key)

# Export an entire group:
eval $(lockr export work)
```

## Security

- Passwords are never stored in plain text.
- Vault files are encrypted using an encryption key derived from your master password using Argon2id.
- Encryption relies on AES-256-GCM with a unique nonce for every save operation.
- Session passwords can be securely cached in your native OS keychain and manually flushed via `lockr lock`.

## Architecture

Built with Go and Cobra.
- `cmd/`: CLI routing, commands, and OS keychain integration.
- `internal/crypto`: Handles Argon2id key derivation and AES-256-GCM encryption.
- `internal/vault`: Handles vault reading, parsing, modification, and secret metadata (timestamps).
- `internal/parser`: Handles `group/key` namespace resolution.
