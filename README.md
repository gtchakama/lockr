# Lockr

**Lockr** is a local-first CLI tool for securely storing, organizing, and retrieving API keys and secrets using strong encryption. It eliminates reliance on cloud-based secret managers for individual developers and small teams by keeping all data encrypted and stored locally.

## Features

- **Local-first storage:** All secrets are kept on your machine. No cloud sync, no remote backups.
- **Strong Encryption:** Uses AES-256-GCM for encryption and Argon2id for key derivation.
- **Group-based organization:** Store secrets in logical groups (e.g., `work/stripe_key`).
- **Per-project scoped vaults:** Initialize a project-level vault inside any directory. Lockr automatically prefers the nearest project vault when you run commands from within that project.
- **OS Keychain Integration:** Caches your master password securely in your OS keychain so you don't have to type it every time.
- **Clipboard Support:** Copy secrets directly to your clipboard to prevent shoulder surfing.
- **Secret Rotation Reminders:** Automatically flags secrets older than 90 days.
- **Seamless Exporting:** Easily export single secrets or entire groups as environment variables (`eval $(lockr export work)`).

## Installation

### Option 1: Homebrew (macOS / Linux)
```bash
brew install gtchakama/tap/lockr
```

### Option 2: Go Install (Cross-platform)
If you have Go installed, you can build and install directly from source:
```bash
go install github.com/gtchakama/lockr@latest
```

### Option 3: Direct Download
Download the pre-compiled binary for your OS and architecture from the [GitHub Releases](https://github.com/gtchakama/lockr/releases) page.

## Usage

### Initialize Vault
```bash
lockr init
```
*Prompts for a master password and initializes `~/.lockr/vault.enc`. Saves the password to your OS keychain.*

### Initialize a Project-Level Vault
```bash
lockr init --project
```
*Initializes a vault in `./.lockr/vault.enc` within the current directory. When you run any `lockr` command from this directory (or any subdirectory), this project vault is used automatically instead of the global vault.*

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
# Permanently delete the active vault and all stored secrets:
lockr destroy

# Skip the confirmation prompt:
lockr destroy --force
lockr destroy -f
```
*Removes the active vault (project-level or global) and clears the cached master password from the OS keychain. This is irreversible.*

### Export Secrets
```bash
# Export a single secret:
eval $(lockr export work/stripe_key)

# Export an entire group:
eval $(lockr export work)
```

### Run a Command with Secrets Injected
```bash
# Inject all secrets from a group into the child process:
lockr run work -- pnpm run dev
lockr run backend -- cargo run

# Inject a single secret:
lockr run work/stripe_key -- bash -lc 'echo $STRIPE_KEY'
```

*`lockr run` preserves your existing environment and overlays the decrypted secret values for the spawned command only.*

## How Project Vaults Work

Lockr resolves the active vault by walking up from your current working directory looking for a `.lockr/vault.enc` file. If one is found, it becomes the active vault for that command. If none is found, the global vault at `~/.lockr/vault.enc` is used.

This means you can:
- Keep personal/global secrets in `~/.lockr/vault.enc`
- Keep project-specific secrets (e.g., API keys, database URLs) in the project's own `.lockr/vault.enc`
- Share the project directory with teammates (they'll need the project vault password)
- Commit `.lockr/` to `.gitignore` so it never leaks into version control

Example workflow:
```bash
cd ~/my-project
lockr init --project
lockr set prod/db_password super_secret_123
lockr get prod/db_password
```

## Security

- Passwords are never stored in plain text.
- Vault files are encrypted using an encryption key derived from your master password using Argon2id.
- Encryption relies on AES-256-GCM with a unique nonce for every save operation.
- Session passwords can be securely cached in your native OS keychain and manually flushed via `lockr lock`.
- Project vaults are completely isolated from the global vault — each has its own encryption key and ciphertext.

## Architecture

Built with Go and Cobra.
- `cmd/`: CLI routing, commands, and OS keychain integration.
- `internal/crypto`: Handles Argon2id key derivation and AES-256-GCM encryption.
- `internal/vault`: Handles vault reading, parsing, modification, and secret metadata (timestamps).
- `internal/parser`: Handles `group/key` namespace resolution.
- `internal/config`: Vault path resolution — supports both global and project-level vault discovery.
