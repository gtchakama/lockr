# Lockr

Lockr is a local, encrypted CLI vault for developers and their AI agents. It keeps logins, API keys and TOTP seeds in one encrypted file and hands them to programs through pipes, so the values never have to appear on your screen or in an agent's context.

- One global vault (`~/.lockr/vault.lockr`, override with `$LOCKR_VAULT`)
- Named projects containing items of kind `login` or `secret`
- A human unlocks a time-limited session; agents use it without ever seeing values

## Install

```sh
brew install gtchakama/tap/lockr
# or
go install github.com/gtchakama/lockr@latest
```

## Quickstart

```sh
lockr init                                   # create the vault, set a master password
lockr project new acme
lockr add acme/api --kind secret --env ACME_API_KEY
lockr add acme/site --kind login --url https://acme.com --username me --totp
lockr unlock                                 # human only, TTY required (default 8h)
lockr list acme
curl -H "Authorization: Bearer $(lockr get acme/api)" https://api.acme.com/me
lockr get acme/api | gh secret set ACME_API_KEY
lockr run acme -- ./deploy.sh                # items with --env become env vars
```

## Reference grammar

```
<project>/<item>[.password|.username|.url|.totp]
```

`secret` items have a single value (`<project>/<item>`). `login` items expose the fields above; a bare `<project>/<item>` on a login means `.password`.

## Commands

| Command | Description |
|---|---|
| `init` | Create the vault |
| `unlock [--ttl 8h]` | Open a session (TTY only); DEK cached in the OS keychain |
| `lock` | End the session |
| `status` | Show locked/unlocked and expiry |
| `project new\|list\|rm` | Manage projects |
| `add <ref> --kind --url --username --env --totp --stdin` | Add an item (`--stdin` reads the value from stdin) |
| `edit <ref>` | Edit an item |
| `rm <ref>` | Remove an item |
| `mv <ref> <ref>` | Rename or move an item |
| `list [project]` | List names (never values) |
| `get <ref> [--reveal]` | Print the raw value to stdout, no newline. Refuses on a TTY unless `--reveal` |
| `run <project> -- <cmd>` | Run a command with the project's env vars |
| `passwd` | Change the master password |
| `skill install [--all] [--agent ids] [--copy] [--dir] [--print]` | Install the agent skill for the coding agents on this machine (interactive checklist on a terminal) |
| `skill list` / `skill uninstall` | Show which agents have it / remove it everywhere |
| `import-v1` | Import a Lockr v1 vault |
| `destroy` | Delete the vault |

Exit codes: `3` locked, `4` not found, `5` refused (stdout is a TTY), `64` usage.

## Using with AI agents

Run `lockr skill install` to teach your agents the rules (see `skill/SKILL.md`). It detects the coding agents on your machine (Claude Code, Codex, Gemini CLI, Antigravity, Cursor, OpenCode, Copilot, Windsurf, Kiro, Factory, Goose, Pi, Grok) and shows a checklist with all of them selected. One copy is written to `~/.agents/skills/lockr/SKILL.md` and each selected agent gets a symlink to it, so updating Lockr and re-running the install updates every agent at once. Use `--all` or `--agent claude,codex` in scripts.

The model:

1. You run `lockr unlock` in a terminal. Agents cannot: it requires a TTY and your password.
2. The agent discovers refs with `lockr list` (names only).
3. The agent uses `lockr get` only inside `$(...)` or a pipe, so the value goes from Lockr to the consuming program and never into the transcript. `get` refuses when stdout is a terminal.
4. If the vault is locked (exit 3) the agent stops and asks you to unlock. When the session expires, access ends.

## Security model

- Master password -> Argon2id (m=256 MiB, t=3, p=1) -> KEK that wraps a random DEK.
- Items are encrypted with XChaCha20-Poly1305; the file header is bound as AAD.
- Writes are atomic with a `.bak` of the previous version; files are mode 0600.
- Sessions cache the DEK in the OS keychain with a fixed TTL (no sliding renewal).
- Every access is recorded in `~/.lockr/audit.jsonl`: time, command, ref, parent process chain and cwd. Refs are logged, never values.

Honest limits: Lockr cannot stop an agent that deliberately prints a value (for example `echo "$(lockr get x/y)"`) or a program that leaks its own credentials. It also cannot protect against malware running as you while the session is open. It makes accidental leakage hard and deliberate leakage visible in the audit log.

## Migrating from v1

v2 is a breaking change: per-project vaults are removed in favor of one global vault with projects. Import an old vault with:

```sh
lockr import-v1 path/to/old-vault
```

Groups become projects and keys become `secret` items.

## Architecture

- `cmd/` - Cobra CLI commands
- `internal/vault` - encrypted file format, locking, atomic persistence
- `internal/model` - projects, items, ref parsing
- `internal/crypto` - Argon2id, key wrapping, XChaCha20-Poly1305
- `internal/session` - DEK cache in the OS keychain with TTL
- `internal/audit` - append-only audit log
- `internal/totp` - TOTP code generation
- `internal/legacy` - v1 vault decryption for migration
- `skill/` - embedded agent skill
