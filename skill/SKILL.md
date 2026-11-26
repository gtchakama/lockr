---
name: lockr
description: Use whenever a task needs a credential - API key, token, password, login, or TOTP code. Fetch secrets from the Lockr vault at runtime without ever printing them, so values never enter the conversation.
---

# Lockr: using secrets without seeing them

Lockr is a local encrypted vault. A human unlocks it; you consume secrets
through pipes and command substitution so values never reach your context.

## Commands

- `lockr list [project]` - discover projects/items. Safe: shows names, never values.
- `lockr get <project>/<item>[.password|.username|.url|.totp]` - prints the raw value to stdout, no newline. Refuses on a terminal.
- `lockr run <project> -- <cmd>` - runs `<cmd>` with the project's env vars set. Use for tools that read env vars.

## Rules

1. Use `lockr get` ONLY inside `$(...)` or piped directly into the consuming program. Prefer stdin (`--password-stdin`, `@-`, `-d @-`) over argv.
2. In scripts, call `lockr get` at runtime via subprocess and keep the value in memory. Never log it.
3. Never: bare `lockr get`; `echo`/`printf`/`cat`/`tee` around it; `--reveal`; `curl -v`/`--trace`; `set -x`/`bash -x`; credentials in URLs; writing values to files, `.env`, logs, commits or test fixtures; printing whole responses that may echo secrets or tokens (filter with `jq`).
4. Exit code 3 (locked): STOP. Ask the human to run `lockr unlock`. Never try to unlock yourself.
5. Exit code 4 (not found): run `lockr list` and ask the human. Never guess refs.

## Good

```sh
docker login -u "$(lockr get ci/registry.username)" --password-stdin < <(lockr get ci/registry.password)
lockr get stripe/key | gh secret set STRIPE_KEY
curl -sS -H "Authorization: Bearer $(lockr get acme/api)" https://api.acme.com/me | jq '{id, name}'
lockr run acme -- ./deploy.sh
```

## Bad

```sh
lockr get acme/api                         # prints the value into the transcript
echo "$(lockr get acme/api)"               # echo leaks it
curl -v -H "Authorization: Bearer $(lockr get acme/api)" ...   # -v prints headers
export TOKEN=$(lockr get acme/api); set -x # trace prints it
curl https://user:$(lockr get a/b)@host    # credential in URL
lockr get acme/api > .env                  # value on disk
```

## Playwright login

```js
import { execFileSync } from "node:child_process";
const get = (ref) => execFileSync("lockr", ["get", ref], { encoding: "utf8" });

await page.fill("#email", get("acme/site.username"));
await page.fill("#password", get("acme/site.password"));
await page.fill("#otp", get("acme/site.totp"));
// Never console.log these values, never screenshot a revealed field.
```
