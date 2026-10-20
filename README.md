# AGYHub

Keep several Antigravity AI (`agy`) logins in an encrypted vault and switch the active one with a single command. Works on Windows and macOS (and Linux).

## Install

```sh
npm install -g agyhub
```

This installs the `agyhub` command (aliases: `agy-hub`, `ai-locker`):

```sh
agyhub init                    # create the vault, choose a passphrase
agyhub add work --from-live    # save the account you're logged in with now
agyhub add personal            # log in to another account and save it
agyhub use work                # switch Antigravity to "work"
agyhub status                  # active account + token details
```

To try it without installing, put `npx agyhub` in front of any command, for example `npx agyhub use work`.

## How it works

Antigravity CLI (`agy`) integrates with your operating system's native secure keyring architecture to store its active session and OAuth tokens:

| OS | Live credential store | Account info |
|---|---|---|
| Windows | Windows Credential Manager (`gemini:antigravity`) | Embedded ID token JWT (claims: email, name, sub...) |
| macOS | Keychain item `gemini` (account `antigravity`) | Embedded ID token JWT (claims: email, name, sub...) |
| Linux | Secret Service (`service=gemini`, `account=antigravity`) | Embedded ID token JWT (claims: email, name, sub...) |

`AGYHub` stores every account in its own encrypted vault and, on `use`, swaps the chosen one into that live slot. It never revokes tokens server-side; it moves credentials transactionally.

Antigravity refreshes its tokens while it runs. Before overwriting the live slot, `AGYHub` saves the current login back into the vault, so the copy you switch back to is always the newest one.

A switch is a safe transaction:

1. Refuse if any `agy` / `antigravity` process is running, since it could write old tokens back (`--force` overrides).
2. Save the live login into the vault. A login that isn't saved yet is never overwritten silently: you're asked to save it, or you pass `--save-live-as <name>` or `--discard-live`.
3. Write an encrypted rollback record.
4. Write the target profile's credentials into the OS keyring.
5. Verify that the credentials match the expected email and account. On failure, the previous login is restored automatically.

If the process is killed partway through, `agyhub doctor` reports it and `agyhub rollback` restores the previous login. Until then, other commands that change the login refuse to run, so the saved login cannot be corrupted or overwritten.

`AGYHub` only launches `agy` from absolute `PATH` entries, never from the current directory, so an `agy.exe` planted in a cloned repo is never run.

## Security model

```
passphrase ──Argon2id (64 MiB, t=3) or scrypt──▶ KEK ──AES-256-GCM──▶ wraps VDK (random 256-bit)
VDK ──HKDF-SHA256(purpose, id)──▶ per-file key ──AES-256-GCM (AAD = vault id + purpose + id)──▶ vault files
```

- **Stolen `~/.agyhub` is useless without the passphrase.** Every profile, the profile list (names, emails), and the rollback record are encrypted. Each file is bound to its id, so blobs cannot be swapped between profiles.
- **OS unlock (optional, on by default).** A copy of the data key is protected by Windows DPAPI (CurrentUser) or the macOS login Keychain, so routine commands don't prompt. It only decrypts for your OS user on this machine. Turn it off with `agyhub config os-unlock off`, or bypass it for one command with `--strict`.
- **The active login is as exposed as Antigravity makes it.** Antigravity needs it in its OS keyring slot to work. `agyhub lock` moves it into the vault and leaves Antigravity logged out; `agyhub unlock` brings it back.
- **Secrets never touch argv, logs, or `--json` output.** Secrets and keys pass over stdin in base64.
- **Zero native dependencies.** Crypto comes from Node's built-in `crypto`. OS key stores are reached through the in-box `powershell.exe` on Windows and `/usr/bin/security` on macOS, so installing needs no C++ build tools.
- `~/.agyhub` is created with mode 0700 on macOS/Linux, and with an ACL granting only your user on Windows.

## Commands

| Command | What it does |
|---|---|
| `init [--no-os-unlock] [--scrypt]` | Create the encrypted vault. |
| `add <name>` | Save current login (if unsaved), log out locally, run login flow, and save the new account. Options: `--email`, `--sso`, `--console`, `--manual`. |
| `add <name> --from-live` | Save the account that is logged in right now. |
| `use [profile]` | Switch to a profile (interactive picker if omitted). Alias `switch`. |
| `list` / `ls` | List saved profiles (`*` marks the active one). |
| `status` | Active profile, live login, and token expiry details. |
| `lock` / `unlock` | Move the live login into the vault, or restore it. |
| `rename <profile> <new>` / `remove <profile>` | Manage profiles. |
| `export <file>` / `import <file>` | Move profiles to another machine, encrypted with a separate passphrase. |
| `passphrase` | Change the vault passphrase and rotate the data key. Every profile is re-encrypted crash-safely. |
| `config show` / `config os-unlock on\|off` | View or change vault settings. |
| `rollback` | Restore the login saved before an interrupted operation. |
| `doctor` | Diagnose the vault, permissions, Antigravity install, and running sessions. |

Global flags: `--json` for machine-readable output, `--strict` to always ask for the passphrase.

Environment variables: `AGYHUB_HOME` (vault location, default `~/.agyhub`), `AGYHUB_PASSPHRASE` (non-interactive unlock, e.g. CI), `AGYHUB_EXPORT_PASSPHRASE`, `AI_LOCKER_AGY_BIN`. (Legacy `AI_LOCKER_*` variables are also supported for backwards compatibility).

## Caveats

- **Quit Antigravity (`agy`) before switching.** A running CLI session keeps tokens in memory and may write them back.
- **Don't use one login on two machines simultaneously.** When one copy refreshes, the other copy's refresh token can be invalidated. `export` is for transferring an account, not duplicating it.
- **Environment overrides win.** If `GEMINI_API_KEY`, `AGY_ADC_AUTH` or `GOOGLE_APPLICATION_CREDENTIALS` is set, Antigravity may ignore the stored login. `agyhub doctor` warns if these are set.

## Development

```sh
npm install
npm test          # vitest: crypto, vault, agy provider, switch transactions (temp dirs only)
npm run build     # tsup -> dist/cli.js
node dist/cli.js --help
```

Tests never touch your real credentials. They use isolated temporary directories and mock stores.

## License

MIT
