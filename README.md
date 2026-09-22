# fnb

`fnb` is a read-only command-line client for viewing FNB South Africa Online Banking accounts, detailed balances and transactions. It is designed exclusively for a declared `view-only-secondary` user and refuses to run without that identity declaration.

> This is a personal tool, not affiliated with FNB. Automated access is outside FNB's terms. Use it only with your own account and stop using it if FNB raises an account notice or objects to the access.

The current release is the M1 scaffold. Commands and safety foundations exist, but bank login and data retrieval intentionally remain unimplemented until later approved milestones.

## Install

```sh
brew install yashiels/tap/fnb
```

To build from source:

```sh
make build
./fnb --version
```

## Configure

Configuration lives at `$XDG_CONFIG_HOME/fnb/config.toml`, or `~/.config/fnb/config.toml` when `XDG_CONFIG_HOME` is unset. Override it per invocation with `--config-dir`.

```toml
username = "your-view-only-username"
identity = "view-only-secondary"
credential_command = ["op-sa", "read", "op://Agents/fnb-viewonly/password"]
```

`FNB_USERNAME` and `FNB_PASSWORD` override configured values. The password is resolved only by a command that explicitly logs in. Secrets are never accepted as flags.

## Commands

```text
fnb auth login
fnb auth approve --wait 120s
fnb auth status
fnb auth logout
fnb auth clear-lockout
fnb auth import-cookies --from-browser chrome --profile PROFILE
fnb auth import-cookies --file FILE
fnb accounts list
fnb accounts balance <accountId>
fnb transactions <accountId> --from YYYY-MM-DD --to YYYY-MM-DD --state posted|pending
fnb doctor
fnb completion <bash|zsh|fish|powershell>
fnb --version
```

Global flags are `--json`, `--plain`, `--no-input`, `--config-dir` and `--verbose`. `--json` and `--plain` are mutually exclusive. Automatic output is a table on a terminal and JSON when redirected; plain output is stable and tab-separated.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success, including an empty result |
| 1 | Unclassified failure or blocked request |
| 2 | Invalid usage or unsafe output directory |
| 3 | Credentials, lockout, expired session, approval decline or identity refusal |
| 4 | Unknown account or no detailed balance |
| 5 | Rate limit, FNB throttling or lock contention |
| 6 | Network, server or maintenance failure |
| 7 | Layout change, incomplete data or unsupported currency |
| 8 | Approval pending |
| 9 | Approval expired |

## Safety

The config directory must be owned by the current user, must not be a symlink or group/world-writable, and must not grant access through ACLs. Sensitive files use pinned-directory, no-follow, atomic `0600` writes. Child processes receive only `HOME`, `PATH`, `TMPDIR`, `LANG` and `USER`; all `FNB_*` variables are removed.

See [`docs/threat-model.md`](docs/threat-model.md) and [`docs/incident.md`](docs/incident.md) before using live credentials.
