# fnb-cli plan (v8, approved)

A read-only Go CLI, `fnb`, that logs in to FNB (South Africa) Online Banking as a **view-only secondary user** and returns the account list, detailed balances and transactions as JSON / plain / tables, all money as int64 cents. Distributed via `brew install yashiels/tap/fnb`. Modeled on `yashiels/investec` (Go, cobra, layout, flags, exit codes, release pipeline) and `yashiels/takealot-cli` (undocumented surface, two-step headless auth handshake, persisted session, agent-first).

## 0. Context and verified facts (recon done 2026-09-22)

- FNB has **no public personal-banking API**. The only surface is the Online Banking web app at `https://www.online.fnb.co.za/banking/`.
- Prior art: `bitshiftza/fnb-api` (GPL-3.0, TypeScript, Puppeteer 19, last functional change 2023). Forked to `yashiels/fnb-api`. Its README tells us which UI areas exist (accounts summary, account detail tabs, transaction history, a never-implemented debit-orders scraper). **Its source is not used as an implementation reference** (see §2, licensing).
- Live recon of the login surface today (no credentials submitted):
  - `fnb.co.za` homepage `form#LOGIN_FORM` POSTs to `https://www.online.fnb.co.za/login/Controller` with hidden fields `formAction=login`, `nav=navigator.UserLogon`, `country=15`, `countryCode=ZA`, `language=en`, JS-filled `BrowserType/BrowserVersion/OperatingSystem`, `homePageLogin=true`, `tp=false`, plus `Username`/`Password`.
  - `/banking/` redirects to `/banking/navigate?_u=…&_p=…` with a second form: `_csrf`, `username`, `a_field` (likely honeypot/anti-bot), `password`, `dataCounter`, `PBKey`. App JS includes `dataPoller.js`, `fePoller.js`, `mmPoller.js`, `is.js`, `geoLocate.js`, firebase messaging, which suggests the post-login "approve on the FNB App" flow is a polled endpoint.
- House conventions that bind: Go + cobra; `internal/…` layout like investec; `--json`/`--plain` mutually exclusive, TTY tables otherwise, non-TTY defaults to JSON; secrets never via flags; tokens/sessions `0600` under XDG; distinct exit codes; `make lint`/`make test`; `ship.yml` + `_release-impl.yml` building darwin/linux × amd64/arm64 and landing a GitHub-signed tap commit via `createCommitOnBranch`; first tap formula bootstrapped by hand; no code comments; `type(scope): summary #N`; stacked PRs, one squashed commit each.

## 1. Goals

1. `fnb accounts list`, `fnb accounts balance`, `fnb transactions` return complete, reconciled data or fail loudly. Never partial data presented as complete. Supported account types are exactly the owner's: **personal cheque** (Private Clients), **business cheque** (a business account linked on the same Online Banking profile), **savings**, **personal eBucks** and **business eBucks**. Scope: (a) account list with name, account number, balance and available balance for all five; (b) detailed balance for personal and business cheque (reserved funds, pending credits, pending debits, charges accrued, minimum balance, outstanding card authorisations) and savings (balance and available only); (c) transactions for personal cheque, business cheque and savings with date, description, reference, service fee, amount, running balance and posted/pending state. Any other account type found on the profile (credit card, vehicle finance, home loan, investment) is listed in `accounts list` with `type: "unsupported"`, its name and last 4 only, no balance fields, and every other command on it exits 4 `unsupported_account_type`.
2. Runs headless for agents on an existing session; re-authentication is always an explicit, human-initiated `fnb auth login`.
3. Cannot move money or change settings: every emitted request is checked against an exact request allowlist (§4.1).
4. Transaction rows keep every source cell verbatim in `raw`. No classification or inference layer in v1.
5. Installable via `brew install yashiels/tap/fnb`, released by the investec-style pipeline.

## 2. Non-goals and policy decisions

- No write operation of any kind (payments, transfers, EFT, beneficiaries, debit-order stop/dispute, eBucks, card controls, profile/settings). Not behind a flag.
- No Capitec or other banks. No FNB mobile-app API reversing.
- No business / Enterprise profiles, no multi-profile switching.
- No background polling or cron in v1.
- **Primary (transact-capable) logins are unsupported in v1.** The CLI requires the config key `identity = "view-only-secondary"` and refuses to run without it. This is a user declaration; `fnb auth status` reports it as `identity: view-only-secondary (declared, unverified)` unless M0 finds an authoritative permission indicator on the page, in which case the CLI verifies it at login and exits 3 if the session can see any transact action.
- **Licensing / provenance:** the implementer of M1+ works only from `docs/pages.md` and synthetic fixtures produced in M0 from our own captures. The bitshiftza source is not read during implementation; `docs/provenance.md` records this. New repo is MIT.
- **ToS acceptance:** automated access to FNB Online Banking is outside FNB's terms. The README states this plainly, the owner accepts it for personal use of their own data, and the repo is marked "personal tool, not affiliated with FNB". If FNB objects (takedown request, account notice), the repo is archived and the tap formula removed; that is the stop criterion.

## 3. Credentials, lockout and session safety

### 3.1 Credential sources
- Precedence **env > config**: `FNB_USERNAME` / `FNB_PASSWORD`; or `~/.config/fnb/config.toml` with `username` and `credential_command = ["op-sa", "read", "op://Agents/fnb-viewonly/password"]` (an **argv array**, executed with `exec.Command` directly, no shell). Never flags, never logged, never in errors.
- Secrets live only in memory for the login request. Any child process the CLI spawns (`sweet-cookie`, the credential command, Chrome if the chromedp transport is chosen) gets a **scrubbed environment**: an explicit allowlist (`HOME`, `PATH`, `TMPDIR`, `LANG`, `USER`) with every `FNB_*` variable removed. A test asserts the child env built by each spawner contains no `FNB_` key.

### 3.2 Lockout guard (fail closed)
- **Before** any credential submission the CLI writes `~/.config/fnb/login-attempt.json` (`0600`, atomic) with `{state:"in_flight", at}`. If that write fails, the login is aborted before any network I/O.
- The credential POST is never retried (transport retry disabled for it; redirects handled manually through the guard).
- Only a response classified as **proven success** (logged-in landing fragment, or approval-pending fragment followed by approved) sets `state:"ok"`. **Every other outcome** (bad credentials, timeout, connection reset after send, unclassified response, maintenance page, declined/expired approval) sets `state:"blocked"` with the reason.
- While `state` is `in_flight` or `blocked`, every credential submission exits 3 with `previous login did not complete (<reason> at <time>); verify you can log in on the FNB site, then run 'fnb auth clear-lockout'`. `clear-lockout` requires an interactive TTY confirmation; it refuses under `--no-input` or without a TTY. Session-cookie reuse is still allowed.
- **Read commands never log in.** On an expired session they exit 3 `session_expired` and tell the user to run `fnb auth login`. There is no automatic relogin and no `--force` in v1.
- Rate guard: at most one credential login per 15 minutes (tracked in the attempt file); minimum 1 s between page requests; one in-flight command per config dir via `flock` (a second invocation waits up to 30 s then exits 5).

### 3.3 Session storage
- Config dir `~/.config/fnb` created `0700`; the CLI refuses to use it if it is a symlink, not owned by the user, or group/world-writable.
- **One secure-write primitive** (`secure.WriteFile`) is used for every sensitive file the CLI creates: `session.json`, `login-attempt.json`, `local.key` and `--partial-out` files. Mechanics: `O_CREATE|O_EXCL|O_NOFOLLOW` temp file `0600` in the **same directory** as the target → write → `fsync(file)` → `rename(temp, target)` → `fsync(parent dir)`. Overwrite policy is explicit per call: `NoOverwrite` uses `link(temp, target)` + `unlink(temp)` so an existing target (or a symlink planted at the target) makes it fail with `EEXIST` and nothing is replaced; `Overwrite` refuses if the existing target is a symlink or not a regular file owned by the user, then renames over it. **Directory pinning:** every step runs relative to a pinned parent-directory handle (`os.OpenRoot` on Go ≥ 1.24, backed by `openat`/`renameat`/`linkat`/`fstatat` with `AT_SYMLINK_NOFOLLOW`), so no step re-resolves a path. The parent must be owned by the user, not group/world-writable, **and carry no ACL entries granting any other principal access** (checked through the pinned handle: on macOS `acl_get_fd_np(fd, ACL_TYPE_EXTENDED)` must return no entries; on Linux the `system.posix_acl_access` / `system.posix_acl_default` xattrs must be absent or equivalent to the mode bits). If ACL inspection fails or is unsupported, the write is refused (fail closed). Any violation → exit 2 `unsafe_output_dir` before any file is created. The same check runs on `~/.config/fnb` at startup. A macOS test creates a `0700` dir, adds `chmod +a "everyone allow add_file,delete_child,file_inherit"`, and asserts refusal with no temp file created; a Linux test uses a non-writable named entry `setfacl -m u:nobody:r-x` (so the mode-bit check alone would pass) and a default ACL `setfacl -d -m u:nobody:r-x`, each asserting the ACL-specific refusal reason. Under that precondition no other user can swap the target between check and rename. The temp file is removed on every error path. Adversarial tests: (a) group/world-writable or foreign-owned parent → refused, nothing created; (b) a test hook swaps the target for a symlink between the ownership check and the rename → the rename replaces the directory entry only (the symlink's target file is unchanged), asserted by content hash; (c) parent dir replaced by a symlink after pinning → writes still land in the originally pinned dir.
- For `login-attempt.json` the `in_flight` write, including the parent-directory `fsync`, **completes before any credential network I/O**; a failure at any step aborts the login with zero requests. A test injects a fake filesystem layer and asserts the exact call order `open(temp) → write → fsync(file) → rename → fsync(dir) → first network call`, and asserts that a failure injected at each step yields zero network calls.
- `fnb auth logout` sends the server logoff and deletes the session. Sessions older than the M0-measured absolute lifetime are deleted on next start.
- `--partial-out file` goes through `secure.WriteFile`: `0600`, no-follow, atomic, `NoOverwrite` by default, `Overwrite` only with `--overwrite`. Tests cover: existing file without `--overwrite` → exit 2 and file unchanged; symlink at target with and without `--overwrite` → exit 2, link target untouched; resulting mode is `0600` regardless of umask.

### 3.4 Cookie import (sweet-cookie)
- `fnb auth import-cookies --from-browser chrome|--file f` runs `sweet-cookie https://www.online.fnb.co.za --browser chrome --format json` (scrubbed env) or reads a file/stdin. Only cookies for `online.fnb.co.za` are kept. The imported session goes through the same identity check as a login. Documented as an ad-hoc fallback: a real browser under the view-only user, logged in and approved by a human, handed to the CLI. Supported: the sweet-cookie version pinned in the README, Chrome stable. A dedicated Chrome profile for the view-only user is required (`--profile` passed through) so the primary profile's cookies are never imported.

## 4. Architecture

```
fnb/
├── cmd/fnb/main.go
├── internal/
│   ├── cli/            cobra commands
│   ├── config/         XDG paths, config.toml, argv credential_command, dir safety checks
│   ├── secure/         atomic 0600 writes, O_NOFOLLOW, env scrubbing for children
│   ├── session/        cookie jar persistence, flock, login-attempt state machine
│   ├── transport/      Transport interface; httpTransport (+ chromeTransport only if M0 requires it)
│   ├── guard/          request allowlist + enforcement (§4.1)
│   ├── fnb/            navigation map (allowlisted actions -> request builders); response classification
│   ├── parse/          pure HTML/CSV/OFX -> model parsers (goquery); no network
│   ├── model/          Account, Balance (per-type detail), Transaction (§4.2)
│   └── output/         json / plain / table, investec contract
├── testdata/fixtures/  synthetic fixtures only (§7 M0)
├── docs/{spike.md, pages.md, threat-model.md, incident.md, provenance.md}
├── skill/SKILL.md
├── Makefile, version.env, .github/workflows/{ci.yml, ship.yml, _release-impl.yml}
```

### 4.1 Read-only enforcement (request allowlist)
- `guard` holds a closed table of permitted requests, one entry per action from `docs/pages.md`: exact scheme (`https`), host (`www.online.fnb.co.za`), method, path, and a **parameter schema** (required keys, allowed keys, and for routing keys like `nav` / `formAction` / `action` the exact allowed value). Unknown keys, unknown values for routing keys, or any other host/path/method are rejected before the request is sent (exit 1, `blocked_request`, logged with key names only).
- Every request goes through `guard.Check` inside the transport's `RoundTrip`, including redirects: `CheckRedirect` validates each redirect target against the allowlist and stops on anything unknown.
- If the chromedp transport is chosen, `Fetch.enable` intercepts **every** request the page issues (XHR, form submit, navigation, beacon); requests matching the allowlist continue, static assets (`GET /banking/static/**`, no query key other than `ver`) continue, everything else is failed with `Fetch.failRequest`. Third-party hosts (analytics, firebase) are blocked outright.
- Tests: (a) a table test sends every allowlisted request shape and asserts pass; (b) a mutation test takes each allowlisted entry and tries extra key / changed routing value / changed method / changed path / changed host and asserts rejection; (c) the httptest integration suite runs every command end-to-end with a recording server and asserts every recorded request matches an allowlist entry; (d) a test asserts no allowlist routing value equals any write-action name catalogued in `docs/pages.md` (M0 catalogues write actions it sees in markup, without invoking them).

### 4.2 Model semantics
- Money: `int64` cents plus `currency` (v1 accepts exactly two values: `ZAR` for cheque/savings rows and `EBUCKS` for eBucks rows only; any other currency, or `EBUCKS` on a non-eBucks account, → exit 7 `unsupported_currency`; never converted; totals are computed per currency and ZAR and EBUCKS are never summed together).
- Transaction `amount` sign is from the account holder's perspective: negative = money out of the account. Overdrawn balances are negative, as FNB prints them (`-R131.62` → `-13162`).
- Balance fields: `current`, `available`, each with FNB's label text as `sourceLabel`, plus `asOf` (scrape timestamp, `Africa/Johannesburg`).
- Transaction `state`: `posted` | `pending`, from the page section it came from, never inferred.
- Dates: `YYYY-MM-DD` in `Africa/Johannesburg`; `--from`/`--to` inclusive on both ends; default window last 30 days.
- Every transaction carries `sourceId` (FNB's own reference/row id if present, else a stable hash of account + date + amount + raw description + running balance + ordinal among identical rows) and `raw` (every source cell verbatim).
- Completeness: every list response carries `complete: true` only when the source signalled end-of-data (download covered the full range, or pagination reached its last page). If a page cap, an unfollowed "more" link, or a download that refuses the range is detected, the command exits 7 `incomplete_data` and prints no rows on stdout; what it did get is written only to `--partial-out <file>` if the user asked for it.

### 4.3 Detailed balance model
- `Balance` carries `type` (`cheque` | `savings` | `ebucks`) plus `segment` (`personal` | `business`), and only the fields listed in §1 for that type, each int64 cents with FNB's label as `sourceLabel`. `segment` comes from the FNB account group/product shown on the summary page (M0 records the exact marker); if it cannot be determined the command exits 7, never guesses. A field FNB omits on the page is absent from JSON (never zero-filled). eBucks amounts are eB points, `currency: "EBUCKS"`, never summed with ZAR. eBucks accounts appear in `accounts list` only; `accounts balance <id>` on them exits 4 `no_detailed_balance`.

## 5. Command surface

```
fnb auth login                     explicit credential login (lockout + rate guarded); may return approval_pending
fnb auth approve [--wait 120s]     poll pending app approval, or submit FNB_OTP from env
fnb auth status                    session state, declared/verified identity, login-attempt state, rate guard
fnb auth logout                    server logoff + delete local session
fnb auth clear-lockout             interactive TTY confirmation required
fnb auth import-cookies [--from-browser chrome --profile P | --file f]
fnb accounts list
fnb accounts balance <accountId>
fnb transactions <accountId> [--from --to] [--state posted|pending] [--partial-out f]
fnb doctor                         runs every parser against the live session read-only; reports layout drift
fnb completion <shell> | fnb --version
global: --json | --plain, --no-input, --config-dir, --verbose (keys only, values redacted)
```

- `accountId`: FNB's own opaque per-account identifier if M0 finds one stable across sessions; otherwise `HMAC-SHA256(localKey, accountNumber)` truncated to 12 hex chars, where `localKey` is a random 32-byte key generated once in the config dir (`0600`); a collision among the profile's accounts aborts with exit 7. Default output shows `accountId`, product name and last 4 digits; full account numbers only in JSON with `--show-account-numbers`. A test asserts default JSON/plain/table and verbose logs never contain a full fixture account number.
- Exit codes: 0 ok (incl. empty), 1 unclassified / `blocked_request`, 2 usage, 3 credentials / lockout / session_expired / identity refused / approval declined, 4 unknown accountId / `no_detailed_balance`, 5 rate guard / FNB throttling / lock contention, 6 network / 5xx / maintenance, 7 layout changed / incomplete_data / unsupported_currency, 8 approval pending (run `fnb auth approve`), 9 approval expired.

## 6. Auth flow

1. `fnb auth login --json`: guard checks (§3.2) → writes `in_flight` → submits once. Outcomes: `{"status":"ok"}` | `{"status":"approval_pending","method":"app"|"otp","expiresInSec":N}` (exit 8, partial session saved, attempt state stays `in_flight`) | failure (attempt `blocked`, exit 3 or 6).
2. `fnb auth approve --wait 120s --json`: `app` polls the approval endpoint at ≥ 3 s intervals within the FNB-shown expiry; `otp` reads `FNB_OTP` env only. `approved` → session saved, attempt `ok`, exit 0. `declined` → partial session deleted, attempt `blocked`, exit 3. `expired` → partial session deleted, attempt `blocked`, exit 9. `approve` never triggers a new push; only `auth login` can.
3. Read commands reuse the session; on the login page / timeout fragment they exit 3 `session_expired`. They never submit credentials or cause an approval push.

## 7. Milestones (stacked PRs, bottom-up, one squashed commit each)

**M0 — Spike (decides feasibility and transport; no product code).**
- Capture: in a dedicated Chrome profile logged in as the view-only user, record one HAR per v1 surface: login → approval → accounts summary → account detail + Detailed Balance tab (personal cheque, business cheque, savings) → transaction history + any download option → logoff. Raw HARs are stored **outside every repo** in `~/.hermes/secure/fnb-m0/` (`0700`), encrypted at rest with `age` to the owner's key, and deleted after M0 fixtures are accepted. After capture, the session is logged off and the view-only password rotated.
- Fixtures: a generator script (kept outside the public repo) builds **synthetic** fixtures by structural allowlisting: it keeps tag/attribute/class structure, routing keys and column layouts, and replaces every text node and attribute value outside an explicit allowlist with synthetic values of the same shape (fake names, fake account numbers failing the real check digit, fake amounts). Output is scanned with `gitleaks` plus a PII rule set (SA ID pattern, 10–16 digit runs, email, phone, card BIN patterns, and a local denylist of the real username/name/surname/account last-4s) and **manually reviewed** before commit. CI runs the same scan (minus the local denylist) on every PR.
- Replay: throwaway Go program using `net/http` + cookiejar + the §4.1 guard replays the sequence against a **fresh** session.
- **Attempt budget:** at most 3 credential logins across all of M0, at least 30 minutes apart, from one IP; any failed or unclassified login pauses M0 for 24 h. Automated replay stops at the first unexpected response.
- **Stop conditions (FAIL, project stops and findings are reported):** account locked; FNB security SMS/email about the login or a "suspicious activity" interstitial; CAPTCHA served; attempt budget exhausted without the required PASSes.
- **Feature matrix (each PASS / DESCOPE / FAIL, recorded in `docs/spike.md`):**
  - login + approval + session reuse for ≥ 10 min: PASS required, else FAIL.
  - accounts summary listing every account the web UI shows: PASS required, else FAIL.
  - transaction history: PASS if a download or pagination path returns every row the web UI shows for a chosen 90-day window on one account; else FAIL.
  - detailed balance for personal cheque, business cheque and savings: PASS required for each, else FAIL.
  - transaction history on the **business** cheque account reachable and parsed the same as personal: PASS required, else FAIL.
  - the view-only secondary user has View permission on all five accounts (personal and business cheque, savings, both eBucks): PASS required; M0 stops and asks the owner to grant it otherwise.
  - transport: `http` if every PASS surface replays over net/http with fields obtained from prior responses; `chrome` if a surface only works with page JS and the §4.1 Fetch interception runs without breaking it; FAIL if neither.
- Also records: approval method and polling endpoint, device-remember behavior (observed across the ≤ 3 logins, no extra ones), session idle and absolute lifetime (measured on one session), download formats and range limits, any authoritative permission indicator for the identity check, FNB's stable account identifiers, catalogue of write actions seen in markup (not invoked).
- Deliverables: `docs/spike.md`, `docs/pages.md`, synthetic fixtures, matrix. M1 starts only after the owner reviews M0.

**M1 — Scaffold.** New public repo `yashiels/fnb`, MIT, cobra root, `config`, `secure`, `output`, exit-code mapping, identity-declaration refusal, `--version` via ldflags, Makefile (`build test lint vet fmt`), `ci.yml` (lint + test + fixture scan + govulncheck), AGENTS.md, `docs/threat-model.md`, `docs/incident.md`, `docs/provenance.md`.
- Acceptance: `make lint test` exits 0 locally and in CI; `fnb --version` prints the `version.env` value; `fnb accounts list` with no config exits 3 naming `FNB_USERNAME`; with credentials but no `identity` key exits 3 naming `identity`; symlinked config dir → exit 3; child-env test passes.

**M2 — Guard, session, auth.** `guard`, `session`, `transport` (M0-selected), response classification, lockout / rate / flock, all `auth` subcommands.
- Acceptance (httptest recording server): each classification fixture maps to its §5/§6 exit code; bad-credentials fixture → `blocked` and the next `auth login` makes **zero** requests; a server that drops the connection after reading the body → `blocked`, zero further requests; a failed attempt-file write → zero requests; the four §4.1 guard suites pass; a read command against a login-page response makes no credential POST.
- Live (owner-run, once): `auth login` + `approve` + `status` + `logout` succeed on the view-only user.

**M3 — Accounts + balances.**
- Acceptance: golden tests on synthetic fixtures for personal cheque, business cheque, savings, personal eBucks, business eBucks (incl. an overdrawn negative balance and an `unsupported` type row), plus a fixture with two accounts sharing product and last 4 proving they stay distinct by `accountId`. Live: the owner views the account summary in the web UI and within the same minute runs `fnb accounts list --json --show-account-numbers` locally (output never committed or pasted); `make reconcile-accounts` compares against a local, uncommitted file the owner fills in from the UI, keyed by **full account number**; PASS iff the key sets are identical and every `current`/`available` equals the UI value to the cent.

**M4 — Transactions.**
- Acceptance: golden tests including pagination end-detection and the `incomplete_data` path (fixture with an unfollowed "more" / capped download → exit 7, empty stdout); Live reconciliation: for one account and a 90-day window, the owner exports FNB's own CSV for the same window; `make reconcile` compares exported rows with `fnb transactions --json` as multisets keyed by (date, amount in cents, whitespace-normalized description); PASS iff the multisets are equal (no missing, extra or duplicated rows) and posted/pending counts equal the UI.

**M5 — Detailed balances + doctor.**
- Acceptance: golden tests per type on synthetic fixtures (personal cheque, business cheque, savings), including a field-absent fixture proving no zero-fill; live: for each of the personal cheque, business cheque and savings accounts (eBucks are covered by M3 list reconciliation and excluded here), the owner opens Detailed Balance in the web UI and within the same minute runs `fnb accounts balance <id> --json`; PASS iff every field in §4.3 for that type equals the UI value to the cent. `doctor` exits 0 on a live session and 7 against each mutated fixture.

**M6 — Release, tap, skill.**
- Release workflow adapted from investec with: all actions pinned to commit SHAs; `HOMEBREW_TAP_TOKEN` a fine-grained PAT scoped to `yashiels/homebrew-tap` contents only; `checksums.txt` generated and each asset re-hashed and compared in-job before upload; a smoke job runs `fnb --version` from the built tarballs on `macos-latest` (arm64), `macos-13` (amd64) and `ubuntu-latest` (amd64); a tag ruleset on `v*` restricting creation to the owner and the release workflow.
- Hand-bootstrap `Formula/fnb.rb` (lnk.rb pattern, SHAs from `checksums.txt`), tap README row, profile README row, `skill/SKILL.md` symlinked into agent-scripts skills, FNB section in the `personal-banking` skill.
- Acceptance: on the jarvis box (darwin/amd64) `brew install yashiels/tap/fnb && fnb --version` prints `0.1.0`; `brew test fnb` exits 0; `brew audit --strict yashiels/tap/fnb` exits 0.

## 8. Testing strategy

- Unit + golden tests on parsers, guard, secure, session state machine. No network in CI.
- httptest recording-server integration suite for every command and failure mode.
- Live smoke `make smoke` (owner-run, never CI) behind `FNB_LIVE=1`, read-only commands only, respecting the rate guard.
- Fixture PII/secret scan in CI on every PR.

## 9. Threat model summary (full in docs/threat-model.md)

- **Assets:** view-only password, live session cookies, financial data.
- **Other local users:** 0700 dir, 0600 atomic files, no secrets in child env or argv. Malware running as the owner is out of scope (it can already read the browser and password manager); the view-only identity bounds damage to disclosure.
- **Backups:** the CLI sets the macOS backup-exclusion xattr on `~/.config/fnb`; README tells Linux users to exclude it from backup/sync.
- **Session theft:** a view-only cookie cannot transact; sessions deleted on logout and on absolute-lifetime expiry.
- **Cookie import:** dedicated browser profile, domain filter, identity check on import.
- **Supply chain:** SHA-pinned actions, minimal deps (cobra, goquery, BurntSushi/toml, optional chromedp), `govulncheck` in CI.

## 10. Incident procedure and retention (full in docs/incident.md)

- Suspected flagging / lockout / FNB security notice: stop all use (`fnb auth logout`, remove any scheduled use), contact FNB via the app, rotate the view-only password, no re-run until resolved.
- Leaked fixture or session: owner decides on history purge, rotate the view-only password, end all sessions via FNB settings, delete local session.
- Retention: sessions deleted on logout/expiry; `--verbose` goes to stderr only, never disk; raw M0 HARs deleted after fixture acceptance; generator script and denylist stay outside the repo.

## 11. Findings → fix map

v8 scope (owner decision after R7 APPROVE): supported types narrowed to the owner's five accounts (personal cheque, business cheque, savings, personal eBucks, business eBucks). Credit card and vehicle removed from models, tests, M0 and M5; unknown types surface as `unsupported` (list-only, exit 4 elsewhere). Added `segment` personal/business (exit 7 if undeterminable), M0 rows for business transaction history and view permission on all five accounts, overdrawn-negative fixture.

Round 6 (descope delta):
1. ZAR-only contradicted EBUCKS → §4.2 allows exactly ZAR and EBUCKS (EBUCKS only on eBucks rows), per-currency totals, never summed.
2. M5 not executable for list-only types → §4.3 `accounts balance` on eBucks exits 4 `no_detailed_balance`; M5 reconciles cheque and savings only; eBucks covered by M3.
3. Stale references → §5 exit 4 no longer mentions statements; obsolete round-1..3 debit-order/statement fix-map lines removed below.

v6 descope (owner decision after R5 APPROVE): v1 scope reduced to account list, detailed balances, transactions. Removed `debit-orders`, `statements`, classification, their M0 rows and old M5. Added §4.3 detailed-balance model, M0 detailed-balance row, M5 = detailed balances + doctor.

Settled rounds 1-5 (non-descoped items): read-only allowlist (§4.1); fail-closed lockout, no auto-relogin (§3.2); mandatory view-only identity (§2); synthetic fixtures + scans (M0); completeness + reconciliation (§4.2, M3, M4); M0 budget/stop/matrix; argv credentials + env scrub (§3.1); single `secure.WriteFile` with dir fsync, NoOverwrite, pinned dir handle, ACL checks (§3.3); approval lifecycle (§6); provenance (§2); accountId HMAC (§5); release security (M6).
