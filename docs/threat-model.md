# Threat model

## Scope and security objective

`fnb` is a personal, read-only client for an FNB Online Banking identity declared as `view-only-secondary`. Its security objective is to prevent the CLI from initiating account mutations, limit disclosure if its local state is stolen and fail closed when filesystem or page behavior is uncertain.

The protected assets are the view-only password, live session cookies, approval state and downloaded financial data. Trust boundaries exist between the process and FNB, the local filesystem, credential helpers, browser-cookie helpers and terminal output.

## Threats and controls

### Unauthorized banking changes

The product has no payment, transfer, beneficiary, card-control, profile or settings feature. Later network milestones must enforce an exact request allowlist inside the transport, including redirects and browser subrequests. Unknown hosts, paths, methods, parameters and routing values are blocked before transmission.

### Primary-user credentials

The CLI requires `identity = "view-only-secondary"`. A missing or different declaration is an authentication failure. Primary, transact-capable logins are unsupported. The declaration bounds intended use; it is not proof of the permissions FNB actually granted unless a later milestone discovers and implements an authoritative permission indicator.

### Credential disclosure

Passwords are accepted only from `FNB_PASSWORD` or an argv-array `credential_command`. The command is executed directly without a shell. Passwords are resolved lazily, held only in memory for login and never written to logs or error messages. Child processes receive an allowlisted environment with all `FNB_*` variables removed.

### Local-user access and filesystem races

The config directory is `0700` and sensitive files are `0600`. The CLI refuses a config or output directory that is a symlink, is owned by another uid, is group/world-writable or has ACL entries granting another principal access. ACL inspection is performed through a pinned directory descriptor and fails closed on unexpected errors.

Sensitive writes use a pinned `os.Root`, create a same-directory temporary file with exclusive creation and no symlink following, sync the file, publish it with a no-overwrite link or a guarded rename, then sync the directory. Existing symlink, non-regular and foreign-owned overwrite targets are rejected. Temporary files are removed on failures.

Malware already running as the account owner is out of scope because it can read the owner's browser and password manager. The view-only identity limits the expected impact to disclosure.

### Session theft and retention

Session cookies are sensitive even though the intended identity cannot transact. Later milestones must delete sessions on logout and absolute-lifetime expiry. Session files must use the secure-write primitive. On macOS, the config directory must be excluded from backups. Linux users must exclude it from backup and synchronization tools themselves.

### Lockout and automated login

Read commands must never submit credentials or trigger app approval. Login is always explicit, never retried and guarded by durable attempt state, rate limits and single-process locking. Any uncertain login outcome blocks further credential submission until the owner verifies browser login and explicitly clears the lockout.

### Cookie import

Cookie import is an ad-hoc fallback only. It must use a dedicated browser profile for the view-only identity, retain only `online.fnb.co.za` cookies and apply the same identity check as credential login. A primary-user browser profile must never be imported.

### Incomplete or misleading data

Every data response must be demonstrably complete. Pagination caps, layout drift, unknown currency, missing account segmentation and unfollowed continuation links are hard failures. Partial results are emitted only to an explicitly requested secure file and never presented on standard output as complete.

### Supply chain

Runtime dependencies are minimized. CI actions are pinned to full commit SHAs, tests run on macOS and Linux, and `govulncheck` scans the module. Release artifacts and Homebrew publishing gain checksum and scoped-token controls in the release milestone.

## Operational assumptions

- The owner uses only an FNB view-only secondary identity.
- The machine account and Go toolchain are trusted.
- FNB may change or withdraw the web interface without notice.
- Automated access may violate FNB's terms and can be stopped at any time.

## Stop criteria

Archive the repository and remove its Homebrew formula if FNB requests takedown or sends an account notice objecting to this access. Stop immediately on an account lock, suspicious-activity notice, CAPTCHA or unexplained authentication response.
