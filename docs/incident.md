# Incident procedure

## Account warning, suspected flagging or lockout

1. Stop all CLI use and remove any scheduled invocation.
2. Run `fnb auth logout` if a safe session logout remains possible; do not attempt another credential login.
3. Contact FNB through the official app or another verified support channel.
4. Rotate the view-only user's password after FNB confirms the account is safe.
5. Resume only after the cause is understood and the owner explicitly accepts the risk.

An FNB takedown request or account notice objecting to automated access is a permanent stop criterion: archive the repository and remove the Homebrew formula.

## Leaked session, credential or fixture

1. Stop use and end all Online Banking sessions through FNB settings.
2. Rotate the view-only user's password.
3. Delete local session and approval-state files.
4. Remove the exposed artifact from every reachable storage location.
5. Decide whether repository history must be purged based on the exposed data and its distribution.

Do not paste live cookies, credentials, account numbers, HAR content or unredacted financial data into issues, pull requests, chat or CI logs.

## Retention

- Session state is deleted on explicit logout and absolute-lifetime expiry.
- Verbose diagnostics go only to stderr and are never persisted by the CLI.
- Raw M0 HAR captures are stored outside repositories, encrypted at rest and deleted after synthetic fixtures are accepted.
- The M0 fixture generator and local denylist remain outside the repository.
- Partial data files exist only when explicitly requested by the user and use secure `0600` writes.

## Evidence to preserve

Record timestamps, the command name, exit code and non-secret error slug. Preserve FNB's notice text and official support case number. Do not preserve request bodies, passwords, OTPs or cookies in the incident record.
