# Troubleshooting UEG

UEG errors are intended to state what happened and the safe next action. Do not
delete or edit evidence files to make an error disappear.

## Public support path

Use https://github.com/stevenkratushniak-ctrl/UEG/issues for ordinary product
questions and sanitized, reproducible defects. No support email, response-time
promise, or service-level agreement is configured.

Use private vulnerability reporting for undisclosed security issues:
https://github.com/stevenkratushniak-ctrl/UEG/security/advisories/new

## Evidence directory does not exist

`run`, `ledger`, `replay`, `export`, and recovery require an initialized home.
Pass the correct `--home` path or create a new identity explicitly with
`ueg identity init --home <new-dir> --recovery-package <new-file>`. `check`
never creates the home.

## Evidence directory is busy

Another UEG process is using the same home. Wait for it to finish. If no UEG
process remains, retry; the lock is owned by the operating system and is
released when a process exits. Do not delete `.ueg.lock` while a process may be
running.

## Recovery is required

An interrupted receipt/request pair is journaled. Run `ueg recover --home
<path>`, then `ueg ledger --home <path>`. Recovery completes only the exact
signed pending pair; it does not rerun the command.

## Evidence verification failed

Leave the home unchanged. Work from a copy if investigation is necessary.
Restore a complete known-good backup rather than editing individual receipts,
requests, keys, or sequence numbers.

## Private key is missing or cannot be secured

Do not create a replacement key manually. Restore a complete current home, or
use `ueg identity recover` with the encrypted recovery package when the ledger
is intact and only the active operational key was lost. Recovery does not
restore missing receipts or a lost ledger. Windows requires a protected DACL
for the owner and LocalSystem; POSIX requires protected directories and mode
`0600` for private-key files.

## Export destination already exists

Choose a new filename or move the existing file. UEG never silently replaces an
export. A neighboring `.ueg-export-*.partial` file is incomplete; remove it
only after confirming no export process is active.

## A command was refused

Read the effect class and reason. `PROHIBITED` never runs through UEG.
`IRREVOCABLE` needs explicit `--approve`; `UNCLASSIFIED` needs explicit
`--allow-unclassified`. Those approvals do not make the command safe, and UEG
is not a sandbox.

## Verification is not fully trusted

Legacy `INTERNALLY_CONSISTENT` means no independent signer fingerprint was
supplied. B+ `TRUST_INDETERMINATE` commonly means the genesis identity pin,
independent lifecycle checkpoint, known-good anchor, or offline freshness
needed for the requested claim is unavailable. Read `reason_code` in JSON
output. Never copy an expected pin or checkpoint from the bundle being checked.

## Identity state is stale or forked

Stop using that home. Compare it with the latest independently retained
checkpoint. Restore the complete current home or establish a new identity if
the current ledger is unavailable. Do not merge lifecycle or receipt files by
hand. UEG can detect a clone only when newer authenticated state is supplied or
retained.

## Lifecycle transaction recovery is required

Run `ueg identity transaction-recover --home <path>`, then inspect
`ueg identity status` and `ueg ledger`. The journal completes one authenticated
transition or rolls an incomplete early stage back. It never invents a second
active epoch.

## Recovery package cannot be opened

Confirm the selected package, identity id, and passphrase. Do not edit the
package. An authentication failure means the passphrase is wrong or the package
changed. If every protected copy is lost, UEG cannot reconstruct the recovery
root. If compromise is suspected, establish a new identity rather than
continuing under the old pin.

## Reporting a product problem

Preserve the exact UEG version, operating system, exit code, and sanitized
stderr. Do not share a private key, raw credentials, or evidence containing
sensitive command arguments or output. Use GitHub Issues for non-sensitive
product reports and the private reporting path in [SECURITY.md](SECURITY.md) for
undisclosed vulnerabilities.
