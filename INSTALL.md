# Install, Initialize, Update, Transfer, and Remove UEG

UEG is a standalone CLI. It installs no service and changes no shell startup
file. The executable, evidence home, public trust artifacts, and encrypted
offline recovery package are separate assets with separate custody rules.

## 1. Verify the download

Download `SHA256SUMS` and the archive for your platform through the intended
release channel. A matching checksum proves byte identity with that checksum;
it does not identify the publisher unless the checksum source is independently
trusted.

Windows PowerShell:

```powershell
$archive = Get-ChildItem -LiteralPath . -Filter 'ueg-*-windows-amd64.zip'
if ($archive.Count -ne 1) { throw 'Expected exactly one Windows UEG archive' }
$line = Get-Content .\SHA256SUMS | Where-Object { $_ -match ('  ' + [regex]::Escape($archive.Name) + '$') }
if (-not $line) { throw 'Archive is not listed in SHA256SUMS' }
$expected = ($line -split '  ', 2)[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive.FullName).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'UEG checksum mismatch' }
```

Linux:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

## 2. Extract and identify the product

Extract the archive into a new directory. Invoke the binary there before
moving it onto `PATH`:

```text
ueg version
ueg --help
```

Those commands are inert. They do not create keys, an evidence home, or other
UEG state.

Each platform archive includes a disposable demo that resolves the executable
from the extracted archive root:

```text
Windows:  pwsh -NoProfile -File .\demo\demo.ps1
Linux:    bash ./demo/demo.sh
```

The independent Python verifier is a separate archive. To include it in the
Bash demo, extract `ueg-python-verifier.zip`, install its `requirements.lock`
in an isolated environment, and set `UEG_PYTHON_VERIFIER_ROOT` to that
extracted directory before running the demo.

On Windows, keep `ueg.exe` in a directory on `PATH` or invoke its full path. On
Linux or macOS:

```bash
chmod +x ./ueg
install -m 0755 ./ueg "$HOME/.local/bin/ueg"
```

## 3. Create a B+ Evidence Identity

Initialization is explicit. Choose a new evidence-home directory and a new
recovery-package file in an existing owner-controlled directory. They must be
different paths, and neither destination may already exist.

Windows PowerShell:

```powershell
ueg identity init `
  --home "$env:USERPROFILE\.ueg" `
  --recovery-package "E:\UEG-Recovery\primary-ledger-recovery.json" `
  --label "Primary operations ledger"
```

Linux or macOS:

```bash
ueg identity init \
  --home "$HOME/.ueg" \
  --recovery-package "/media/offline/UEG/primary-ledger-recovery.json" \
  --label "Primary operations ledger"
```

UEG prompts for the package passphrase through the terminal. It never accepts
the passphrase as a command-line argument. Initialization does not complete
until the encrypted package has been durably written and passed an actual
decrypt/sign/verify self-test.

Run `ueg identity status` and record the complete
`ueg:identity:sha256:...` identity id through a channel separate from exported
evidence. Test the recovery package before moving it offline:

```text
ueg identity recovery-verify --recovery-package <file> --identity-id <complete-identity-id>
```

Keep the recovery package outside the evidence home. Make separately protected
encrypted backup copies only through an owner-controlled process. UEG creates
no hidden backup. The file itself is owner-protected; UEG does not rewrite the
permissions of an owner-selected parent directory.

## 4. First operation and independent trust artifacts

```text
ueg check -- echo hello
ueg run -- echo hello
ueg ledger
ueg identity card --output identity-card.json
ueg identity anchor --output evidence-anchor.json
ueg identity checkpoint export --output lifecycle-checkpoint.json
ueg export evidence-001.tar.gz
```

`check` is inert. A policy refusal is also inert. `run` writes evidence only
when a command is admitted and executed. Artifact and export commands refuse to
replace an existing destination; use a new filename each time.

Distribute the identity id/card and lifecycle checkpoint independently of the
bundle when another party needs a B+ trust verdict. The verifier must not copy
its expected identity id from the bundle being checked.

## 5. Update without changing identity

1. Stop UEG operations using the evidence home.
2. Verify the new release archive and extracted binary.
3. Replace only the installed executable.
4. Run `ueg version`.
5. Run `ueg ledger` and `ueg identity status` against the existing home.
6. Compare the complete identity id and retained lifecycle checkpoint.

Do not replace or overlay the evidence home during a binary update. Removing
the executable does not remove evidence or identity material.

## 6. Rotate or transfer the operational key

Routine rotation and official device transfer create a new operational epoch
and retire the old one. Exactly one epoch remains active.

```text
ueg identity anchor --output before-rotation-anchor.json
ueg identity rotate --recovery-package <offline-file> --reason ROUTINE_ROTATION --anchor before-rotation-anchor.json
ueg identity checkpoint export --output after-rotation-checkpoint.json
```

Use `identity transfer` instead of `rotate` for the official transfer workflow.
Copy the complete evidence home while no UEG process is using it, then perform
the transfer from the destination and retain the new checkpoint independently.
A copied home is only a clone; concurrent signing is not authorized.

Supply a newer `--checkpoint` or `--trust-store` to `run`, `replay`, status, or
lifecycle mutations when available. UEG then blocks a stale clone before it
can sign or mutate state.

## 7. Suspension, recovery, and revocation

Suspension stops signing until root-authorized resumption. Operational-key
recovery replaces a lost operational key but does not recover missing receipts
or a lost ledger. Preserve a known-good anchor before a transition whenever the
current ledger is still trustworthy.

Permanent revocation requires the complete current key fingerprint and the
explicit compromise confirmation flag shown by `ueg identity revoke --help`.
After revocation, the identity cannot sign again.

If the recovery package is permanently lost, current signing may continue but
future authenticated rotation, recovery, suspension, and revocation are no
longer possible. Establish a new identity. If the recovery root is compromised,
the old identity's trustworthy continuity has ended; do not attempt to repair
it under the same identity id.

## 8. Migrate a legacy v1/v2 home

Migration is explicit, one-way, and never automatic. First verify the legacy
home and independently confirm its complete operational fingerprint. Migrate
only when there is no reason to suspect that key was compromised:

```text
ueg identity migrate --home <legacy-home> --recovery-package <new-offline-file> --confirm-key-id <legacy-fingerprint> --confirm-not-compromised
```

Migration enrolls the existing key as epoch zero. Historical v1/v2 evidence
remains verifiable, but B+ lifecycle protection began at migration and is not
retroactive. Old v2 binaries fail closed on the migrated live home.

## 9. Back up and restore

Stop operations, then copy the complete evidence home as one unit to protected
storage. Do not combine files from different snapshots. Retain current public
checkpoints separately so a restored stale clone can be detected.

After restore, run:

```text
ueg ledger --home <restored-home>
ueg identity status --home <restored-home> --checkpoint <latest-retained-checkpoint>
```

If UEG reports an interrupted transaction, use the exact recovery command it
names. `ueg recover` completes a paired receipt write; `ueg identity
transaction-recover` completes or safely rolls back initialization, migration,
or lifecycle mutation. Neither command reruns a child command.

## 10. Remove or deliberately clean up

Delete the installed executable to uninstall UEG. It has no background service.
That action intentionally leaves the evidence home, identity, recovery package,
public artifacts, and exports untouched.

Before deliberately deleting evidence, export to a new filename and verify it
from another directory with independently retained trust inputs. Delete the
home and recovery copies only when you intend to destroy local access. Ordinary
file deletion is not guaranteed secure erasure on every filesystem or device.

Read [LIMITS.md](LIMITS.md) and [SUPPORT.md](SUPPORT.md) before production use.
