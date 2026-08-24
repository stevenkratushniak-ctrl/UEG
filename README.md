# UEG - Universal Execution Gateway

UEG runs commands through an explicit policy gate and records signed,
offline-verifiable evidence of what was requested, admitted, executed, and
returned. It is built for operators, CI systems, and AI agents that need both
a pre-execution decision and a durable receipt chain. UEG is not a sandbox.

## Public release status

`2.2.0-v3-candidate.2` is publicly available as an **unsigned Windows x64 and
Linux amd64 engineering release**. Both exact platform archives passed the same
50-check native packaged-artifact workflow. It is not a signed general release.

- [Product page](https://stevenkratushniak-ctrl.github.io/UEG/)
- [GitHub prerelease and exact downloads](https://github.com/stevenkratushniak-ctrl/UEG/releases/tag/v2.2.0-v3-candidate.2)
- [Release checksums](RELEASE_CHECKSUMS.txt)
- [Complete public-status boundary](PUBLIC_ENGINEERING_PREVIEW.md)
- [Support through GitHub Issues](https://github.com/stevenkratushniak-ctrl/UEG/issues)
- [Private vulnerability reporting](https://github.com/stevenkratushniak-ctrl/UEG/security/advisories/new)

The qualified Windows x64 archive SHA-256 is
`42daf24cabbef22c074516ca246d237866a2499340a19737ce854f37128bb179`.
The qualified Linux amd64 archive SHA-256 is
`d5bb3b251d1dc7035298a45e86cc869caf001114e5c4562c248709beea94c0c3`.
Linux arm64, macOS, ARM, and WSL are not qualified distribution targets. The
manifest is unsigned, and no independent-review or customer-result claim is
made.

Start a disposable first demo by creating an evidence identity, then running a
harmless command:

```text
ueg identity init --home ./ueg-demo --recovery-package ./ueg-demo-recovery.json --label "Demo ledger"
ueg run --home ./ueg-demo -- echo hello
ueg ledger --home ./ueg-demo
```

Initialization prompts for a recovery-package passphrase without placing it on
the command line. Move the encrypted recovery package to separately protected
offline storage after testing it. Help, version, checks, refusals, parse errors,
inspection, and verification never create an identity or evidence home.

From an extracted release archive, run the disposable packaged demo directly:

```text
Windows:  pwsh -NoProfile -File .\demo\demo.ps1
Linux:    bash ./demo/demo.sh
```

The platform archive performs Go verification itself. The Bash demo runs the
independent Python verifier only when `UEG_PYTHON_VERIFIER_ROOT` names an
extracted `ueg-python-verifier.zip`; that verifier and its locked dependencies
are distributed separately.

The demo uses the operating system's temporary directory. The retained Linux
qualification uses a persistent native Linux temp root because this host's WSL
systemd-user startup can remove ordinary `/tmp` state. WSL hosted that native
amd64 run but is not itself a qualified distribution target.

## What UEG does

- Refuses every command classified `PROHIBITED`, regardless of posture or
  approval flags.
- Refuses `UNCLASSIFIED` commands by default and requires explicit approval for
  `IRREVOCABLE` commands.
- Records executed commands in an Ed25519-signed, hash-linked receipt chain.
- Exports deterministic evidence bundles without private keys.
- Verifies legacy v1/v2 evidence and B+ evidence with independent Go and Python
  implementations.
- Gives one evidence ledger a stable B+ identity across operational-key
  rotation, official transfer, suspension, recovery, and revocation.

UEG decides whether to start a process. An admitted process still runs with the
caller's privileges and is not contained after launch.

## Thirty-second workflow

After explicit initialization:

```text
ueg check --home ./ueg-demo -- echo hello
ueg run --home ./ueg-demo -- echo hello
ueg identity card --home ./ueg-demo --output ./identity-card.json
ueg identity checkpoint export --home ./ueg-demo --output ./checkpoint.json
ueg export --home ./ueg-demo ./evidence.tar.gz
```

`check` is inert: it classifies but does not execute or record. `run` executes
only an admitted command and records its admission and outcome. Public identity
artifacts and export destinations are never silently overwritten.

For a B+ trust verdict, obtain the complete `ueg:identity:sha256:...` identity
pin and lifecycle checkpoint through a channel independent of the bundle:

```text
ueg verify --expected-identity-id <PINNED_IDENTITY_ID> --checkpoint ./checkpoint.json ./evidence.tar.gz
```

A matching independent pin and authentic checkpoint can yield `VERIFIED` at
that checkpoint. A clean offline verifier cannot prove that no newer revocation
exists. `--require-current-status` therefore exits nonzero with
`TRUST_INDETERMINATE` when freshness cannot be established.

## Policy decisions

| Class | Meaning | Enforce posture |
|---|---|---|
| `REVERSIBLE` | Read or a precisely undoable change described by argv | admitted |
| `COMPENSABLE` | Can be counteracted but not erased | admitted |
| `IRREVOCABLE` | Prior state cannot be restored by UEG | needs `--approve` |
| `PROHIBITED` | A recognized machine/filesystem destructive form | always refused |
| `UNCLASSIFIED` | No rule describes this argv | needs `--allow-unclassified` |

Observe posture admits non-prohibited classifications, including
`IRREVOCABLE` and `UNCLASSIFIED`, so a rule set can be measured before enforce
mode is enabled. It never admits `PROHIBITED`. Classification is syntactic:
UEG reads argv and does not inspect a program's code or parse shell strings.
Read [LIMITS.md](LIMITS.md) before relying on the gate.

The versioned policy rules live in
[`internal/policy/rules.json`](internal/policy/rules.json). Their hash is bound
into receipts so an export states which rules were in force.

## Evidence and replay

An admitted execution creates an admission receipt and an outcome receipt. The
outcome binds the exit code, complete stdout/stderr SHA-256 values, byte counts,
duration, and bounded excerpts. Receipt ids are content-derived, signatures
cover those ids, and each receipt names its predecessor.

`ueg replay` verifies stored evidence before doing anything. It then applies
current enforce policy, re-runs one complete admitted command, records the new
receipts, and compares exit code and output hashes. It reports `MATCH`,
`DIVERGED`, `REFUSED`, `TAMPERED`, or `INCOMPLETE_OR_TRUNCATED`. Replay never
repeats `PROHIBITED`; non-reversible and unclassified commands still require
their explicit flags.

`ueg export` validates the home, writes a protected partial file beside the
destination, verifies the completed temporary bundle, and atomically publishes
the final new filename. It does not replace an existing destination or include
any private key.

## B+ evidence identities

A B+ Evidence Identity means only the pseudonymous cryptographic continuity of
one evidence ledger. Its stable identity id is derived from an authenticated
genesis manifest, not from a replaceable operational key. It does not prove a
human, organization, device, legal authority, evidence truth, trusted time,
admissibility, or nonrepudiation. Labels are advisory.

Exactly one operational signing key may be active. Lifecycle records are
canonical, hash-linked, recovery-root authenticated, and bound to exact ledger
boundaries. The encrypted recovery package is created only at the explicit
destination selected during initialization; the recovery private key is never
stored in the evidence home, bundle, receipt, log, or release archive.

```text
ueg identity status --home <home>
ueg identity rotate --home <home> --recovery-package <offline-file> --reason ROUTINE_ROTATION
ueg identity transfer --home <home> --recovery-package <offline-file> --reason DEVICE_TRANSFER
ueg identity suspend --home <home> --recovery-package <offline-file> --reason INVESTIGATION
ueg identity resume --home <home> --recovery-package <offline-file> --reason CLEARED
ueg identity recover --home <home> --recovery-package <offline-file> --reason LOST_OPERATIONAL_KEY
```

Lifecycle mutations prompt for the recovery-package passphrase. For local
automation, `--passphrase-stdin` reads it from standard input; UEG never accepts
the passphrase as an argument. Supply `--checkpoint` or `--trust-store` to stop
a stale clone before signing or lifecycle mutation when newer authenticated
status is available.

Recovery restores signing authority only. It does not recreate deleted
receipts or a lost ledger. Permanent loss of the recovery root makes future
authenticated lifecycle control impossible. Recovery-root compromise ends the
identity's trustworthy continuity; establish a new independently pinned
identity rather than pretending the old identity can be repaired.

See [INSTALL.md](INSTALL.md) for custody, transfer, migration, update, and
removal procedures.

## Commands

```text
ueg identity <command>                    initialize and manage B+ identity
ueg run [flags] -- <command>              decide, execute, and record
ueg check [flags] -- <command>            decide only; never execute or write
ueg replay [flags] [receipt-prefix]       verify, re-run, and compare
ueg export [--home <dir>] <bundle>        export verified evidence
ueg verify [trust flags] <bundle>         verify legacy or B+ evidence
ueg ledger [--home <dir>]                 inspect local evidence
ueg recover [--home <dir>]                finish an interrupted receipt write
ueg policy [-- <command>]                 show rules or classify inertly
ueg validate                              inspect model invariants inertly
ueg version
```

Run `ueg help <command>`, `ueg <command> --help`, or
`ueg identity <command> --help` for exact flags. Exit codes are the child
command's exit code when it ran, `77` for policy refusal, `2` for verification
or trust failure, `3` for incomplete recorded execution, and `1` for usage or
internal failure. `--json` provides stable machine-readable output.

## Install and verify

Download the platform archive and `SHA256SUMS`, verify the archive, extract it,
and invoke `ueg version` before initialization. Full Windows and POSIX commands
are in [INSTALL.md](INSTALL.md). The independent Python verifier is distributed
as `ueg-python-verifier.zip` with locked dependencies and schemas.

Release targets are Windows amd64, Linux amd64, Linux arm64, macOS Intel, and
macOS Apple Silicon. Cross-building is not native runtime qualification; see
[SUPPORTED_PLATFORMS.md](SUPPORTED_PLATFORMS.md).

Build locally with Go 1.22 or newer:

```text
make build
make test
make dist VERSION=2.2.0-v3-candidate.2
make verify-release DIST=dist
```

Release construction requires a clean source tree and refuses to replace an
existing output directory. Reproducible-build details are in
[REPRODUCIBLE_BUILDS.md](REPRODUCIBLE_BUILDS.md).

## Product boundary

UEG is not operating-system containment, malware detection, secret scrubbing,
trusted timestamping, PKI, a hosted revocation service, or protection for
commands run outside UEG. Host timestamps are metadata only. Evidence proves
what the UEG process signed and chained, subject to the supplied external trust
inputs; it does not prove the host was honest.

The source is a reconstructed UEG v2 line extended by the B+ work. The original
archive omitted `internal/keys` and could not compile; that package was newly
reconstructed, not proven original Devin source. See [PROVENANCE.md](PROVENANCE.md).

MIT License. See [LICENSE](LICENSE).
