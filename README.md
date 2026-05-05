# UEG - Universal Execution Gateway

UEG runs commands through a deterministic CLI that saves receipts, replays outcomes, and flags tampered execution records.
It is built for DevOps, infrastructure, security/compliance teams, and AI-agent builders who need proof of what happened on a machine.
It matters because command execution usually disappears into stdout and exit codes; UEG leaves behind replayable evidence instead.

First demo:
```powershell
go run ./cmd/ueg --receipt .\demo-receipt.json cmd /c echo hello-from-ueg
go run ./cmd/ueg --replay .\demo-receipt.json
```

## What UEG does

- Executes commands without relying on shell string interpretation by default
- Records receipts for each run
- Replays prior receipts and checks for deterministic path matches
- Detects tampering via receipt checksums
- Exposes validation and state information when work is incomplete

## Who it is for

- DevOps and infrastructure teams
- Security and compliance-minded engineering teams
- AI-agent builders who need a safer execution boundary
- Developers who want repeatable CLI evidence, not just terminal output

## Quick start

```powershell
go test ./...
go vet ./...
go run ./cmd/ueg --validate
```

For a fuller walkthrough, see [examples/quick_demo.md](examples/quick_demo.md).

## Core commands

```text
ueg <command> [args...]                   Execute command
ueg --prompt "<request>"                  Natural language request
ueg --env "<package spec>"                Environment or package request
ueg --check <command> [args...]           Preflight only
ueg --fix <command|--prompt|--env>        Apply guaranteed-safe refinements only
ueg --validate                            Prove the state model
ueg --replay <receipt.json|capsule.zip>   Replay a prior decision path
ueg --receipt <receipt.json> ...          Save receipt JSON
ueg --capsule <capsule.zip> ...           Save portable execution capsule
ueg --json ...                            Print receipt JSON
```

## Repository layout

```text
cmd/ueg/                  Go CLI entrypoint and tests
docs/                     Product docs and taxonomy references
examples/                 Copy-paste demos
launch/                   Launch copy, release notes, outreach, landing page
scripts/                  Verification and release build scripts
taxonomy/                 Machine-readable state assets
dist/                     Built release archives and checksums
```

## Validate and build

Run the verification pass:

```powershell
pwsh -File .\scripts\smoke-test.ps1
```

Build cross-platform release archives:

```powershell
pwsh -File .\scripts\build-release.ps1
```

This produces Windows, Linux, macOS Intel, and macOS Apple Silicon release archives plus `checksums.txt` in `dist/`.

## Taxonomy bundle

The product includes both the architectural and operational views of state:

- [docs/STATE_TAXONOMY_v1.0.md](docs/STATE_TAXONOMY_v1.0.md)
- [docs/STATE_MODEL_ALIGNMENT.md](docs/STATE_MODEL_ALIGNMENT.md)
- [taxonomy/states.json](taxonomy/states.json)
- [taxonomy/transitions.json](taxonomy/transitions.json)
- [taxonomy/operational_stages.json](taxonomy/operational_stages.json)

## Launch materials

Everything needed for public launch lives in [launch](launch):

- Product Hunt submission copy
- Landing page copy and single-file HTML starter
- GitHub release notes
- Demo commands
- Outreach posts
- Pricing and offer draft
- Validation report
