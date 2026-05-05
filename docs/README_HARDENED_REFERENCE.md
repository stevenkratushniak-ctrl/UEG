# UEG - Universal Execution Gateway

## Install

```bash
# Linux
curl -L -o ueg https://[...]/ueg-linux-amd64
chmod +x ueg
sudo mv ueg /usr/local/bin/

# macOS (Intel)
curl -L -o ueg https://[...]/ueg-darwin-amd64
chmod +x ueg
sudo mv ueg /usr/local/bin/

# macOS (Apple Silicon)
curl -L -o ueg https://[...]/ueg-darwin-arm64
chmod +x ueg
sudo mv ueg /usr/local/bin/

# Windows
# Download ueg-windows-amd64.exe
# Add to PATH
```

## Usage

```bash
ueg <command> [args...]           # Execute command
ueg --prompt "<request>"          # Natural language
ueg --env "<package spec>"        # Environment/packages
ueg --check <command> [args...]   # Preflight only
ueg --validate                    # Prove state model
ueg --replay <receipt.json>       # Replay from receipt
ueg --receipt <file> <cmd...>     # Save receipt

UEG_VERBOSE=1 ueg <cmd>           # Show state flow
```

## States

```
○ VOID        ◔ NASCENT     ◑ DECLARED    ◕ CANONICAL
● GATED       ◈ REFINABLE   ◉ EXECUTABLE  ✓ EXECUTED
◆ STABILIZED
```

## Output

Success: stdout passes through.

Incomplete: Shows state, requirements, and what's needed to proceed.

## Files

```
states.json       State definitions (machine-readable)
transitions.json  Transition graph (machine-readable)
```

## Validate

```bash
ueg --validate
```

Returns JSON proof that:
- No error states exist
- Execution is gated
- State space is closed
- Transitions are forward-only
## Hardening (v1.2.0+)

- Receipts now include `determinism_hash` (stable across replays of the same decision-path; ignores timestamps, trace IDs, stdout/stderr text, and duration).
- Replay now verifies determinism via `determinism_hash` and also matches the transition flow (from/to/action) ignoring timestamps.
- Capsule `.zip` output is now deterministic (fixed timestamps + stable entry order), so the same receipt produces identical capsule bytes.

Recommended CI gates:
- `go test ./... -race`
- `go vet ./...`
- `govulncheck ./...` (if available in your toolchain)
- Fuzz: `go test -fuzz=Fuzz -run=^$` (add fuzz tests for prompt/env parsing + path resolution)
