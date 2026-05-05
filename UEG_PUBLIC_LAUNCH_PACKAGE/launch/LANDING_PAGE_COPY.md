# Landing Page Copy

## Headline

Run commands. Prove what happened.

## Subheadline

UEG is a standalone CLI for teams that need receipts, replay, and tamper detection around command execution.

## Value bullets

- Save a receipt for every run
- Replay prior runs and verify deterministic path matches
- Detect when an execution record has been changed
- Validate the state model with a built-in proof command
- Keep the workflow local with no service dependency

## Demo section

**Section heading:** See the full flow in under a minute

**Body copy:**

Run a command, save a receipt, replay it, and then intentionally tamper with the receipt to see UEG catch the change.

**Demo bullets:**

- Execute a real command
- Save `receipt.json`
- Replay and get `MATCH`
- Change the receipt
- Replay and get `TAMPERED`

## Download section

**Section heading:** Download UEG

**Body copy:**

Pick the release archive for your platform, verify the checksum, extract the binary, and run the quick demo.

**Download bullets:**

- Windows AMD64
- Linux AMD64
- macOS Intel
- macOS Apple Silicon
- `checksums.txt`

## Proof and security section

**Section heading:** Built for teams that need evidence

**Body copy:**

UEG focuses on proof and replay, not buzzwords. It records receipts, verifies deterministic execution paths during replay, and flags receipt tampering. It does not claim sandboxing, hosted isolation, or compliance certifications it does not have.

**Proof bullets:**

- Receipts can be saved and shared
- Replay can confirm `MATCH`
- Tampering triggers checksum failure
- `ueg --validate` proves the state model invariants exposed by the binary

## Pricing section

**Section heading:** Start free, buy when you need shipping convenience and support

**Pricing bullets:**

- Community: build from source and use the docs for free
- Founding License: prebuilt binaries, commercial use, updates, and email support
- Team License: shared internal use and team-friendly support
- Enterprise/Support: custom onboarding and procurement support

## FAQ

### Is UEG open source?

The repo can offer a free source-build path even if paid tiers cover convenience, binaries, and support.

### Does UEG run in the cloud?

No. UEG is a local CLI.

### Does UEG sandbox commands?

No. It adds proof, replay, and validation around execution, but it is not an isolation layer.

### Who should care?

DevOps, infrastructure engineers, security/compliance teams, and AI-agent builders who need better command execution records.

### How do I know it worked?

Run the quick demo, save a receipt, replay it, and confirm `MATCH`.

## CTA

Download UEG, run the 60-second demo, and see whether receipts and replay belong in your workflow.
