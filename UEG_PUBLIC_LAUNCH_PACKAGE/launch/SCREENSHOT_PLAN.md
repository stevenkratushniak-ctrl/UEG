# Screenshot Plan

## 1. `ueg --validate`

**Capture:**

- terminal output from `ueg --validate`

**What it proves:**

- the binary exposes a built-in proof surface
- the state model can be validated directly by the user

## 2. Command with receipt

**Capture:**

- terminal output from a command run with `--receipt`
- the generated `demo-receipt.json` visible in the directory

**What it proves:**

- UEG executes a real command
- a receipt artifact is created as part of the run

## 3. Replay `MATCH`

**Capture:**

- terminal output from `ueg --replay demo-receipt.json`

**What it proves:**

- the receipt can be replayed
- the tool reports deterministic path match when the record is intact

## 4. Tamper detected

**Capture:**

- terminal output from replaying a manually edited receipt

**What it proves:**

- UEG can detect receipt tampering
- replay is not just a convenience feature; it verifies integrity

## 5. `dist/` plus `checksums.txt`

**Capture:**

- file explorer or terminal listing showing the four platform archives and `checksums.txt`

**What it proves:**

- the product is packaged for public download
- there is a checksum verification step for release assets

## 6. Optional 30-second GIF

**Capture order:**

- `ueg --validate`
- run command with `--receipt`
- replay `MATCH`
- edit receipt
- replay `TAMPERED`

**What it proves:**

- the whole product value proposition in one sequence
