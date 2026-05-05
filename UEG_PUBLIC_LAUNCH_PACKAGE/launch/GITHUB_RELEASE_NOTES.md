# UEG Public Release Notes

## v1.0 launch summary

This is the first public launch package for UEG: a standalone CLI for command execution with receipts, replay, validation, and tamper detection.

Important version note:

- the current build artifacts in this package report `v1.2.0`
- if you publish these exact binaries, the GitHub release tag should match `v1.2.0`
- if you want the public release tag to be `v1.0.0`, change the version in the core intentionally before rebuilding

## What is included

- `ueg-v1.2.0-windows-amd64.zip`
- `ueg-v1.2.0-linux-amd64.zip`
- `ueg-v1.2.0-darwin-amd64.zip`
- `ueg-v1.2.0-darwin-arm64.zip`
- `checksums.txt`

## What UEG does

- Executes commands through a deterministic gateway
- Saves receipts for runs
- Replays prior runs and checks for deterministic path matches
- Detects tampered receipts via checksum verification
- Exposes a `--validate` command for state-model proof output

## What UEG does not do

- It does not claim OS-level sandboxing
- It does not require or provide a cloud service
- It does not replace your shell
- It does not promise compliance certifications, hosted audit storage, or managed workflows

## Checksum verification

Verify release assets before use.

### PowerShell

```powershell
Get-FileHash .\ueg-v1.2.0-windows-amd64.zip -Algorithm SHA256
Get-Content .\checksums.txt
```

### Bash

```bash
sha256sum ./ueg-v1.2.0-linux-amd64.zip
cat ./checksums.txt
```

## Install instructions

### Windows AMD64

1. Download `ueg-v1.2.0-windows-amd64.zip`
2. Verify the SHA-256 hash against `checksums.txt`
3. Extract the archive
4. Run `ueg.exe` from the extracted folder or add it to `PATH`

### Linux AMD64

1. Download `ueg-v1.2.0-linux-amd64.zip`
2. Verify the SHA-256 hash
3. Extract the archive
4. `chmod +x ueg`
5. Move it into your preferred binary directory if desired

### macOS Intel

1. Download `ueg-v1.2.0-darwin-amd64.zip`
2. Verify the SHA-256 hash
3. Extract the archive
4. `chmod +x ueg`

### macOS Apple Silicon

1. Download `ueg-v1.2.0-darwin-arm64.zip`
2. Verify the SHA-256 hash
3. Extract the archive
4. `chmod +x ueg`

## Demo commands

### Windows PowerShell

```powershell
.\ueg.exe --receipt .\demo-receipt.json cmd /c echo hello-from-ueg
.\ueg.exe --replay .\demo-receipt.json
.\ueg.exe --validate
```

### Bash

```bash
./ueg --receipt ./demo-receipt.json /bin/echo hello-from-ueg
./ueg --replay ./demo-receipt.json
./ueg --validate
```
