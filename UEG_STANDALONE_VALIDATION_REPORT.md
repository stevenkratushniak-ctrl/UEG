# UEG Standalone Validation Report

## Scope

This report is the authoritative standalone validation record for `C:\UEG_PRODUCT`.

Historical launch validation files remain preserved under `launch/`, but this document is the standalone-root proof after extraction and packaging normalization.

## Commands run from `C:\UEG_PRODUCT`

### Formatting

```powershell
Get-ChildItem .\cmd\ueg -Filter *.go | ForEach-Object { gofmt -w $_.FullName }
```

Result: passed.

### Unit tests

```powershell
go test ./...
```

Result: passed.

### Static analysis

```powershell
go vet ./...
```

Result: passed.

### Smoke test script

```powershell
pwsh -File .\scripts\smoke-test.ps1
```

Result: passed.

Validation proof returned:

- `PROOF: no_error_states - verified across all 9 states`
- `PROOF: execution_gated - only EXECUTABLE is executable`
- `PROOF: single_terminal - only STABILIZED is terminal`
- `PROOF: closed_state_space - exactly 9 states defined`
- `PROOF: forward_only - ordinals 0-8 monotonically increase`

### Direct validation command

```powershell
go run ./cmd/ueg --validate
```

Result: passed.

### Fuzz targets

```powershell
go test ./cmd/ueg -run=^$ -fuzz=FuzzDeterminismHash_NoPanic$ -fuzztime=3s
go test ./cmd/ueg -run=^$ -fuzz=FuzzReadReceiptFromCapsule_NoPanic$ -fuzztime=3s
```

Result: both passed.

### Release packaging

```powershell
pwsh -File .\scripts\build-release.ps1
```

Result: passed.

### Reproducibility check

```powershell
pwsh -File .\scripts\build-release.ps1
pwsh -File .\scripts\build-release.ps1
```

Result: passed.

Repeated `dist/checksums.txt` output was identical across consecutive rebuilds:

- `973c665b0af59ccbe3fcb7edc8d637242471a16209a52667792219e7de12532f  ueg-v1.2.0-darwin-amd64.zip`
- `654e75b7d559870722df1874d7d5e145e7c270f2e76a5c84ceaa48a17e47b5bc  ueg-v1.2.0-darwin-arm64.zip`
- `9645781daf7183c61cbc463f339d622ed3ae0e26a51f88d41d6d032386c9120f  ueg-v1.2.0-linux-amd64.zip`
- `16ef6ac4b20028a2a0db6646df4f17e8e8fa233627da1e61504c93079f17fa27  ueg-v1.2.0-windows-amd64.zip`

## README and quick-demo proof

### Receipt run

```powershell
go run .\cmd\ueg --receipt .\demo-receipt.json cmd /c echo hello-from-ueg
```

Result: passed. Output was `hello-from-ueg`.

### Replay match

```powershell
go run .\cmd\ueg --replay .\demo-receipt.json
```

Result: passed. Replay reported `REPLAY: DETERMINISTIC - state paths match`.

### Tamper detection

```powershell
Copy-Item .\demo-receipt.json .\demo-receipt-tampered.json
$json = Get-Content .\demo-receipt-tampered.json -Raw | ConvertFrom-Json
$json.final_stage = 7
$json | ConvertTo-Json -Depth 100 | Set-Content .\demo-receipt-tampered.json
go run .\cmd\ueg --replay .\demo-receipt-tampered.json
```

Result: passed. Replay reported `REPLAY: RECEIPT TAMPERED (checksum mismatch)`.

## Checksum verification

Local `dist/checksums.txt` was verified against every archive in `dist/`.

- `ueg-v1.2.0-darwin-amd64.zip`: match
- `ueg-v1.2.0-darwin-arm64.zip`: match
- `ueg-v1.2.0-linux-amd64.zip`: match
- `ueg-v1.2.0-windows-amd64.zip`: match

## GitHub release verification

Verified against the live release:

- Repo: `https://github.com/stevenkratushniak-ctrl/UEG`
- Tag: `v1.2.0`
- Release URL: `https://github.com/stevenkratushniak-ctrl/UEG/releases/tag/v1.2.0`

Local asset names match the live release asset names:

- `checksums.txt`
- `ueg-v1.2.0-darwin-amd64.zip`
- `ueg-v1.2.0-darwin-arm64.zip`
- `ueg-v1.2.0-linux-amd64.zip`
- `ueg-v1.2.0-windows-amd64.zip`

The live release assets were refreshed after deterministic packaging so their published digests now match the standalone root.

## Product Hunt preservation check

Hash comparison against the original source root confirmed preserved launch copy for:

- `launch/PRODUCT_HUNT_SUBMISSION.md`
- `launch/SCREENSHOT_PLAN.md`
- `launch/OUTREACH_POSTS.md`
- `launch/GITHUB_RELEASE_NOTES.md`

All compared files matched exactly.

## Old-root dependency scan

Scanned the standalone root for legacy broader-root, integration-subtree, and receipts-subtree path references.

Result: no matches found after report cleanup.

## Conclusion

`C:\UEG_PRODUCT` is validated as a standalone product root with:

- passing tests and validation commands
- reproducible release packaging
- verified local checksums
- live GitHub release alignment
- preserved Product Hunt launch context
- no required dependency on the broader Fast Industries root
