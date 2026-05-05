# Validation Report

## UEG root

Validated root:

- `C:\UEG`

Confirmed project locations:

- `README.md`
- `go.mod`
- `cmd/ueg/main.go`
- `cmd/ueg/ueg_test.go`
- `cmd/ueg/fuzz_test.go`
- `scripts/`
- `docs/`
- `examples/`
- `dist/`
- `launch/`

## Commands run

Formatting:

```powershell
gofmt -w .\cmd\ueg\main.go .\cmd\ueg\ueg_test.go .\cmd\ueg\fuzz_test.go
```

Test suite:

```powershell
go test ./...
```

Static analysis:

```powershell
go vet ./...
```

State-model validation:

```powershell
go run ./cmd/ueg --validate
```

Fuzz targets:

```powershell
go test ./cmd/ueg -run=^$ -fuzz=FuzzDeterminismHash_NoPanic$ -fuzztime=3s
go test ./cmd/ueg -run=^$ -fuzz=FuzzReadReceiptFromCapsule_NoPanic$ -fuzztime=3s
```

Release build:

```powershell
pwsh -File .\scripts\build-release.ps1
```

Windows demo validation:

```powershell
go run C:\UEG\cmd\ueg --validate
go run C:\UEG\cmd\ueg --receipt .\demo-receipt.json cmd /c echo hello-from-ueg
go run C:\UEG\cmd\ueg --replay .\demo-receipt.json
go run C:\UEG\cmd\ueg --replay .\demo-receipt-tampered.json
```

Windows release-binary smoke test:

```powershell
Expand-Archive .\dist\ueg-v1.2.0-windows-amd64.zip -DestinationPath .\launch\_windows_release_smoke -Force
.\launch\_windows_release_smoke\ueg.exe --validate
```

Repository initialization:

```powershell
git init -b main
```

## Results

- `gofmt` completed successfully
- `go test ./...` passed
- `go vet ./...` passed
- `go run ./cmd/ueg --validate` returned `valid: true`
- `FuzzDeterminismHash_NoPanic` passed for a 3-second fuzz run
- `FuzzReadReceiptFromCapsule_NoPanic` passed for a 3-second fuzz run
- `build-release.ps1` completed successfully
- Windows demo flow worked end to end
- Tampered receipt replay reported `REPLAY: RECEIPT TAMPERED (checksum mismatch)`
- Extracted Windows release binary ran `--validate` successfully

## Release files found

Found in `dist/`:

- `ueg-v1.2.0-windows-amd64.zip`
- `ueg-v1.2.0-linux-amd64.zip`
- `ueg-v1.2.0-darwin-amd64.zip`
- `ueg-v1.2.0-darwin-arm64.zip`
- `checksums.txt`

Checksums file:

- `C:\UEG\dist\checksums.txt`

Current checksum contents:

```text
06dea9dfa21d315670717d60095a3a3ebb8fa5a63a59a4352afe9a0c52774331  ueg-v1.2.0-darwin-amd64.zip
1229865fcb648aa174d8efbc2116851c95153345bbb4c8efef0485ef1010b03e  ueg-v1.2.0-darwin-arm64.zip
e825989c25a7402d0f472ac6a8043e97f1038b80bc5df944b3276630cf13cd6d  ueg-v1.2.0-linux-amd64.zip
9af3fed4d2f5a4b700e73d9768ccb726c6088e578bbcac3839a30e0827ab648d  ueg-v1.2.0-windows-amd64.zip
```

## Files created or modified

Created or updated for launch packaging:

- `README.md`
- `examples/quick_demo.md`
- `docs/STATE_TAXONOMY_v1.0.md`
- `taxonomy/states.json`
- `launch/PRODUCT_HUNT_SUBMISSION.md`
- `launch/LANDING_PAGE_COPY.md`
- `launch/GITHUB_RELEASE_NOTES.md`
- `launch/DEMO_SCRIPT.md`
- `launch/OUTREACH_POSTS.md`
- `launch/SCREENSHOT_PLAN.md`
- `launch/PRICING_AND_OFFER.md`
- `launch/FINAL_LAUNCH_CHECKLIST.md`
- `launch/VALIDATION_REPORT.md`
- `launch/landing-page.html`

Validated release output:

- `dist/ueg-v1.2.0-windows-amd64.zip`
- `dist/ueg-v1.2.0-linux-amd64.zip`
- `dist/ueg-v1.2.0-darwin-amd64.zip`
- `dist/ueg-v1.2.0-darwin-arm64.zip`
- `dist/checksums.txt`

## Standalone-root check

Searches for old workspace and user-path references returned no matches for:

- `FastFactory`
- `Fast Industries`
- `Downloads`
- `C:\Users\steve`
- `Semantic_CUTOVER`

## Unresolved issues

- Public launch copy can describe this as the first public launch, but the current binaries identify themselves as `v1.2.0`. The GitHub release tag should match `v1.2.0` unless you intentionally change the core version and rebuild.
- The Bash demo commands were authored for launch materials, but only the Windows flow was executed on this Windows host.
