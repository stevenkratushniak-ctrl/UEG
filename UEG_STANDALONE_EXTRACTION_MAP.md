# UEG Standalone Extraction Map

## Source and target

- Source root: pre-extraction UEG product tree
- Standalone root: `C:\UEG_PRODUCT`
- Backup snapshot: `C:\UEG_EXTRACTION_BACKUP_20260512_162417`

## Migrated into the standalone root

- `.git`
- `.gitignore`
- `README.md`
- `go.mod`
- `cmd/`
- `dist/`
- `docs/`
- `examples/`
- `launch/`
- `scripts/`
- `taxonomy/`
- `UEG_PUBLIC_LAUNCH_PACKAGE/`
- `UEG_PUBLIC_LAUNCH_PACKAGE.zip`

## Normalized during extraction

- `launch/FINAL_LAUNCH_CHECKLIST.md`
  Updated operator path references to the standalone root.
- `launch/PUBLICATION_OPERATOR_GUIDE.md`
  Updated operator path references to the standalone root.
- `UEG_PUBLIC_LAUNCH_PACKAGE/launch/FINAL_LAUNCH_CHECKLIST.md`
  Updated bundled operator path references to the standalone root.
- `scripts/build-release.ps1`
  Replaced non-deterministic ZIP packaging with deterministic archive creation so repeated builds produce stable `dist/` checksums.

## Product artifacts kept inside the standalone root

- Go source and tests in `cmd/ueg/`
- Cross-platform release assets and `checksums.txt` in `dist/`
- Product docs and taxonomy references in `docs/` and `taxonomy/`
- Quick demo and runnable examples in `examples/`
- Launch copy, release notes, outreach, pricing, landing page, and Product Hunt packet in `launch/`
- Rebuild and smoke-test scripts in `scripts/`
- Previously assembled public launch bundle in `UEG_PUBLIC_LAUNCH_PACKAGE/` and `UEG_PUBLIC_LAUNCH_PACKAGE.zip`

## External operational evidence intentionally retained outside the standalone root

- Launch receipt run `011758fb326c`
  Initial standalone packaging and publication preparation evidence.
- Launch receipt run `b5b62da3002e`
  GitHub release publication and Product Hunt readiness evidence.

These receipts remain external because they are operator evidence, not product source. Their publication facts are preserved in the standalone root through `UEG_RELEASE_ROOT_AUTHORITY.json`, `UEG_PUBLICATION_CONTEXT.md`, and `UEG_STANDALONE_VALIDATION_REPORT.md`.

## Historical documents intentionally left unchanged

- `launch/VALIDATION_REPORT.md`
- `UEG_PUBLIC_LAUNCH_PACKAGE/launch/VALIDATION_REPORT.md`

These are preserved as historical launch artifacts from the original extraction root. The authoritative standalone validation record is `UEG_STANDALONE_VALIDATION_REPORT.md`.
