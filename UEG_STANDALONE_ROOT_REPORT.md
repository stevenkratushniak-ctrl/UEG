# UEG Standalone Root Report

## Status

UEG now operates as a standalone product root from `C:\UEG_PRODUCT`.

- Runtime dependency on the broader Fast Industries root: none required
- Release packaging dependency on the broader Fast Industries root: none required
- GitHub publication context preserved: yes
- Product Hunt launch context preserved: yes
- Reproducible packaging flow present in this root: yes

## Root authority

- Product: `UEG`
- Tagline: `Run commands. Prove what happened.`
- Git remote: `https://github.com/stevenkratushniak-ctrl/UEG.git`
- Branch: `main`
- Commit: `0b6b4792687204151799986c96510357c52b5153`
- Public repo: `https://github.com/stevenkratushniak-ctrl/UEG`
- Public release: `https://github.com/stevenkratushniak-ctrl/UEG/releases/tag/v1.2.0`

## Standalone root layout

- `cmd/ueg/`
  CLI entrypoint, tests, and fuzz corpus.
- `dist/`
  Cross-platform release ZIPs and `checksums.txt`.
- `docs/`
  Product docs and taxonomy references.
- `examples/`
  Quick demo and replay/tamper path.
- `launch/`
  Product Hunt packet, release notes, outreach copy, landing page, pricing, validation history, and operator guide.
- `scripts/`
  Smoke test and deterministic release packaging.
- `taxonomy/`
  Machine-readable state assets.
- `UEG_PUBLIC_LAUNCH_PACKAGE/`
  Previously assembled launch bundle preserved inside the product root.

## Dependency scan result

The standalone root was scanned for legacy broader-root, integration-subtree, and receipts-subtree path references.

Result: no matches found outside earlier drafts of this report, which were then removed.

## Intentionally retained legacy references

The only preserved legacy root references are mentions inside historical validation documents:

- `launch/VALIDATION_REPORT.md`
- `UEG_PUBLIC_LAUNCH_PACKAGE/launch/VALIDATION_REPORT.md`

These are historical records, not current instructions. The current standalone instructions now point to `C:\UEG_PRODUCT`.

## Release alignment

- Local `dist/` asset names match the live `v1.2.0` GitHub release asset names.
- Local `dist/checksums.txt` matches the live release asset digests after the deterministic republish.
- The release packager now yields identical `checksums.txt` across repeated runs from this standalone root.

## Publication context preserved

- Product Hunt source packet preserved at `launch/PRODUCT_HUNT_SUBMISSION.md`
- Screenshot plan preserved at `launch/SCREENSHOT_PLAN.md`
- Outreach copy preserved at `launch/OUTREACH_POSTS.md`
- Release notes preserved at `launch/GITHUB_RELEASE_NOTES.md`
- Landing page starter preserved at `launch/landing-page.html`

## External evidence

Original launch operator evidence remains external to this root under receipt run IDs:

- `011758fb326c`
- `b5b62da3002e`

Those facts have been summarized into standalone product artifacts rather than copied wholesale into the source tree.
