# UEG Publication Context

## Public identity

- Product: `UEG`
- Tagline: `Run commands. Prove what happened.`
- Repo: `https://github.com/stevenkratushniak-ctrl/UEG`
- Release: `https://github.com/stevenkratushniak-ctrl/UEG/releases/tag/v1.2.0`
- Release tag: `v1.2.0`

## Release assets preserved and aligned

The standalone root contains the same release asset names as the live public release:

- `dist/checksums.txt`
- `dist/ueg-v1.2.0-darwin-amd64.zip`
- `dist/ueg-v1.2.0-darwin-arm64.zip`
- `dist/ueg-v1.2.0-linux-amd64.zip`
- `dist/ueg-v1.2.0-windows-amd64.zip`

The packaging flow in this root is deterministic, and the live release assets were refreshed to match the new stable local checksums.

## Product Hunt context preserved

Preserved source materials:

- `launch/PRODUCT_HUNT_SUBMISSION.md`
- `launch/SCREENSHOT_PLAN.md`
- `launch/OUTREACH_POSTS.md`
- `launch/GITHUB_RELEASE_NOTES.md`
- `launch/LANDING_PAGE_COPY.md`
- `launch/landing-page.html`
- `launch/PRICING_AND_OFFER.md`
- `launch/DEMO_SCRIPT.md`

Current Product Hunt publication state:

- Launch copy is preserved and unchanged.
- Screenshot and GIF requirements are preserved as a plan, not generated assets.
- The product remains ready for manual browser submission using the preserved packet and screenshot plan.

## Operator evidence retained separately

Original operator evidence remains outside the product source under launch receipt run IDs:

- `011758fb326c`
- `b5b62da3002e`

These IDs are preserved here for audit continuity without making the product root depend on external operator directories.

## Standalone publication posture

`C:\UEG_PRODUCT` is now the authoritative standalone release root for:

- source
- docs
- examples
- taxonomy
- release archives
- checksums
- launch packet
- packaging scripts
- standalone validation reports

No step in the local build, validation, or release packaging flow requires the broader Fast Industries root.
