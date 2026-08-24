# Public engineering preview status

UEG `2.2.0-v3-candidate.1` is publicly available as an **unsigned Linux amd64 engineering preview**. It is not a signed or generally qualified release.

## Canonical public locations

- Product page: https://stevenkratushniak-ctrl.github.io/UEG/
- Repository: https://github.com/stevenkratushniak-ctrl/UEG
- GitHub prerelease: https://github.com/stevenkratushniak-ctrl/UEG/releases/tag/v2.2.0-v3-candidate.1
- Support: https://github.com/stevenkratushniak-ctrl/UEG/issues
- Private security reporting: https://github.com/stevenkratushniak-ctrl/UEG/security/advisories/new

No custom domain is configured.

## Allowed claim

The exact Linux amd64 platform archive with SHA-256 `0fe3378528a559c832d2c6201369e9ae669cb842e3ee0be12d8e344734959d35` passed the supplied native Ubuntu 24.04.3 x86_64 engineering walkthrough. Fresh 2026-08-24 validation also passed under WSL2 Ubuntu 24.04.3 from a persistent Linux home. WSL is not itself a qualified distribution target.

Windows amd64 has compile-only evidence. Linux arm64 and macOS are not qualified. The release manifest is unsigned, and no independent review, customer outcome, support SLA, or general-release claim is made.

## Source identity

- Candidate source commit recorded by build provenance: `bce0b9658853db3fb3fc8cef2e743d9d7587e5ed`
- Candidate source tree: `844c36bf0eff1bd621cd867af3d1b5dba165fcc9`
- Exact source archive SHA-256: `9c7e4fb79fe50b3d215e4425758c32acb8d944349c84c8c99184e2aac2de8299`

The public repository commit contains the candidate source snapshot plus public-status documentation. The exact source archive remains the byte authority for the candidate build.
