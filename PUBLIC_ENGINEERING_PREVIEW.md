# Public dual-platform engineering release status

UEG `2.2.0-v3-candidate.2` is publicly available as an **unsigned Windows x64
and Linux amd64 engineering release**. Both platform archives are natively
qualified from one source state. It is not a signed general release.

## Canonical public locations

- Product page: https://stevenkratushniak-ctrl.github.io/UEG/
- Repository: https://github.com/stevenkratushniak-ctrl/UEG
- GitHub prerelease: https://github.com/stevenkratushniak-ctrl/UEG/releases/tag/v2.2.0-v3-candidate.2
- Exact source commit: https://github.com/stevenkratushniak-ctrl/UEG/commit/a249e9d09d76aa99a257677d34c86df648481e3a
- Support: https://github.com/stevenkratushniak-ctrl/UEG/issues
- Private security reporting: https://github.com/stevenkratushniak-ctrl/UEG/security/advisories/new

No custom domain is configured.

## Allowed claims

- Windows x64 archive SHA-256: `42daf24cabbef22c074516ca246d237866a2499340a19737ce854f37128bb179`
- Linux amd64 archive SHA-256: `d5bb3b251d1dc7035298a45e86cc869caf001114e5c4562c248709beea94c0c3`

Each exact archive passed 50 native packaged-artifact checks covering clean
extraction, identity/recovery custody, admitted execution, receipts/export,
pinned Go and packaged-Python verification, tamper refusal, restart, transfer,
suspension/resumption, recovery, and revocation.

The release is unsigned. Linux arm64, macOS, ARM, and WSL are not qualified
distribution targets. No independent review, customer outcome, support SLA,
security email, code-signing, or general-release claim is made.

## Source identity

- Source commit: `a249e9d09d76aa99a257677d34c86df648481e3a`
- Source tree: `d87cecfc0e5d07435d5e045ec0964e7d361beed1`
- Source archive SHA-256: `4df1ad857bde7954a0263b0ead7cf50d02c1228d1679b93e51d5b0520bc0be92`

`SOURCE_AUTHORITY.json` in the release records the exact relationship to the V3
candidate archive, recorded source tree, and test-fixture-only Windows repair.
