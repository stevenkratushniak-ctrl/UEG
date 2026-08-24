# UEG 2.2.0-v3-candidate.2

This prerelease is the first UEG release with separately packaged, natively
qualified downloads for both Windows x64 and Linux amd64 from one source state.
It remains an unsigned engineering release, not a signed general release.

## Downloads

- Windows x64: `ueg-2.2.0-v3-candidate.2-windows-amd64.zip`
  - SHA-256: `42daf24cabbef22c074516ca246d237866a2499340a19737ce854f37128bb179`
- Linux amd64: `ueg-2.2.0-v3-candidate.2-linux-amd64.tar.gz`
  - SHA-256: `d5bb3b251d1dc7035298a45e86cc869caf001114e5c4562c248709beea94c0c3`

Download `SHA256SUMS` from this release and verify the archive before
extracting it. Each platform archive includes native walkthrough and normal
installation/use instructions in `INSTALL.md` and `README.md`.

## Native qualification

The exact Windows and Linux archive hashes above each passed the 50-check native
packaged-artifact workflow. Retained proof covers identity and encrypted
recovery custody, command admission/execution, receipts and export, pinned Go
and independent packaged-Python verification, tamper refusal, restart,
transfer, suspension/resumption, operational-key recovery, and revocation.

The proof archives and `QUALIFICATION_REPORT.json` bind those results to the
download hashes. `SOURCE_AUTHORITY.json` records source lineage and the exact
public source commit.

## Source and limits

- Source commit: `a249e9d09d76aa99a257677d34c86df648481e3a`
- Source tree: `d87cecfc0e5d07435d5e045ec0964e7d361beed1`
- Source archive SHA-256: `4df1ad857bde7954a0263b0ead7cf50d02c1228d1679b93e51d5b0520bc0be92`

No code-signing, private review, customer outcome, support SLA, macOS, Linux
arm64, ARM, or sandbox claim is made. Support is through GitHub Issues. Use the
repository's private vulnerability-reporting door for undisclosed security
reports.
