# Supported Platforms

The release builder produces these targets. A successful cross-build is not a
native runtime qualification.

| Target | Artifact | Release requirement |
|---|---|---|
| Windows x64 | `ueg-windows-amd64.exe` and `.zip` | PASS for exact `2.2.0-v3-candidate.2` archive; unsigned |
| Linux amd64 | `ueg-linux-amd64` and `.tar.gz` | PASS for exact `2.2.0-v3-candidate.2` archive; unsigned |
| Linux arm64 | `ueg-linux-arm64` and `.tar.gz` | Deterministic cross-build plus native execution |
| macOS Intel | `ueg-darwin-amd64` and `.tar.gz` | Deterministic cross-build, native execution, and signing |
| macOS Apple Silicon | `ueg-darwin-arm64` and `.tar.gz` | Deterministic cross-build, native execution, signing, and notarization |

UEG uses operating-system-specific file locking and private-key protection.
Native qualification therefore includes first-use key permissions, concurrent
access, interruption recovery, export publication, independent verification,
update, and removal. Architecture compatibility alone is not enough.

Qualification belongs to an exact binary hash, not to a platform name or an
older release. Candidate-specific native results are retained in the candidate.2
release proof archives. They bind PASS only to the recorded Windows x64 and
Linux amd64 archive hashes; this document does not turn a cross-build or an
inherited result into a native PASS.

The Python verifier requires Python 3.11 or newer and the exact dependencies in
`requirements.lock`. It is packaged separately so verification can occur on a
machine that never held the producer's private key.
