# Reproducing a UEG Release Build

The release builder is deterministic for one committed source tree and one
recorded toolchain. Reproduction means using the exact source commit, Go
version, Python version, and build arguments recorded in
`BUILD_PROVENANCE.json`; a different compiler or compression library can emit
different bytes even when program behavior is equivalent.

## Prerequisites

- Git with the complete candidate commit available locally;
- the exact Go toolchain recorded in build provenance;
- the exact Python major/minor version recorded in build provenance;
- no source-tree changes or untracked files;
- no signing credentials. Candidate archives are unsigned until the owner
  completes platform signing outside this build.

## Build

From a clean checkout:

```text
python tools/build_release.py --version 2.2.0-v3-candidate.1 --output <new-empty-path>
python tools/verify_release.py <new-output-path>
```

The output path must not exist. The builder uses the commit timestamp as
`SOURCE_DATE_EPOCH`, strips local source paths and VCS stamping from Go
binaries, clears the Go build id, normalizes archive ownership, modes, names,
ordering, and timestamps, and refuses a dirty tree. A failed build is preserved
under a `.failed` path with its compiler logs; successful public assets contain
no build logs.

## Compare two independent checkouts

Build into two different output paths from two clean checkouts of the same
commit. Verify both, then compare `SHA256SUMS` byte for byte. Every listed
artifact must match. `BUILD_PROVENANCE.json` must also match and name the same
commit and toolchain.

Native execution is a separate gate. Matching cross-built macOS or Linux ARM64
bytes do not substitute for the native qualification kit and returned evidence.
