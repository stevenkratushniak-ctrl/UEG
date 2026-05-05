# UEG Hardening Checklist (Above Apple/Microsoft)

1) Determinism
- Receipt includes a determinism hash that is stable across replays.
- Capsule (zip) output is deterministic (fixed modtime, stable ordering).
- Replay asserts: determinism hash matches + stage flow matches.

2) Truth & Auditability
- Receipt checksum detects tampering (full receipt integrity).
- Replay distinguishes: TAMPERED vs DIVERGED vs MATCH.
- Receipts are versioned; changes bump receipt version.

3) Attack Surface
- Prompt/env: explicit allowlist of internal ops; dangerous ops require --yes.
- Path resolution: canonicalize + verify executable and existence.
- No shell interpretation by default; exec.Command with argv only.

4) CI Quality Gates
- gofmt, go vet, staticcheck
- race detector
- fuzz tests for inputs (prompt/env/cli)
- golden tests for flows (expected stage sequences)

5) Release Discipline
- deterministic builds (CGO=0 where possible)
- signed checksums + SBOM + provenance (SLSA-style)
