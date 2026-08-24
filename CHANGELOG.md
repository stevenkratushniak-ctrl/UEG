# Changelog

All notable changes to the reconstructed UEG v2 source line are recorded here.

## [Unreleased]

### Added

- Host-independent Windows-root parsing, bounded output capture, exact
  receipt/petition binding, external-checkpoint receipt-boundary checks,
  portable archive-member validation, serialized checkpoint import and
  migration, and explicit interrupted evidence-write recovery.
- B+ Authenticated Evidence Epochs with a stable genesis-derived identity id,
  exactly one active operational key, and recovery-root-authenticated lifecycle
  records.
- Explicit initialization, legacy migration, status, recovery-package
  verification, rotation, official transfer, suspension, resumption, lost-key
  recovery, permanent revocation, and transaction recovery.
- Public identity cards, evidence anchors, lifecycle checkpoints, retained
  checkpoint rollback/fork protection, and stale-clone blocking when newer
  authenticated state is available.
- Version-distinct B+ bundles and matching Go/Python trust verdicts while
  preserving legacy v1/v2 verification.
- Journaled initialization, migration, and lifecycle mutations with durable
  atomic publication and interruption recovery.
- B+ JSON Schemas, dependency inventory updates, release-package integration,
  and native clean-machine qualification workflows.

### Changed

- Stateful use now requires `ueg identity init`; Help, version, check, refusal,
  parse errors, inspection, and verification are inert.
- B+ trust requires an independently obtained identity pin and lifecycle
  checkpoint. Offline current-status freshness remains explicitly
  indeterminate.
- Source candidate version advanced to `2.2.0-v3-candidate.1`; policy rules
  advanced to version 2. The previous `2.1.0-bplus` candidate remains
  unqualified.

### Security

- Recovery packages use Argon2id plus AES-256-GCM and are created only at an
  explicit external destination after restore/sign self-verification.
- Public outputs and identity homes are no-overwrite; private files are created
  with platform protection before secret bytes are written.
- Lifecycle parsers reject ambiguous, oversized, replayed, skipped, duplicated,
  conflicting, forked, and unauthorized records.

## [2.0.0] - Unpublished candidate

### Reconstructed source

- Reconstructed the missing `internal/keys` package whose imports existed in
  the supplied archive, then hardened key parsing and platform permissions.
- Enforced `PROHIBITED` refusal in every posture and approval combination.
- Added strict Go and Python verification, full key fingerprints, external pin
  handling, malformed-evidence rejection, atomic export, serialized evidence
  writes, interrupted-write recovery, and inert Help/error paths.
- Preserved the exact reconstruction provenance in `PROVENANCE.md`.
