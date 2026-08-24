# UEG Source Provenance

This source line is a reconstructed and reviewed UEG v2 candidate extended with
new B+ Authenticated Evidence Epochs work. It is not an untouched
original-source release, and B+ code is not claimed as original Devin source.

## Supplied authority

The supplied archive is `ueg-v2.tar.gz`, SHA-256:

`7c0f38142382dbe1f9fb22faea710d289588b958e311288e8c3a7c8a812d21cf`

The archive does not contain `internal/keys`, but these supplied production
files import `github.com/stevenkratushniak-ctrl/ueg/internal/keys`:

- `internal/bundle/bundle.go`
- `internal/bundle/verify.go`
- `internal/ledger/ledger.go`

The supplied source therefore cannot compile by itself. The immutable archive
remains the evidence of what was supplied; it was not edited to conceal this
gap.

## Reconstruction baseline

The frozen pre-repair candidate's non-cache source/release manifest has
SHA-256:

`f36bb4bb4aceea37e0dd3bd60289569742da1833fb14f8bc20053162913e54cf`

Its `internal/keys/keys.go` has SHA-256:

`4812d72f85d53d63719353848fa5b9c7e62e62cb73b0732209aeea117ee8bf04`

That file was newly authored during the 2026-08-18 reconstruction so the
incomplete archive could compile. No source in the supplied archive, no
independently identified local original repository, and no proven public commit
establishes it as Devin-original work. Its authorship is recorded as newly
reconstructed code produced by OpenAI Codex under the product owner's direction
and then reviewed and hardened in this repair line.

## Production-file lineage

| Path | In supplied archive | Repair-line origin |
|---|---:|---|
| `cmd/ueg/main.go` | yes | Supplied CLI, previously hardened, then changed here only for truthful trust-verdict input/output. |
| `internal/bundle/bundle.go` | yes | Supplied bundle builder, changed here for complete key ids, v2 manifests, and legacy-ledger export compatibility. |
| `internal/bundle/verify.go` | yes | Supplied verifier, substantially repaired here for strict parsing, revocations, key binding, seal validation, and external trust pins. |
| `internal/ledger/ledger.go` | yes | Supplied ledger, changed here to emit complete key ids, retain legacy verification aliases, and strictly parse stored petitions. |
| `internal/policy/policy.go` | yes | Supplied classifier, previously hardened for prohibited observe behavior, then changed here for generic Windows executable and root normalization. |
| `verifier/ed25519.py` | yes | Supplied Python key wrapper, changed here to derive and validate canonical key fingerprints. |
| `verifier/reality_verify.py` | yes | Supplied independent verifier, repaired here to match strict parsing, revocation, identity-binding, and trust-verdict rules. |
| `internal/keys/keys.go` | no | Newly reconstructed before this repair; reviewed and hardened here. No proven original-source counterpart exists. |
| `internal/keys/permissions_other.go` | no | Newly authored in this repair for enforced POSIX private-key permissions. |
| `internal/keys/permissions_windows.go` | no | Newly authored in this repair for protected owner-and-LocalSystem Windows DACLs and post-write verification. |
| `internal/strictjson/strictjson.go` | no | Newly authored in this repair as the shared Go security JSON decoder. |

## B+ source authority

The B+ branch starts from frozen qualified-parent commit
`479e4948ba590cb019d11c0fa5e87e23dc584387`. The parent commit and its evidence
remain unchanged. B+ changes the runtime, identity, bundle, and verifier trust
model and therefore requires its own qualification evidence; prior v2 evidence
is not relabeled as B+ proof.

The following production paths are newly authored B+ work under owner
authorization, not recovered original-source files:

| Path | Origin and purpose |
|---|---|
| `cmd/ueg/identity.go` | New B+ lifecycle CLI, explicit initialization, public artifacts, migration, and transaction recovery. |
| `internal/identity/types.go` | New versioned B+ authority, epoch, recovery, anchor, and checkpoint types. |
| `internal/identity/crypto.go` | New domain-separated canonical signing and digest rules. |
| `internal/identity/recovery.go` | New Argon2id/AES-256-GCM encrypted recovery-package implementation. |
| `internal/identity/storage.go` | New strict B+ home storage and loading implementation. |
| `internal/identity/initialization.go` | New journaled initialization recovery state machine. |
| `internal/identity/lifecycle.go` | New genesis and lifecycle validation/state derivation. |
| `internal/identity/transaction.go` | New journaled lifecycle-mutation state machine. |
| `internal/identity/migration.go` | New explicit one-way legacy enrollment and migration recovery. |
| `internal/identity/artifacts.go` | New public identity card, evidence anchor, checkpoint, and retained-state logic. |
| `internal/identity/replace_*.go` and `publish_new_*.go` | New platform-specific durable replacement and no-overwrite publication helpers. |
| `internal/bundle/bplus.go` and `internal/bundle/verify_bplus.go` | New version-distinct B+ bundle construction and Go verification. |
| `verifier/bplus_verify.py` | New independently implemented Python B+ authority and trust verification. |
| `internal/keys/private_file_*.go` | New platform-specific protected exclusive private-file creation. |

Existing `cmd/ueg/main.go`, gateway replay, ledger, bundle, verifier dispatch,
release tooling, schemas, documentation, and tests were changed only where
needed to integrate and qualify B+ while preserving legacy verification.

The new direct Go dependencies are the pinned `golang.org/x/crypto`,
`golang.org/x/sys`, and `golang.org/x/term` modules recorded in `go.mod`,
`go.sum`, the SPDX SBOM, and `THIRD_PARTY_NOTICES.md`.

The full supplied-archive-to-frozen-baseline no-index diff, immutable tree
manifests, repair commit diff, and file-by-file SHA-256 manifests belong in the
external `RELEASE_EVIDENCE` package. Build artifacts and audit receipts are not
source authority and are not copied into this repository as if they were
original source.
