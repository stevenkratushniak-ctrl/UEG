# UEG Independent Python Verifier

This package verifies an exported UEG bundle without a UEG source checkout,
the evidence-producing host, or any private key. It supports legacy v1/v2 and
version-distinct B+ evidence.

Use Python 3.11 or newer and an isolated environment:

```text
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock
.venv\Scripts\python -m verifier.reality_verify --help
```

On Linux or macOS, use `.venv/bin/python` in place of
`.venv\Scripts\python`.

## Legacy evidence

```text
python -m verifier.reality_verify --expected-key-id <PINNED_COMPLETE_FINGERPRINT> evidence.tar.gz
```

The expected key id must come from a channel independent of the bundle. Without
it, an internally consistent legacy bundle is not an externally anchored
identity claim.

## B+ evidence

```text
python -m verifier.reality_verify \
  --expected-identity-id <PINNED_GENESIS_ID> \
  --checkpoint lifecycle-checkpoint.json \
  evidence.tar.gz
```

The identity pin and checkpoint must be retained or supplied independently of
the bundle for a `VERIFIED` result. Add `--anchor` when evaluating evidence
against an independently retained known-good ledger anchor. A matching anchor
covers only its exact ledger boundary and operational epoch.

`--trust-store` selects a previously imported monotonic checkpoint instead of a
checkpoint file. `--minimum-checkpoint-sequence` plus
`--minimum-checkpoint-digest` rejects an older status. `--require-current-status`
exits nonzero with `TRUST_INDETERMINATE` because a clean offline verifier cannot
prove that no newer revocation exists.

JSON output reports these fields independently:

```text
SIGNATURE
BUNDLE_LEDGER_INTEGRITY
IDENTITY_CONTINUITY
LIFECYCLE_CHAIN
SIGNING_KEY_STATUS
EPOCH_AUTHORIZATION
EVIDENCE_ANCHOR
CHECKPOINT_AUTHENTICITY
CHECKPOINT_SOURCE
CHECKPOINT_SEQUENCE
CHECKPOINT_FRESHNESS
EVIDENCE_TIME_ASSURANCE
OVERALL_TRUST
```

Overall B+ results are `VERIFIED`, `TRUST_INDETERMINATE`, `NOT_TRUSTED`, or
`INVALID`. Cryptographic signature validity is never presented as full trust
when identity, lifecycle authority, epoch status, anchor coverage, or requested
freshness is missing.

An Evidence Identity represents pseudonymous continuity for one ledger. It
does not establish a human, organization, device, legal authority, evidence
truth, trusted time, admissibility, or nonrepudiation.

Bundles contain command arguments and bounded output excerpts. UEG does not
scrub secrets from those fields. Inspect evidence before sharing it and use a
transfer channel suitable for its contents.
