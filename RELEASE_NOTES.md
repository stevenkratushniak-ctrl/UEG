# UEG 2.2.0-v3-candidate.1

This is an unqualified source candidate, not a release.

The prior `2.1.0-bplus` engineering qualification is not a release basis. Review testing found that Windows-spelled root paths were not recognized host-independently by the Linux policy classifier, so prohibited deletion forms could become approvable. The repaired candidate uses a new version and policy-rules version.

## Candidate changes

- host-independent lexical recognition of Windows drive, device-prefix, environment-expanded drive, and UNC roots;
- prohibited-command refusal across posture and approval combinations;
- removal of the global help/version policy bypass and support for `--` as the end of flags;
- narrower, fail-closed policy treatment for identified ambiguous or mutating commands;
- bounded stdout/stderr excerpts with complete streaming hashes and byte counts;
- execution of the exact path returned by executable resolution;
- bijective receipt/petition binding by receipt ID and petition hash;
- exact external-checkpoint receipt-boundary verification;
- portable archive-member validation in Go and Python;
- serialized monotonic checkpoint imports;
- reusable Unix/Windows file locking and serialized legacy migration;
- durable pending-marker replacement/removal and explicit evidence-write recovery.

## Qualification state

Source tests, race tests, Go vet, Python verifier tests, Go/Python cross-verification, and Windows compile-only checks must pass for the final tree. A public release additionally requires a new exact Linux amd64 package, artifact qualification, provenance, dependency inventory/SBOM, checksums, raw logs, public-claim closure, and signed release manifest.

No public download, platform claim, signing-key publication, security contact, or publication authorization is part of this source candidate.
