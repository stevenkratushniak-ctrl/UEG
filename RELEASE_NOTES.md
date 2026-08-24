# UEG 2.2.0-v3-candidate.1

This exact candidate is publicly downloadable as an **unsigned Linux amd64
engineering preview**. It is not a signed or generally qualified release.

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

The exact Linux amd64 platform archive passed the supplied native Ubuntu 24.04.3
x86_64 qualification walkthrough. Source tests, race tests, Go vet, Python
verifier tests, Go/Python cross-verification, deterministic rebuilds, packaging,
policy, output capture, and Windows compile-only checks are recorded in the
candidate evidence. Fresh Fast Launch validation on 2026-08-24 also passed run,
replay, export, pinned Go verification, independent Python verification,
prohibited refusal, and tamper rejection under WSL2 Ubuntu 24.04.3 using a
persistent Linux home. WSL is not a qualified distribution target.

The release manifest remains unsigned. Windows has no runtime qualification or
download. Linux arm64 and macOS are not qualified. No independent review,
customer outcome, support SLA, security email, or signing-key claim is made.
