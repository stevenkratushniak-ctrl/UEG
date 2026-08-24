# Security Policy

UEG is a command decision and evidence tool, not an operating-system sandbox.
Read [LIMITS.md](LIMITS.md) before relying on it.

## Supported release

Only the newest published release would receive fixes. This reconstructed B+
tree is an unpublished engineering candidate. Local qualification is not an
independent security review or platform distribution signing.

## Reporting

Do not put private keys, credentials, private evidence, or an undisclosed
security report in a public issue. Before public distribution, the owner must
enable and publish a private vulnerability-reporting channel. Until that owner-
controlled channel exists, there is no safe public intake address to claim.

For a report, include the UEG version, platform, observed behavior, expected
behavior, and the smallest synthetic local fixture that demonstrates the issue.
Do not test against third-party systems or real customer material.

## Product boundary

UEG can refuse a command before starting it and can produce signed evidence of
what it observed. It cannot contain an admitted process, prove the host was
honest, prevent commands run outside UEG, scrub secrets from command output, or
establish a signer's real-world identity.

A B+ identity pin establishes pseudonymous continuity for one evidence ledger,
not a human, organization, device, account, legal authority, trusted time,
evidence truth, admissibility, or nonrepudiation. Offline verification proves
only the latest authentic lifecycle status independently supplied or retained;
it cannot prove that no newer revocation exists.

The encrypted recovery package is the sole recovery-root private-key container.
Keep it outside the evidence home and release archives. Recovery-root loss makes
future lifecycle control impossible. Recovery-root compromise ends trustworthy
continuity for that identity and requires a new independently pinned identity.
