# Security Policy

UEG is a command decision and evidence tool, not an operating-system sandbox.
Read [LIMITS.md](LIMITS.md) before relying on it.

## Supported release

The newest public artifact is `2.2.0-v3-candidate.1`, published as an unsigned
Linux amd64 engineering preview. It is not a signed general release. Engineering
qualification is not an independent security review or platform distribution
signing.

## Reporting

Do not put private keys, credentials, private evidence, or an undisclosed
security report in a public issue. Use GitHub's private vulnerability-reporting
form:

https://github.com/stevenkratushniak-ctrl/UEG/security/advisories/new

Ordinary non-sensitive product defects belong in GitHub Issues. No security
email, response-time promise, service-level agreement, or bounty is claimed.

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
