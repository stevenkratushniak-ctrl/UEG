# Native Release Qualification Kit

Use this kit on a clean native machine with a release archive but no UEG source
tree, identity, or evidence home. It standardizes raw evidence for an operator
walkthrough; it is not a substitute for owner or independent-user review.

Requirements:

- Python 3.11 or newer;
- one platform UEG release archive (preferred) or raw binary;
- its expected SHA-256 from the candidate release manifest;
- optionally, the packaged Python verifier ZIP and its expected SHA-256.

Run the script from a disposable directory and select a new output path:

```text
python native_release_walkthrough.py --artifact <archive> --expected-sha256 <hash> --python-verifier <zip> --expected-python-verifier-sha256 <hash> --output <new-directory>
```

The workflow uses synthetic local state only. It checks acquisition and package
contents, inert Help/error behavior, explicit initialization, encrypted
recovery-package verification, inert policy check, normal execution, harmless
prohibited refusal, restart, export, move, tamper rejection, Go and optional
packaged-Python verification, official transfer, historical verification,
suspension/resumption, operational-key recovery, multi-epoch indeterminate
trust, independently anchored pre-compromise trust, permanent revocation,
offline freshness limits, executable removal, and deliberate cleanup.

The output directory must not exist. The harness preserves public synthetic
bundles, pins, checkpoints, logs, before/after manifests, result JSON, and
`SHA256SUMS`. It never copies a recovery package or operational private key into
the evidence output.

Return the complete directory without editing it. A pass proves only the listed
behaviors on that native host and exact artifact hash. It does not prove native
behavior on another platform, platform signing/notarization, hosted status,
independent security assessment, or owner acceptance.
