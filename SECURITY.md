# Security

Security fixes target the newest public Snoot release. The first release is
0.1.0. Use its exact tag or full commit SHA; `main` is development code.

Report a vulnerability privately using **Report a vulnerability** on the
repository's [Security page](https://github.com/chasebryan/snoot/security).
Include the affected version, expected behavior, and a minimal synthetic input.
Do not post real private keys, credentials, proprietary source, or customer data.
If private reporting is unavailable, open an issue asking for a private channel
without disclosing vulnerability details.

Snoot reads repository files and emits evidence. Treat findings and reports as
repository data: SARIF can contain filenames and source snippets. The action's
optional SARIF upload sends this evidence to GitHub code scanning. Supported
private PEM/JWK material is redacted, but Snoot is not a general secret scrubber.
Do not use its reports as a safe way to publish arbitrary confidential inputs.

The action compiles the selected source revision using a pinned Rust toolchain
and locked dependencies. Upload integrations are pinned to commit SHAs. No scan
input is executed by Snoot. Baselines represent accepted findings, so review
baseline changes as carefully as changes to severity gates or exclusions.

Read errors, malformed supported manifests, invalid baselines, and report failures
must fail scanning. Unsupported inputs are explicitly limited in the README; a
clean scan must not be represented as proof of completeness or quantum safety.
