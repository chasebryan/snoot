# Snoot release readiness

The first public release is **v0.1.0: experimental cryptography inventory**.
The GitHub Action is intended for reviewed inventory findings and severity gates.
It does not certify completeness, compliance, or quantum safety. Marketplace
availability and detection assurance are separate claims.

## Release acceptance

Before merging or tagging a release:

- Rust formatting, warnings-as-errors linting, all CLI/fixture regression tests,
  and repository self-scans pass on Linux, macOS, and Windows.
- Positive and empty SARIF 2.1.0 and CycloneDX 1.6 reports pass the pinned official
  schema validators.
- The composite action is exercised on all three operating systems, including
  expected severity failure, report outputs, baseline/exclusion suppression,
  invalid inputs, and repository-relative locations.
- The built-in SARIF upload is exercised before an expected failed gate on a
  trusted Linux CI run. Fork CI disables upload without elevating token access.
- Five native optimized archives are built, checksummed, extracted, and executed
  on their corresponding architectures. The installed CLI's version, positive
  finding gate, baseline suppression, and missing-input error are verified.
- Archive contents are limited to the executable, README, and license. A final
  collection step requires all five archives and verifies their checksums before
  the publisher can create a draft. The publisher is the only job with release
  write permission.
- Cargo version, exact semantic release tag, and reviewed release notes agree.
  Third-party workflow actions are pinned to full commit SHAs.
- README documents action inputs/outputs, permissions, runner/toolchain
  requirements, runtime support, fork handling, baselines, and detection limits.
- Security reporting, contribution guidance, community conduct, and dependency
  update configuration are included.

The scanner's correctness suite contains 83 Rust tests. The action adapter adds
seven integration tests against the actual binary. Hosted CI additionally tests
composite behavior and every installed release archive. Results must be verified
on the final release revision; checklist items alone are not evidence of a pass.

## Publishing to GitHub Marketplace

The repo is public and has one root `action.yml`, with unique intended name
**Snoot PQC Scan**, shield branding, and the documented action contract. GitHub
performs the final name and metadata validation in the release editor.

1. Merge the reviewed change after the complete CI run passes.
2. Push the exact version tag (initially `v0.1.0`) from that reviewed main commit.
   `release-draft.yml` reruns all native builds and creates a complete draft only
   after every archive passes. Never move an exact published version tag.
3. Inspect the draft's five archives, five checksum sidecars, `SHA256SUMS`, and
   reviewed release notes.
4. In GitHub's release editor, select **Publish this Action to the GitHub
   Marketplace**. Accept the Marketplace Developer Agreement as the repository
   owner if GitHub requires it. Select **Security** as the primary category and
   **Code quality** as the secondary category. Resolve any metadata errors.
5. Publish the release after GitHub reports the metadata is valid. Confirm both
   the public release and Marketplace listing, then run a consumer workflow using
   the exact public tag. No crates.io publication is required for Marketplace.

Full release tags are the supported references for the 0.x series. Publish fixes
as new exact tags. Breaking action input/output, baseline, or fingerprint changes
must be documented and given a new compatible release line; retain older tags.
A moving major alias can be introduced when a stable 1.x contract is established.

Official requirements:
[Publishing actions in GitHub Marketplace](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace).

## Remaining detection assurance work

This work limits the claims made for v0.1.0; it does not prevent publishing a
clearly scoped experimental inventory tool.

1. Measure recall against labeled production code across supported languages.
   Earlier triage of 160 findings is historical precision evidence and was not
   independently reproduced in the correctness review.
2. Expand independent review of import/type ambiguity, aliases, indirect calls,
   parser robustness, and malformed material. Generic names can misidentify uses.
3. Add TLS includes/inheritance and virtual-host scope, or retain the explicit
   file-level limitation. Static configuration does not prove negotiation.
4. Expand supported key formats: encrypted PKCS#8, DSA private keys, PKCS#12,
   escaped PEM, arbitrary nested JWKs, and unknown algorithms remain incomplete.
5. Broaden coverage for dynamically loaded libraries, FFI, and transitive
   dependencies. Unsupported/oversized files remain documented skipped inputs.

Baseline version 2 is the supported contract. Regenerate older baselines after
reviewing their findings. Every new query needs a compiling positive example,
negative fixtures, and a documented coverage contract.
