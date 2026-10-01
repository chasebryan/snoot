# Snoot readiness and release checklist

Assessment date: 2026-09-30. **Suitable for a controlled pre-alpha evaluation;
not ready to certify inventory completeness or claim production readiness.**

The review integrates the newer 22-rule implementation on main with the
reliability work in PRs #1 and #2. Main's newer rule IDs and detectors are
preserved. The older branches are included in the integration history.

## Repaired before merge

- Missing RSA/EC DER fixtures and CI workflows are restored and committed.
- Missing/unreadable scan inputs, bad baselines, malformed structured manifests,
  and output failures return errors instead of successful clean reports.
- Reads are bounded before allocation; supported binary DER continues to reach
  the secrets engine. Child symlinks and build/dependency trees are skipped.
- Baselines use version 2, root-relative identities, full call arguments, and
  complete private material before redaction. They survive line shifts, moved
  checkouts, and reordered JWKS. Identical calls share suppression identity.
- Distinct call locations are retained, including multiple calls on one line.
- C++ inherits applicable C queries; MTS/CTS/TSX work; common Python RSA and
  NodeRSA constructors are restored without replacing newer constrained queries.
- TLS exclusions and inline comments no longer enable weak ciphers or hybrid
  groups. Hybrid tokens must occur in group-related directives.
- Cargo dependency aliases, target sections, compact Maven entries, and Gradle
  comment/non-dependency noise are handled. Unsupported Ruby/PHP manifest names
  are removed from the dispatch list.
- DER algorithms are read from AlgorithmIdentifier positions, not arbitrary key
  bytes. Correct P-384/P-521 OIDs and extracted RSA sizes feed the inventory.
- Separate reports, escaped SARIF paths, valid CycloneDX asset types/primitives,
  unique component references, and atomic writes replace invalid or partial output.
- Report writes protect existing source files and symlink destinations. Baseline
  replacement requires explicit `--force`.
- The reusable action builds the selected revision, passes inputs as environment
  variables, supports exclusions/baselines, and uploads findings even when their
  severity fails the job. Failed scans do not upload stale reports.
- README, design status, and rule text remove unsupported safety/readiness claims.
  Inventory-only severity does not imply that Ed25519 or public keys are quantum-safe.

## Verification

Local macOS ARM64 checks:

- 83 tests: 56 unit/fixture tests, 20 CLI reliability tests, 7 smoke tests.
- Formatting and all-target warnings-as-errors lint checks pass.
- Real positive and empty reports validate against pinned official SARIF 2.1.0
  and CycloneDX 1.6 schemas.
- Repository self-scan passes its severity gate with deliberate fixtures excluded.
- Native optimized build, package verification (including the missing fixtures),
  and documentation with warnings treated as errors pass.

CI also runs tests/lints/formatting on Linux, macOS, and Windows, plus official
schema validation and a reusable-action/code-scanning smoke test. Hosted results
must pass on the integrated revision before merging.

On this machine the default macOS 27 SDK is incompatible with the installed
linker; local compilation uses the already installed macOS 15.4 SDK. This is a
local tooling condition, not a product workaround committed into the build.

## Production release gates

1. Measure recall against a labeled corpus of production application code across
   supported languages. Earlier reported triage of 160 findings is historical
   precision evidence and was not independently reproduced in this review.
2. Independently review import/type ambiguity, aliases, indirect calls, malformed
   material, and parser robustness. Generic names can still misidentify algorithms.
3. Validate TLS inheritance/includes and mixed virtual hosts or keep file-level
   inference explicitly limited. Static configuration does not prove negotiation.
4. Define the supported material contract: encrypted PKCS#8, DSA private keys,
   PKCS#12, escaped PEM strings, nested JWK objects, and unknown algorithms remain
   incomplete. Preserve explicit limitations until support is tested.
5. Exercise the five-target release workflow and inspect/install every archive.
   Native compilation and three-platform test CI do not validate cross-built
   release archives. The workflow creates a draft prerelease; no tag is pushed
   and no package or public release is published by this review.

## Publishing after those gates

The fixtures and workflows are in Git; the previous web-upload instructions are
obsolete. Rust 1.90 is pinned. Publishing remains a deliberate maintainer action.

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all --check
cargo publish --dry-run --locked
# Authenticate with crates.io, then publish only after the release gates pass.
cargo publish --locked
```

Choose and tag the reviewed version to trigger the five-platform draft prerelease.
Inspect its artifacts and checksums, smoke-test installs, and review release
notes before publication. Regenerate version-1 baselines after reviewing findings.
