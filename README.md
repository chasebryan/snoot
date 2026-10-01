![snoot](assets/banner.png)

# snoot

*Snoot out the crypto hiding in your codebase.*

snoot scans a source tree for classical public-key cryptography — RSA,
ECDSA/ECDH, DSA, DH — in API calls, key material, dependency manifests, and
TLS configs. It reports what's quantum-vulnerable, maps each finding to its
NIST post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA), and emits
machine-readable evidence: SARIF (GitHub PR annotations), CycloneDX CBOM (the
compliance artifact), and JSON.

**Status: pre-alpha, suitable for controlled evaluation.** Four detection
engines cover source code, key material, dependency manifests, and TLS
configuration, with 22 rules and eight source languages. Reports and baselines
have automated regression checks. Detection remains heuristic: a clean scan
is not proof that a repository is quantum-safe. Production release gates are
listed in [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

## Quick start

```sh
cargo install --path .   # or: cargo run --

snoot scan ./myapp
snoot scan ./myapp --format sarif --output results.sarif --fail-on high
snoot scan ./myapp --exclude 'tests/fixtures/**'   # skip known test keys
snoot rules              # list detection rules
```

## Why now: harvest now, decrypt later

Encrypted traffic can be recorded now and decrypted after a cryptographically
relevant quantum computer becomes available. Classical RSA encryption and
ECDH/DH key exchange are vulnerable to that future threat. RSA, ECDSA, DSA,
and Ed25519 signatures face future forgery risk as well. Inventorying the
cryptography in a repository helps teams plan their migration.

NIST's post-quantum standards define ML-KEM for key establishment, ML-DSA for
signatures, and SLH-DSA for signatures. Migration choices depend on the use
of a key and the protocols that consume it; a scanner finding starts that review.

## Baselines, outputs, and CI

```sh
snoot init ./myapp --output .snoot-baseline.json
snoot scan ./myapp --baseline .snoot-baseline.json --fail-on high
snoot init ./myapp --output .snoot-baseline.json --force
snoot scan ./myapp --format json --format sarif --format cbom --output reports
```

One format writes to stdout or the named output file. Multiple formats require
an output directory and produce separate `snoot.json`, `snoot.sarif`,
`snoot.cdx.json`, or `snoot.txt` files. Existing scan source files and symlink
outputs are protected from report overwrites; generated reports can be replaced.

Baselines use version 2 fingerprints relative to the scan root. Regenerate
older baselines after reviewing the findings. Moving code down a file or moving
a checkout preserves suppression. Changing a call's arguments, key material,
or relative filename reports it again. Identical calls in one file share a
baseline identity: suppression does not track their number of copies.

Exit codes are **0** for a completed scan below the requested threshold,
**2** for findings at or above `--fail-on` (also used for invalid CLI arguments),
and **3** for scan, baseline, validation, or output errors. Reports are written
before returning a findings exit code. Suppressed findings do not fail CI.

`--exclude` accepts root-relative globs (`*`, `**`, and character classes),
including bare filename patterns. `.snootignore` additionally accepts exact
paths, directory prefixes ending in `/`, and simple `*` patterns; it does not
implement gitignore negation or the full gitignore grammar. The repository
excludes deliberate key fixtures from self-scans and tests them separately.

The GitHub Action builds the revision selected by `uses: chasebryan/snoot@REF`.
It supports `path`, `fail-on`, `exclude`, `baseline`, `sarif`, and
`upload-sarif`. SARIF upload still runs when findings fail the severity gate;
input or output errors do not upload stale reports. Upload requires the
caller's `security-events: write` permission and GitHub code-scanning access.

## Development checks

Requires Rust 1.90; the tested toolchain is pinned in the checkout.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- scan . --fail-on high
python -m pip install jsonschema==4.23.0
python scripts/validate_reports.py target/debug/snoot
```

Only the development schema validator downloads schemas. Snoot scans offline.

## Pipeline

**snoot discovers → [orange](https://github.com/chasebryan/orange) verifies →
[orange-school](https://github.com/chasebryan/orange-school) teaches.**
Findings for primitives orange supports carry an `orange_note` pointing at
what orange can verify or replace.

## Honest limitations (v1)

- Heuristic detection; no data-flow analysis — a flagged call site means
  "look here", not "this is exploitable". snoot doesn't know whether a key
  protects long-lived data. Findings under test/example directories are
  demoted to medium by path convention; the path does not establish deployability.
- Can't see obfuscated code, dynamically loaded crypto libraries, or crypto
  behind FFI boundaries it has no queries for.
- Deliberate blind spots: PKCS#12 bundles, DSA private keys, and
  `ENCRYPTED PRIVATE KEY` blocks (algorithm unknowable without the
  passphrase) produce no findings rather than guesses.
- Source only: binary / container / firmware analysis is the v2 roadmap.
- Direct dependencies only; transitive analysis is out of scope for v1.
- Symmetric crypto and hashes get hygiene flags at most; v1 is about the
  quantum-vulnerable public-key surface.
- Read/traversal errors and malformed JSON/TOML dependency manifests fail the
  scan. Build/dependency directories are pruned. Unsupported, oversized (over
  4 MiB), non-UTF-8, and binary source files are skipped; supported DER key and
  certificate files are still inspected. Child symlinks are not followed.
- Secret reports redact PEM bodies and private JWK fields. Embedded escaped
  PEM strings and arbitrary nested JSON keys remain outside detection coverage.
- TLS checks are file-level heuristics. They do not resolve includes, inheritance,
  or individual virtual hosts. A configured hybrid group is not proof of negotiation.
- CBOM records known asset types and extracted private RSA sizes, and omits
  algorithm use, runtime environments, and parameters not established by evidence.
- Some source rules match names without resolving imports or types. Aliases,
  indirect calls, and generic names can create misses or false positives.
- Recall is unmeasured — see [docs/accuracy.md](docs/accuracy.md) for what
  validation does and doesn't prove.

## License

GNU AGPLv3 — see LICENSE (in the [snoot repo](https://github.com/chasebryan/snoot)).
