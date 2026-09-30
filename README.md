![snoot](assets/banner.png)

# snoot

*Snoot out the crypto hiding in your codebase.*

snoot scans a source tree for classical public-key cryptography — RSA,
ECDSA/ECDH, DSA, DH — in API calls, key material, dependency manifests, and
TLS configs. It reports what's quantum-vulnerable, maps each finding to its
NIST post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA), and emits
machine-readable evidence: SARIF (GitHub PR annotations), CycloneDX CBOM (the
compliance artifact), and JSON.

**Status: pre-alpha — week 2/3 of 6.** Tree-sitter detection is live for all six
v1 languages (Rust, Python, Go, JS/TS, Java, C/C++), with 20 rules, PEM private
key detection, classical-only TLS flagging, direct-manifest crypto deps,
baseline/`snoot init`, and a GitHub Action. Baselines are portable across
checkouts; SARIF and CycloneDX reports have schema validation in CI. Complete
key/certificate parsing and broader accuracy validation remain unfinished. See [DESIGN.md](DESIGN.md). Nothing
here has been independently reviewed. Trust is the product, so the gaps are
documented, not hidden.

## Quick start

```sh
cargo install --path .   # or: cargo run --

snoot scan ./myapp
snoot scan ./myapp --format sarif --output results.sarif --fail-on high
snoot init ./myapp       # write .snoot-baseline.json from current findings
snoot rules              # list detection rules
```

Optional `{repo}/.snootignore` excludes paths (gitignore-style). This repo
ignores `tests/fixtures/` so self-scans stay clean while the accuracy gate
still scans that tree explicitly.

Requires Rust 1.90 or later; the checkout pins the tested toolchain.

### Baselines and CI

```sh
# Review the findings, then record the accepted starting point.
snoot init ./myapp --output .snoot-baseline.json
snoot scan ./myapp --baseline .snoot-baseline.json --fail-on high

# Replace a baseline deliberately after reviewing the changes.
snoot init ./myapp --output .snoot-baseline.json --force

# Multiple formats write separate files into a directory.
snoot scan ./myapp --format sarif --format cbom --format json --output reports
```

The directory receives `snoot.sarif`, `snoot.cdx.json`, and `snoot.json`
(`snoot.txt` for console output). Multiple formats require `--output`; a
single format writes to stdout or the named output file. Existing report
files at those destinations are excluded from the scan.

Baselines contain a version and sorted fingerprints, with no source snippets
or private key payloads. Paths are relative to the scan root, so the same
source tree can move between machines. Moving code down a file preserves its
fingerprint. Changing the matched call, key body, or relative filename reports
it again. Use the same root boundary when creating and applying a baseline.
Identical matched calls in the same file share a fingerprint and are suppressed
together; baselines do not track the number of copies.

Exit codes: **0** for a completed scan below the requested threshold, **2**
for findings at or above `--fail-on` (also used by clap for invalid CLI
arguments), and **3** for scan, baseline, or output errors. Reports are written
before the findings exit code is returned. Suppressed findings do not fail CI.
Missing paths, unreadable files, and invalid baseline files fail the scan.

### Development checks

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- scan . --fail-on high

# Optional report-schema check; only this development script downloads schemas.
python -m pip install jsonschema==4.23.0
python scripts/validate_reports.py target/debug/snoot
```

The repository self-scan honors `.snootignore`, which excludes the intentional
fixture findings. The fixture tests scan those files separately. Report schema
checks use pinned official SARIF 2.1.0 and CycloneDX 1.6 schemas, with both
positive and empty reports. The scanner itself stays offline.

## Why

NIST finalized the PQC standards (FIPS 203/204/205) in August 2024. Migration
deadlines are fixed — CNSA 2.0 enforcement 2031, US federal high-value assets
2030 — and "harvest now, decrypt later" means long-lived data is exposed
*today*. Every mandate (OMB M-23-02, CNSA 2.0, UK NCSC, EU 2024/1101) leads
with the same first step: **cryptographic discovery** — inventory where your
classical crypto lives. Most organizations can't do it. snoot is the
developer-native, open-source tool for that first step.

### CNSA 2.0 → snoot mapping (cheat sheet)

| Classical find | CNSA 2.0 / NIST target | snoot rules |
|----------------|------------------------|-------------|
| RSA encrypt / key exchange | ML-KEM (FIPS 203), hybrid during transition | SNOOT001, SNOOT011, SNOOT003 |
| ECDSA / RSA signatures | ML-DSA (FIPS 204) | SNOOT002, SNOOT008 |
| ECDH / X25519 | ML-KEM hybrid (X25519MLKEM768) | SNOOT006, SNOOT005 |
| DSA / weak DH | Retire → ML-DSA / ML-KEM | SNOOT004, SNOOT007 |
| Ed25519 | Plan ML-DSA (inventory) | SNOOT014 |

## Pipeline

**snoot discovers → [orange](https://github.com/chasebryan/orange) verifies →
[orange-school](https://github.com/chasebryan/orange-school) teaches.**
Findings for primitives orange supports carry an `orange_note` pointing at
what orange can verify or replace.

## Compared to pqc-scan / pqctl / pqcanalyzer

Those tools are useful spikes; snoot aims to be the maintainer-grade,
developer-native option:

- **Rules as data** with tree-sitter AST queries (not regex-only on source)
- **Evidence formats** auditors ask for: SARIF + CycloneDX CBOM
- **CI-native**: `--fail-on`, baselines, `.snootignore`, GitHub Action
- **Honest scope**: documented gaps, fixture accuracy gate, real-world notes
  in `docs/accuracy.md`
- **orange hook**: findings point at verification/learning downstream

## Honest limitations (v1)

- Heuristic detection; no data-flow analysis yet — a flagged call site means
  "look here", not "this is exploitable".
- Source only: binary / container / firmware analysis is the v2 roadmap.
- Direct dependencies only; transitive analysis is out of scope for v1.
- Symmetric crypto and hashes get hygiene flags at most; v1 is about the
  quantum-vulnerable public-key surface.

- Existing baselines from before root-relative fingerprints must be regenerated.
  Duplicate queries at one location are collapsed; identical calls at different
  lines remain separate findings but share baseline suppression.
- Read and traversal errors fail the scan. Binary, non-UTF-8, unsupported, and
  oversized (over 4 MiB) files are skipped and counted; build/dependency
  directories and `.snootignore` matches are pruned. Symlinks are not followed.
- PEM bodies and private JWK fields are redacted from reports. JWK detection
  parses JSON objects and JWKS `keys` arrays; arbitrary nested objects, YAML,
  escaped PEM strings, and full certificate algorithms remain unsupported.
- CBOM includes extracted private-key sizes where available. Unproven algorithm
  uses, execution environments, modes, and curves are omitted or marked unknown.
- TLS and dependency findings are heuristics, not proof of active cryptography.
  Real-world observations in [docs/accuracy.md](docs/accuracy.md) still need a
  labelled accuracy assessment before release claims can be made.

## License

GNU AGPLv3 — see LICENSE (in the [snoot repo](https://github.com/chasebryan/snoot)).
