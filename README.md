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
baseline/`snoot init`, and a GitHub Action. Full ASN.1/JWK parsing and
lockfile/transitive analysis are next. See [DESIGN.md](DESIGN.md). Nothing
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

## License

GNU AGPLv3 — see LICENSE (in the [snoot repo](https://github.com/chasebryan/snoot)).
