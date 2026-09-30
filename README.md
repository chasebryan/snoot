# snoot

*Snoot out the crypto hiding in your codebase.*

snoot scans a source tree for classical public-key cryptography — RSA,
ECDSA/ECDH, DSA, DH — in API calls, key material, dependency manifests, and
TLS configs. It reports what's quantum-vulnerable, maps each finding to its
NIST post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA), and emits
machine-readable evidence: SARIF (GitHub PR annotations), CycloneDX CBOM (the
compliance artifact), and JSON.

**Status: pre-alpha — week 1 of 6.** The crate skeleton, CLI, data model, and
first five rules are in. The detection engines are wired but stubbed; see
[DESIGN.md](DESIGN.md) for the six-week plan. Nothing here has been
independently reviewed, and week-1 snoot will cheerfully report zero findings
on code it can't yet read. Trust is the product, so the gaps are documented,
not hidden.

## Quick start

```sh
cargo install --path .   # or: cargo run --

snoot scan ./myapp
snoot scan ./myapp --format sarif --output results.sarif --fail-on high
snoot rules              # list detection rules
```

## Why

NIST finalized the PQC standards (FIPS 203/204/205) in August 2024. Migration
deadlines are fixed — CNSA 2.0 enforcement 2031, US federal high-value assets
2030 — and "harvest now, decrypt later" means long-lived data is exposed
*today*. Every mandate (OMB M-23-02, CNSA 2.0, UK NCSC, EU 2024/1101) leads
with the same first step: **cryptographic discovery** — inventory where your
classical crypto lives. Most organizations can't do it. snoot is the
developer-native, open-source tool for that first step.

## Pipeline

**snoot discovers → [orange](https://github.com/chasebryan/orange) verifies →
[orange-school](https://github.com/chasebryan/orange-school) teaches.**
Findings for primitives orange supports carry an `orange_note` pointing at
what orange can verify or replace.

## Honest limitations (v1)

- Heuristic detection; no data-flow analysis yet — a flagged call site means
  "look here", not "this is exploitable".
- Source only: binary / container / firmware analysis is the v2 roadmap.
- Direct dependencies only; transitive analysis is out of scope for v1.
- Symmetric crypto and hashes get hygiene flags at most; v1 is about the
  quantum-vulnerable public-key surface.

## License

GNU AGPLv3 — see LICENSE (in the [snoot repo](https://github.com/chasebryan/snoot)).
