![snoot](assets/banner.jpg)

# snoot

*Snoot out the crypto hiding in your codebase.*

snoot scans a source tree for classical public-key cryptography — RSA,
ECDSA/ECDH, DSA, DH — in API calls, key material, dependency manifests, and
TLS configs. It reports what's quantum-vulnerable, maps each finding to its
NIST post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA), and emits
machine-readable evidence: SARIF (GitHub PR annotations), CycloneDX CBOM (the
compliance artifact), and JSON.

**Status: pre-alpha — week 5 of 6.** All four detection engines are live
(code, secrets, manifests, TLS configs), 22 rules across 8 languages, SARIF +
CycloneDX CBOM reporters, baseline suppression, `--fail-on` CI gating.
Validated on three real repos with zero false positives —
[docs/accuracy.md](docs/accuracy.md). See [DESIGN.md](DESIGN.md) for the plan.
Nothing here has been independently reviewed. Trust is the product, so the
gaps are documented, not hidden.

## Quick start

```sh
cargo install --path .   # or: cargo run --

snoot scan ./myapp
snoot scan ./myapp --format sarif --output results.sarif --fail-on high
snoot scan ./myapp --exclude 'tests/fixtures/**'   # skip known test keys
snoot rules              # list detection rules
```

## Why now: harvest now, decrypt later

An adversary doesn't need a quantum computer today. They record your
encrypted traffic and stored data *now*, and decrypt it the day a
cryptographically-relevant quantum computer arrives. Anything encrypted with
RSA, ECDSA/ECDH, or finite-field DH that must stay secret past that day is
already exposed. That's why every mandate — OMB M-23-02, CNSA 2.0, UK NCSC,
EU 2024/1101 — leads with the same first step: **cryptographic discovery**.
Inventory where your classical crypto lives, before you can migrate it.

| Deadline | Source |
|----------|--------|
| 2028–2035 | UK NCSC phased migration |
| 2030 | US federal high-value assets (OMB) |
| 2031 | CNSA 2.0 enforcement |
| 2026–2035 | EU coordinated migration |

NIST finalized the replacements in August 2024 (FIPS 203 ML-KEM, 204 ML-DSA,
205 SLH-DSA). The standards are done; the inventory is what's missing.

## Pipeline

**snoot discovers → [orange](https://github.com/chasebryan/orange) verifies →
[orange-school](https://github.com/chasebryan/orange-school) teaches.**
Findings for primitives orange supports carry an `orange_note` pointing at
what orange can verify or replace.

## Honest limitations (v1)

- Heuristic detection; no data-flow analysis — a flagged call site means
  "look here", not "this is exploitable". snoot doesn't know whether a key
  protects long-lived data or a test fixture.
- Can't see obfuscated code, dynamically loaded crypto libraries, or crypto
  behind FFI boundaries it has no queries for.
- Deliberate blind spots: PKCS#12 bundles, DSA private keys, and
  `ENCRYPTED PRIVATE KEY` blocks (algorithm unknowable without the
  passphrase) produce no findings rather than guesses.
- Source only: binary / container / firmware analysis is the v2 roadmap.
- Direct dependencies only; transitive analysis is out of scope for v1.
- Symmetric crypto and hashes get hygiene flags at most; v1 is about the
  quantum-vulnerable public-key surface.
- Recall is unmeasured — see [docs/accuracy.md](docs/accuracy.md) for what
  validation does and doesn't prove.

## License

GNU AGPLv3 — see LICENSE (in the [snoot repo](https://github.com/chasebryan/snoot)).
