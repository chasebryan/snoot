# Accuracy notes (pre-alpha)

snoot is heuristic. A finding means "look here", not "this is exploitable".
This document tracks known strengths, gaps, and the fixture gate.

## Fixture gate

`tests/fixture_corpus.rs` requires:

- Every rule in `{SNOOT001…SNOOT010, SNOOT016}` to fire on `tests/fixtures/positive/`
- `tests/fixtures/negative/` to produce zero findings

Engine unit tests cover additional shapes (Go/JS/C call sites, PEM variants,
TLS hybrid allowlist, manifest non-dep noise).

## Known false-positive classes

| Shape | Why |
|-------|-----|
| `crypto.generateKeyPairSync('ed25519')` | Matched as SNOOT001 by function name; algorithm arg not yet constrained |
| `Signature.getInstance(...)` (Java) | Any algorithm string matches SNOOT008 |
| `EVP_DigestSign` (OpenSSL) | Fires for all digest-sign paths, including future PQC |
| Manifest `cryptography` / `rustls` / `ring` | Broad libraries; medium inventory signal, not proof of classical use |

## Known false-negative classes

| Shape | Why |
|-------|-----|
| PKCS#8 PEM with ML-DSA/ML-KEM | Treated as classical (SNOOT010) until ASN.1 parsing lands |
| Transitive deps in lockfiles | v1 scopes direct manifests only |
| Obfuscated / dynamically loaded crypto | No data-flow or binary analysis in v1 |
| C# / Ruby / PHP / Swift / Kotlin | Out of scope for v1 |

## Real-world validation (planned)

Week 5 (DESIGN.md §13): run against 3+ public repos with known crypto usage
and publish miss/FP analysis here.
