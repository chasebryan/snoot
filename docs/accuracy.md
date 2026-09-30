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

## Real-world validation

### RustCrypto/RSA (2026-09-30)

`snoot scan` against https://github.com/RustCrypto/RSA (`/tmp/rsa-src`):

| Rule | Count | Notes |
|------|------:|-------|
| SNOOT001 | 6 | `RsaPrivateKey::new` in benches + signing helpers |
| SNOOT003 | 3 | example PEMs + one in-source PEM fixture |
| SNOOT010 | 1 | PKCS#8 example PEM |
| SNOOT013 | 1 | SHA-1 reference in PKCS#1 v1.5 paths |
| SNOOT016 | 2 | classical deps in `marvin-toolkit/Cargo.toml` |

**13 findings / 65 files / ~1.6s.** Expected surface for an RSA library.
Likely FP/noise: inventory of the library's own implementation APIs (still
correct as discovery). Misses: no key-size extraction yet on the PEMs.

Further repos (Go `crypto/tls` consumers, Node `crypto` apps) still planned.
