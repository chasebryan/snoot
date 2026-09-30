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

### 1. RustCrypto/RSA (2026-09-30)

https://github.com/RustCrypto/RSA — **13 findings / 65 files / ~1.6s**

| Rule | Count | Notes |
|------|------:|-------|
| SNOOT001 | 6 | `RsaPrivateKey::new` in benches + signing helpers |
| SNOOT003 | 3 | example PEMs + one in-source PEM fixture |
| SNOOT010 | 1 | PKCS#8 example PEM |
| SNOOT013 | 1 | SHA-1 reference in PKCS#1 v1.5 paths |
| SNOOT016 | 2 | classical deps in `marvin-toolkit/Cargo.toml` |

### 2. sybrenstuvel/python-rsa (2026-09-30)

https://github.com/sybrenstuvel/python-rsa — **14 findings / 61 files / ~1.2s**

| Rule | Count | Notes |
|------|------:|-------|
| SNOOT001 | 9 | `rsa.newkeys` call sites |
| SNOOT003 | 4 | PEM private key fixtures |
| SNOOT016 | 1 | manifest dependency |

### 3. go-jose/go-jose (2026-09-30)

https://github.com/go-jose/go-jose — **37 findings / 89 files / ~3.2s**

| Rule | Count | Notes |
|------|------:|-------|
| SNOOT002 | 19 | `ecdsa.GenerateKey` / `Sign` usage |
| SNOOT001 | 5 | `rsa.GenerateKey` |
| SNOOT011 | 5 | RSA encrypt/decrypt APIs |
| SNOOT014 | 4 | Ed25519 inventory |
| SNOOT008 | 2 | classical signature APIs |
| SNOOT013 | 1 | SHA-1 |
| SNOOT020 | 1 | certificate inventory |

### 4. rzcoder/node-rsa (2026-09-30)

https://github.com/rzcoder/node-rsa — **~113 findings** after NodeRSA queries

| Rule | Count | Notes |
|------|------:|-------|
| SNOOT001 | ~107 | `new NodeRSA` / `.generateKeyPair` / `generateKeyPairSync` (mostly tests → medium) |
| SNOOT016 | 4 | classical deps in package manifests |
| SNOOT003 / 010 | 2 | PEM private key material |

Dense on a crypto library as expected; test/example paths demote to medium.

**Takeaway:** on libraries that *are* classical crypto, snoot reports a dense
but expected surface when APIs match the rule table. Gaps: PKCS#8 key-size,
deeper Node/Java library-internal shapes, and application-repo sampling.
