# snoot accuracy — real-world validation

Published validation results. This page is a lab notebook, not a datasheet:
method, raw counts, what we fixed, and what we still can't see.

## Method (2026-09-30)

Cloned three open-source repos with known crypto usage into `/tmp/snoot-validation`
(not committed; clones are disposable), ran `snoot scan` on each, and **manually
triaged every finding** — true positive, false positive, or unclear. No sampling:
all 160 findings were read.

## Results

| Repo | Findings | False positives |
|------|----------|-----------------|
| paramiko (SSH library, Python) | 15 | 0 |
| golang-jwt (JWT library, Go) | 14 | 0 |
| libtomcrypt (crypto library, C) | 131 | 0 |

Breakdown:

- **paramiko**: SNOOT003×4, SNOOT009×9 (all real test keys in `tests/`),
  SNOOT007×1 (ECDH key exchange), SNOOT016×1 (`cryptography` dependency).
- **golang-jwt**: SNOOT001×1 (RSA keygen in tests), SNOOT003×1, SNOOT009×3
  (test keys), SNOOT014×5 (classical JWT algs RS/ES/PS256 — the library's
  actual purpose), SNOOT022×5 (test public keys, inventory).
- **libtomcrypt**: SNOOT003×94 (real test keys, including passphrase-encrypted
  traditional-format PEM), SNOOT009×2, SNOOT013×1 (SHA-1), SNOOT020×17
  (RSA-signed certs), SNOOT022×16. The 17 "certs" include ASN.1 torture-test
  vectors (`oid_overflow`, `illegal_padding`) — structurally valid
  certificates, correctly flagged. snoot flags test data as test data; it does
  not judge deployability, and saying otherwise would be a lie.

## Fixes the triage produced

1. Passphrase-encrypted traditional PEM keys (`Proc-Type: 4,ENCRYPTED`) were
   firing as plain private keys. They now carry "encrypted at rest" in the
   evidence detail instead of silently looking identical to plaintext keys.
2. The SARIF reporter omitted `region` for whole-file DER/JWK findings (no
   line number). It now always emits a region, defaulting to line 1.

## Per-rule precision notes

- Key-material rules (SNOOT003/009/015/022) are the highest-precision rules in
  the registry: a parseable RSA/EC private key is never ambiguous. The only
  judgment call is *encrypted* keys, handled above.
- Code rules depend on tree-sitter queries, which are validated two ways:
  every query must compile against its grammar, and every query must fire on
  a minimal positive fixture (`tests/fixtures/`). This caught real bugs
  pre-release: a Python RSA query that could never match, and a Java DSA
  query that substring-matched `SHA256withECDSA`.
- TLS-config rules (SNOOT005/018/019) are line-based, not AST-based. They
  honor negations (`SSLProtocol all -SSLv3`) and only fire on explicitly
  *enabled* weak protocols — an absent directive is not a finding.

## What this does NOT prove

- **Recall is unmeasured.** We triaged everything snoot *found*; we did not
  establish ground truth for everything it *missed*. Three crypto-heavy repos
  are selection-biased toward true positives. A proper recall study needs a
  labeled corpus — that's future work, tracked in DESIGN.md §14.
- **Test data dominates.** Most findings above are test keys and fixtures.
  That's correct behavior (test keys are still keys), but it means precision
  on *production* code paths is less exercised.
- **Adversarial inputs untested.** Obfuscated code, dynamically loaded crypto
  libraries, and deliberately mislabeled PEM blocks beyond what the secrets
  engine handles will slip through. See "Detection limits" in the README.

## Regression gate

The `tests/fixtures/` corpus (22+ files, exact rule-ID set pinned per file in
`src/fixture_corpus.rs`) runs on every `cargo test`. Any query change that
alters fixture behavior fails loudly. New rules must ship fixtures.

## Current regression coverage

The integrated revision retains the exact per-file rule sets and every-query
positive checks, and adds CLI tests for baseline portability, changed private
material, JWKS reordering, repeated call locations, full argument fingerprints,
DER dispatch, C++/TSX/MTS/CTS, TLS exclusions/comments, structured manifests,
output preservation, severity thresholds, and separate reports.

Pinned official SARIF 2.1.0 and CycloneDX 1.6 schemas validate real fixture
reports and empty reports in CI. Schema validity establishes interchange shape,
not inventory completeness or regulatory compliance.

The historical 160-finding exercise above was documented by earlier work.
This readiness review did not reproduce its manual labels. Its per-rule counts
are not current output expectations: duplicate-location retention, new queries,
path-based test severity, and manifest coverage have changed.

Known limits include import/type ambiguity, aliases and indirect calls, file-level
TLS hybrid decisions across virtual hosts, unsupported encrypted/DSA material,
and unmeasured recall. No claim of universal zero false positives is warranted.

## Labeled recall benchmark

A separate recall harness now lives in
[`benchmarks/recall/`](../benchmarks/recall/manifest.json) and is documented in
[`docs/recall-benchmark.md`](recall-benchmark.md). It measures labeled
cryptographic sites detected / total labeled sites and surfaces unmatched
scanner findings for review.

The committed seed corpus is synthetic and exists to regression-test the
measurement machinery. It is **not** a production recall estimate. A defensible
recall claim still requires independently labeled, production-like ground truth
across supported languages, engines, and documented blind spots.
