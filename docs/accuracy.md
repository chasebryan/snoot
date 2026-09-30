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
  engine handles will slip through. See "Honest limitations" in the README.

## Regression gate

The `tests/fixtures/` corpus (22+ files, exact rule-ID set pinned per file in
`src/fixture_corpus.rs`) runs on every `cargo test`. Any query change that
alters fixture behavior fails loudly. New rules must ship fixtures.

## How snoot compares

Other open-source PQC scanners exist, all single-author and all young
(checked September 2026). This is a factual comparison, not a ranking —
different tools make different tradeoffs.

- **[pqctl](https://github.com/rjcuff/pqctl)** — the closest in spirit.
  Scans key files (PEM PKCS#1/PKCS#8, OpenSSH), X.509 certs/CSRs, source
  code (Go, Python, Java, JS/Node, C/OpenSSL, Ruby, PHP, C#), and TLS
  configs; `--json`, `--min-severity`, `--fail-on`, `--exclude`. Also
  *generates* PQC keys (`keygen`), which snoot deliberately doesn't do.
  Its README carries the same honest disclaimer we do ("heuristic
  inventory tool, not a certifier").
- **[pqc-scan](https://github.com/sachhg/pqc-scan)** — "Snyk for PQC"
  positioning, tree-sitter AST detection like ours, PQC001-style rule IDs.
- **[pqcanalyzer](https://github.com/xuxu298/pqcanalyzer)** (MIT) — the
  broadest scope: *active* TLS 1.3 ClientHello probing for X25519MLKEM768,
  PCAP flow analysis with HNDL scoring, VPN config scanning, PQC
  benchmarking via liboqs, and migration roadmaps with cost estimates.
  256 tests. Has a paid enterprise tier.

Where snoot differs, concretely:

1. **Static only, by design.** snoot never touches the network.
   pqcanalyzer's active probing answers "what's deployed"; snoot answers
   "what's in the repo." Different questions.
2. **Accuracy transparency.** The fixture corpus (exact rule-ID set pinned
   per file) and this document's published validation — 160 findings
   across three real repos, zero false positives, with an explicit section
   on what the validation does *not* prove — are the differentiator we
   chose to invest in. We publish our misses policy, not just our hits.
3. **Compliance-shaped outputs.** SARIF 2.1.0 (lands as GitHub PR
   annotations) and CycloneDX CBOM (the artifact auditors actually ask
   for), plus baseline suppression for CI.
4. **The orange hook.** Findings point at what orange can verify or
   replace. None of the above has that pipeline.

What snoot does *not* do that others do: live host probing, PQC key
generation, benchmarking, cost roadmaps. If you need those, use those
tools — they're good at their jobs.
