# snoot — Design Doc (v1)

**Status:** Draft · **Date:** 2026-09-30 (week 2 in progress) · **Author:** Muse, for Chase Bryan
**Tagline:** *Snoot out the crypto hiding in your codebase.*

## 1. Problem

Post-quantum cryptography standards are final (NIST FIPS 203/204/205, Aug 2024).
Migration deadlines are fixed and funded (CNSA 2.0 enforcement 2031, US federal
high-value assets 2030, $7.1B OMB estimate, UK NCSC 2028–2035, EU 2026–2035).
"Harvest now, decrypt later" means long-lived data is exposed *today*.

Yet a July 2026 DigiCert survey (n=1,001) found 87% of organizations are planning
PQC migration but only 7% have deployed it. The universally mandated first step —
OMB M-23-02, CNSA 2.0, NCSC, EU 2024/1101 all lead with it — is **cryptographic
discovery**: producing an inventory of where classical public-key crypto lives.
Most organizations cannot do this. Existing discovery tools are enterprise SaaS
sold to CISOs (SandboxAQ, IBM Guardium Quantum Safe, Keyfactor) or brand-new,
single-author OSS toys (pqc-scan, pqctl, pqcanalyzer — all <3 months old, ~2 stars).
There is no credible, maintained, developer-native open-source PQC scanner.

## 2. Goals

- Be the `cargo install`-able scanner a developer runs in CI: fast, honest,
  well-tested, with SARIF output that lands as GitHub PR annotations.
- Find classical public-key crypto usage in source: RSA, ECDSA/ECDH, DSA, DH —
  API calls, key material, certificates, dependency manifests, TLS config.
- Emit machine-readable evidence: SARIF, CycloneDX CBOM, JSON.
- Serve as **orange's front door**: findings point at what orange can verify or
  replace (discover → verify → learn pipeline with orange-school).
- Ship in ~6 weeks. Scope discipline is the strategy; the toys die promising
  everything.

## 3. Non-goals (v1)

- Binary / container / firmware analysis (v2 differentiator — nobody in OSS has it)
- Auto-remediation or code rewriting
- Transitive dependency analysis (v1 covers direct manifests only)
- Web dashboard, SaaS, hosted inventory
- Symmetric crypto / hash migration guidance beyond deprecation flags
  (v1 focuses on public-key, the quantum-vulnerable surface)

## 4. CLI UX

```text
snoot scan [PATH]            Scan a source tree (default: .)
  --format console|sarif|cbom|json   (default: console; repeatable)
  --output FILE              Write report to file instead of stdout
  --fail-on SEVERITY          Exit non-zero if findings at/above severity (CI gating)
  --baseline FILE            Suppress findings already recorded in baseline
  --no-color                 Disable colored output
  --quiet                    Findings only, no banner/summary

snoot init                   Write a baseline file from current findings
snoot rules                  List all detection rules with IDs and descriptions
snoot --version
```

Example:

```text
$ snoot scan ./myapp --format sarif --output results.sarif --fail-on high

snoot v0.1.0 — snooting out hidden crypto in ./myapp …

SNOOT003  high    RSA-2048 private key material          src/auth/keys.rs:42
SNOOT007  high    ECDSA P-256 signing                    src/tokens.rs:118
SNOOT012  medium  TLS 1.2 without PQC hybrid             config/nginx.conf:9

3 findings (2 high, 1 medium) · 1,204 files scanned in 1.8s
```

## 5. Architecture

Single Rust binary crate, modules:

```text
src/
  main.rs          CLI (clap derive), subcommands, exit codes
  model.rs         Finding, Severity, Rule, Location, Evidence
  scanner.rs       Orchestration: walk tree, dispatch per-file engines, collect
  engines/
    code.rs        tree-sitter based API-call detection per language
    secrets.rs     PEM / DER / JWK / key-material scanning + key-size extraction
    manifest.rs    Dependency manifests (Cargo.toml, package.json, go.mod,
                   requirements.txt, pom.xml, Gemfile, composer.json)
    tlsconf.rs     TLS configuration strings (protocol versions, cipher suites)
  rules.rs         Rule registry: static table + per-language tree-sitter queries
  reporters/
    console.rs     Colored human output with grouping + summary
    sarif.rs       SARIF 2.1.0 (GitHub code scanning integration)
    cbom.rs        CycloneDX 1.6 CBOM (cryptography bill of materials)
    json.rs        Plain JSON
  baseline.rs      Baseline read/write, finding fingerprinting for suppression
```

Key design decisions:

- **Rules as data, not code.** Each rule is a struct: `id` (SNOOT001…),
  `title`, `severity`, `description`, `remediation` (classical → PQC mapping),
  and per-language tree-sitter query strings. Adding a language or rule means
  adding data, not new control flow.
- **tree-sitter for code, regex/parsers for the rest.** AST queries catch API
  usage precisely (`Rsa::generate`, `ecdsa.Sign`, `crypto.createSign`…);
  dedicated parsers handle PEM blocks (extract algorithm + key size),
  manifests (parse properly, don't regex TOML), and TLS configs.
- **Finding fingerprints** (rule id + file + normalized snippet hash) make
  baselines stable across line shifts.
- **No network calls.** The scanner must work offline and in air-gapped CI.
  All rule data ships in the binary.

## 6. Rule system (v1 sketch)

Severity model (v1, deliberately simple — HNDL-aware but explainable):

| Severity | Meaning |
|----------|---------|
| critical | Private key material for classical algorithms, or signing with RSA/ECDSA on long-lived artifacts |
| high     | Classical public-key usage (encrypt, sign, key exchange) in application code |
| medium   | Classical crypto in dependencies, test code, or TLS configs without PQC hybrid |
| low      | Deprecated-but-not-quantum-relevant (MD5, SHA-1, DES) — flagged for hygiene |
| info     | Inventory-only: crypto found, no action needed (feeds the CBOM) |

Migration mapping (each rule carries its remediation):

| Found | Migrate to |
|-------|-----------|
| RSA-2048/3072/4096 (encrypt) | ML-KEM-768 / ML-KEM-1024 (FIPS 203), hybrid X25519+ML-KEM during transition |
| ECDSA P-256/P-384 (sign) | ML-DSA-65 / ML-DSA-87 (FIPS 204) |
| ECDH / X25519 / X448 (exchange) | ML-KEM (FIPS 203), hybrid for interop |
| DSA, DH < 3072 | Retire; ML-DSA / ML-KEM |
| Ed25519 (sign) | Not quantum-vulnerable *today* via Shor the same way, but flagged info: plan ML-DSA migration per CNSA 2.0 |

v1 target: **20+ rules** across the six languages.

## 7. Language coverage (v1)

Rust, Python, Go, JavaScript/TypeScript, Java, C/C++ — via tree-sitter grammars.
Each language gets: key-generation calls, sign/verify, encrypt/decrypt, key
exchange / TLS setup, and key import/parse calls. C/C++ covers OpenSSL,
mbedTLS, and libsodium call shapes.

Out of scope for v1: C#, Ruby, PHP, Swift, Kotlin (add by demand; the
rules-as-data design makes this cheap).

## 8. Outputs

- **console**: grouped by severity, file:line, one-line remediation hint, summary
  counts + scan stats. Respects NO_COLOR.
- **SARIF 2.1.0**: rules metadata + results with locations, so GitHub code
  scanning renders findings as PR annotations. This is the distribution hack:
  the GitHub Action + SARIF upload makes snoot visible where developers work.
- **CBOM (CycloneDX 1.6)**: `components` with `cryptoProperties` per finding —
  algorithm, key size, mode, and protocol refs. This is the compliance artifact
  auditors and the OMB inventory mandate want.
- **JSON**: full finding objects for piping into other tools.

## 9. The orange hook (front door, not second product)

v1 keeps this light and honest:

- Findings for primitives orange supports get an `orange_note`: "verifiable with
  orange — see <link>". No codegen, no overclaiming.
- README positions the pipeline: **snoot discovers → orange verifies →
  orange-school teaches**.
- Later (explicitly not v1): `snoot --orange` emitting an orange migration stub
  for flagged call sites.

This is what none of the competing scanners can copy: they don't have an orange.

## 10. Testing & honesty strategy

This is the differentiator against the toy scanners. v1 ships with:

- **Fixture corpus**: a `tests/fixtures/` tree per language with known-positive
  and known-negative samples for every rule. Every rule must have fixtures.
- **Real-world validation**: run against 3+ real open-source repos with known
  crypto usage; publish the results and the miss/false-positive analysis in
  `docs/accuracy.md`.
- **Documented limitations** in the README: heuristic detection, no data-flow
  analysis in v1, what it can't see (obfuscated code, dynamically loaded libs).
  The pre-alpha honesty of orange, applied here. Trust is the product.
- **CI**: `cargo test`, clippy, fmt, plus a self-scan (`snoot scan` on its own
  repo must be clean) and a fixture-accuracy gate.

## 11. Distribution

- `cargo install snoot` (crates.io)
- GitHub Action (`chasebryan/snoot-action` or in-repo `action.yml`) that runs
  scan + uploads SARIF to code scanning
- Prebuilt binaries via release workflow (linux/mac/windows, x86_64 + aarch64)
- Homebrew formula once there's traction

## 12. v2 roadmap (documented, not built)

1. **Binary analysis** — ELF/Mach-O/PE string extraction, library fingerprinting
   (OpenSSL/BoringSSL version strings), constant/parameter detection in
   stripped binaries. *Nobody in OSS does this; it's the moat.*
2. Transitive dependency crypto inventory (lockfile graph walk)
3. Data-flow-aware findings (is this RSA key protecting long-lived data?)
4. HNDL-prioritized reporting (data-lifetime × algorithm × exposure)
5. `snoot --orange` migration stubs

## 13. Six-week milestones

- **Week 1**: Crate skeleton, CLI, model types, console + JSON reporters.
  First 5 rules (Rust + Python).
- **Week 2**: tree-sitter engine + 4 more languages. PEM/key-material engine.
  15 rules.
- **Week 3**: Manifest engine, TLS config engine. 20+ rules. SARIF reporter.
- **Week 4**: CBOM reporter, baseline/suppression, `--fail-on`. Fixture corpus
  complete (every rule has +/- fixtures).
- **Week 5**: Real-world validation on 3 repos, accuracy docs, honest
  limitations. GitHub Action + SARIF upload working end-to-end.
- **Week 6**: Docs (README with HNDL story + CNSA 2.0 table + pqc-scan
  comparison), release workflow, crates.io publish, announcement.

## 14. Open questions

- Rule ID namespace: `SNOOT001` vs CWE-mapped IDs? (Lean: SNOOT IDs, with CWE
  refs in rule metadata where they exist.)
- Minimum severity default for `--fail-on` in the GitHub Action: high?
- Should `snoot init` also emit a starter CBOM? (Probably yes — the compliance
  artifact is the point.)
- Binary analysis spike in week 6 if ahead? (Only if v1 is done; protect the
  ship date.)
