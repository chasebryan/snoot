# Changelog

## 0.1.0 (pre-alpha)

First public scaffold → working scanner:

- Tree-sitter code engine for Rust, Python, Go, JS/TS, Java, C/C++
- 22 rules (SNOOT001–022) covering classical public-key crypto, PEM/JWK,
  TLS configs, manifests, and hygiene flags
- Reporters: console, JSON, SARIF 2.1.0, CycloneDX 1.6 CBOM
- `snoot init` / `--baseline`, `.snootignore`, `--fail-on`
- RSA PKCS#1/PKCS#8/DER/JWK modulus bit-length extraction
- Fixture corpus, self-scan gate, GitHub Action + CI + release workflow
- Real-world notes: RustCrypto/RSA, python-rsa, go-jose

Reliability integration:

- Version-2 portable baselines using complete call/key identities; explicit `init --force`
- Preserved repeated finding locations, protected outputs, and atomic report writes
- Error exits for unreadable inputs and malformed structured manifests
- Official SARIF/CycloneDX schema validation and separate multi-format reports
- C++ and modern TypeScript coverage, common RSA/NodeRSA calls, manifest aliases,
  and corrected TLS exclusions/comment handling
- Restored three-platform CI and DER fixtures; revision-specific reusable action
- Draft prerelease archives with SHA-256 checksums; production release gates documented
