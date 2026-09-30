# Changelog

## 0.1.0 (pre-alpha)

First public scaffold → working scanner:

- Tree-sitter code engine for Rust, Python, Go, JS/TS, Java, C/C++
- 20 rules (SNOOT001–020) covering classical public-key crypto, PEM/JWK,
  TLS configs, manifests, and hygiene flags
- Reporters: console, JSON, SARIF 2.1.0, CycloneDX 1.6 CBOM
- `snoot init` / `--baseline`, `.snootignore`, `--fail-on`
- RSA PKCS#1 modulus bit-length extraction
- Fixture corpus, self-scan gate, GitHub Action + CI + release workflow
- Real-world notes: RustCrypto/RSA, python-rsa, go-jose
