//! Rule registry: detection rules as data, not code.
//!
//! Each rule carries its id, severity, description, classical → PQC
//! remediation mapping, and per-language tree-sitter queries (consumed by the
//! code engine). Adding a rule or a language means adding data here — no new
//! control flow. v1 target: 20+ rules; week 1 ships the first 5.
//!
//! Migration mappings follow DESIGN.md §6 (NIST FIPS 203/204/205).

use crate::model::{LanguageQuery, Rule, Severity};

fn q(language: &str, query: &str) -> LanguageQuery {
    LanguageQuery {
        language: language.to_string(),
        query: query.to_string(),
    }
}

/// Week-1 rule set: the first five detection rules.
pub struct RuleRegistry;

impl RuleRegistry {
    pub fn all() -> Vec<Rule> {
        vec![
            Rule {
                id: "SNOOT001".to_string(),
                title: "RSA key generation".to_string(),
                severity: Severity::High,
                description: "Application code generates an RSA key pair. RSA is \
                    quantum-vulnerable (Shor's algorithm): anything this key \
                    protects is exposed to harvest-now-decrypt-later."
                    .to_string(),
                remediation: "Migrate encryption to ML-KEM-768 or ML-KEM-1024 \
                    (FIPS 203); use hybrid X25519+ML-KEM during transition. For \
                    signatures, migrate to ML-DSA (FIPS 204)."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Rsa\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"RsaPrivateKey\")\n  (#eq? @_fn \"new\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (attribute\n      object: (identifier) @_a\n      attribute: (identifier) @_b)\n    attribute: (identifier) @_fn)\n  (#eq? @_a \"Crypto\")\n  (#eq? @_b \"RSA\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"rsa\")\n  (#eq? @_fn \"newkeys\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "RSA key-generation sites are candidates for orange-verified \
                     ML-KEM migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT002".to_string(),
                title: "ECDSA signing".to_string(),
                severity: Severity::High,
                description: "Application code signs with ECDSA (P-256/P-384). \
                    ECDSA falls to Shor's algorithm; signatures on long-lived \
                    artifacts become forgeable once a cryptographically relevant \
                    quantum computer exists."
                    .to_string(),
                remediation: "Migrate signatures to ML-DSA-65 or ML-DSA-87 \
                    (FIPS 204). CNSA 2.0 requires PQC signatures for \
                    software/firmware signing by 2030."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"SigningKey\")\n  (#eq? @_fn \"random\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"SigningKey\")\n  (#eq? @_fn \"generate\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "ECDSA signing sites are candidates for orange-verified \
                     ML-DSA migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT003".to_string(),
                title: "RSA private key material in PEM".to_string(),
                severity: Severity::Critical,
                description: "A PEM block containing an RSA private key was \
                    found in the source tree. Embedded private keys are \
                    compromised by definition — and quantum-vulnerable on top \
                    of it."
                    .to_string(),
                remediation: "Remove the key from source control immediately \
                    and rotate it. Store secrets in a KMS/HSM going forward. \
                    Issue PQC replacements (ML-KEM for encryption, ML-DSA for \
                    signatures) for the replacement keys."
                    .to_string(),
                // Detected by the secrets engine (PEM parsing), not tree-sitter.
                queries: vec![],
                cwe: Some("CWE-798".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT004".to_string(),
                title: "Weak Diffie-Hellman parameters".to_string(),
                severity: Severity::High,
                description: "Diffie-Hellman key exchange with parameters below \
                    3072 bits, or a named weak group (e.g. Oakley Group 2 / \
                    modp1024). Weak to precomputation attacks today (Logjam \
                    class) and to Shor's algorithm."
                    .to_string(),
                remediation: "Retire DH below 3072 bits. Migrate key exchange \
                    to ML-KEM (FIPS 203); use hybrid X25519+ML-KEM for \
                    interoperability during transition."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Dh\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"DH\")\n  (#eq? @_fn \"generate_parameters\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT005".to_string(),
                title: "TLS configuration without PQC hybrid key exchange".to_string(),
                severity: Severity::Medium,
                description: "A TLS configuration enables classical-only key \
                    exchange (ECDHE / X25519) with no hybrid post-quantum \
                    group such as X25519+ML-KEM-768. Connections are exposed \
                    to harvest-now-decrypt-later."
                    .to_string(),
                remediation: "Enable hybrid PQC key exchange \
                    (X25519MLKEM768) in the TLS configuration. Chrome, \
                    Cloudflare, and the major clouds already negotiate it; \
                    plan full migration against CNSA 2.0 timelines."
                    .to_string(),
                // Detected by the tlsconf engine (config-string matching).
                queries: vec![],
                cwe: None,
                orange_note: None,
            },
        ]
    }

    // Used by unit tests now; by the code engine starting week 2.
    #[allow(dead_code)]
    pub fn by_id(id: &str) -> Option<Rule> {
        Self::all().into_iter().find(|r| r.id == id)
    }

    // Week-1 API surface: used by reporters/tests starting week 2.
    #[allow(dead_code)]
    pub fn count() -> usize {
        Self::all().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_week1_rules() {
        let rules = RuleRegistry::all();
        assert_eq!(rules.len(), 5);
        for id in ["SNOOT001", "SNOOT002", "SNOOT003", "SNOOT004", "SNOOT005"] {
            assert!(RuleRegistry::by_id(id).is_some(), "missing rule {id}");
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let rules = RuleRegistry::all();
        let mut ids: Vec<_> = rules.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len());
    }

    #[test]
    fn code_rules_carry_queries() {
        // Rules detected by the code engine must ship at least one query.
        for id in ["SNOOT001", "SNOOT002", "SNOOT004"] {
            let rule = RuleRegistry::by_id(id).unwrap();
            assert!(!rule.queries.is_empty(), "{id} has no tree-sitter queries");
        }
    }
}
