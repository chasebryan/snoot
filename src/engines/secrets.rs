//! Secrets engine: PEM / DER / JWK / key-material scanning + key-size extraction.
//!
//! **Job** (DESIGN.md §5): find key material checked into the tree —
//! `-----BEGIN RSA PRIVATE KEY-----` blocks, PKCS#8 / PKCS#1 DER blobs,
//! JWK `{"kty":"RSA","n":"…","d":"…"}` objects — parse each one properly
//! (don't regex the ASN.1), extract the algorithm and key size, and emit
//! findings like SNOOT003. Key size matters: it drives severity and the
//! remediation mapping (RSA-1024 vs RSA-4096 get different guidance).
//!
//! Finds private keys (critical) as well as public keys and certificates
//! (info — inventory feed for the CBOM).
//!
//! **Status**: week-2 partial. PKCS#1 RSA PEM armor detection is live
//! (SNOOT003). Full PEM/DER/JWK parsing with ASN.1 key-size extraction
//! lands later in week 2/3.

use std::path::Path;

use crate::engines::Engine;
use crate::model::{Evidence, Finding};
use crate::rules::RuleRegistry;

pub struct SecretsEngine;

/// Armor labels that map directly to a classical private-key rule.
/// Full ASN.1 discrimination for generic `PRIVATE KEY` (PKCS#8) is later.
const RSA_PRIVATE_PEM: &str = "BEGIN RSA PRIVATE KEY";

impl Engine for SecretsEngine {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn file_matches(&self, path: &Path) -> bool {
        // Dedicated key/cert files, plus source files (PEM blocks get pasted
        // into code and config more often than anyone admits).
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".pem")
                || lower.ends_with(".key")
                || lower.ends_with(".crt")
                || lower.ends_with(".cer")
                || lower.ends_with(".der")
                || lower.ends_with(".p12")
                || lower.ends_with(".pfx")
                || lower.ends_with(".pub")
                || lower.ends_with(".asc")
                || lower.ends_with(".jwk")
            {
                return true;
            }
        }
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(
                "rs" | "py"
                    | "go"
                    | "js"
                    | "ts"
                    | "java"
                    | "c"
                    | "h"
                    | "cpp"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "toml"
                    | "env"
                    | "txt"
                    | "md"
            )
        )
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding> {
        let Ok(text) = std::str::from_utf8(content) else {
            return Vec::new();
        };
        let Some(rule) = RuleRegistry::by_id("SNOOT003") else {
            return Vec::new();
        };

        let path_str = path.to_string_lossy().replace('\\', "/");
        let mut findings = Vec::new();

        for (idx, line) in text.lines().enumerate() {
            if line.contains(RSA_PRIVATE_PEM) {
                let snippet = line.trim().to_string();
                findings.push(Finding::new(
                    &rule,
                    path_str.clone(),
                    Some((idx + 1) as u32),
                    Some(snippet.clone()),
                    Evidence {
                        kind: "pem_block".to_string(),
                        detail: "RSA PRIVATE KEY (PKCS#1 PEM)".to_string(),
                    },
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_rsa_private_pem() {
        let path = PathBuf::from("secrets/dev.key");
        let src = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n";
        let findings = SecretsEngine.scan(&path, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT003");
        assert_eq!(findings[0].location.line, Some(1));
    }

    #[test]
    fn ignores_public_pem() {
        let path = PathBuf::from("secrets/dev.pub");
        let src =
            b"-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQAD...\n-----END PUBLIC KEY-----\n";
        let findings = SecretsEngine.scan(&path, src);
        assert!(findings.is_empty());
    }
}
