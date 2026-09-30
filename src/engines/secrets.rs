//! Secrets engine: PEM / DER / JWK / key-material scanning + key-size extraction.
//!
//! **Status**: week-2. PKCS#1 RSA/EC/DSA PEM armor and generic PKCS#8
//! `PRIVATE KEY` blocks are detected. Full ASN.1 key-size extraction and JWK
//! parsing still land later.

use std::path::Path;

use crate::engines::Engine;
use crate::model::{Evidence, Finding};
use crate::rules::RuleRegistry;

pub struct SecretsEngine;

/// (armor substring, rule id, evidence detail)
const PEM_PRIVATE_RULES: &[(&str, &str, &str)] = &[
    (
        "BEGIN RSA PRIVATE KEY",
        "SNOOT003",
        "RSA PRIVATE KEY (PKCS#1 PEM)",
    ),
    (
        "BEGIN EC PRIVATE KEY",
        "SNOOT009",
        "EC PRIVATE KEY (SEC1 PEM)",
    ),
    ("BEGIN DSA PRIVATE KEY", "SNOOT010", "DSA PRIVATE KEY (PEM)"),
    (
        "BEGIN PRIVATE KEY",
        "SNOOT010",
        "PRIVATE KEY (PKCS#8 PEM — classical until proven otherwise)",
    ),
];

impl Engine for SecretsEngine {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn file_matches(&self, path: &Path) -> bool {
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

        let path_str = path.to_string_lossy().replace('\\', "/");
        let mut findings = Vec::new();

        for (idx, line) in text.lines().enumerate() {
            // Prefer the most specific armor match (RSA/EC/DSA before generic).
            let mut matched: Option<(&str, &str)> = None;
            for (armor, rule_id, detail) in PEM_PRIVATE_RULES {
                if line.contains(armor) {
                    // Avoid double-firing: "BEGIN RSA PRIVATE KEY" also contains
                    // "BEGIN" + "PRIVATE KEY" but not the exact generic label.
                    if *armor == "BEGIN PRIVATE KEY"
                        && (line.contains("RSA PRIVATE KEY")
                            || line.contains("EC PRIVATE KEY")
                            || line.contains("DSA PRIVATE KEY")
                            || line.contains("ENCRYPTED PRIVATE KEY"))
                    {
                        continue;
                    }
                    matched = Some((rule_id, detail));
                    break;
                }
            }
            let Some((rule_id, detail)) = matched else {
                continue;
            };
            let Some(rule) = RuleRegistry::by_id(rule_id) else {
                continue;
            };
            let snippet = line.trim().to_string();
            findings.push(Finding::new(
                &rule,
                path_str.clone(),
                Some((idx + 1) as u32),
                Some(snippet),
                Evidence {
                    kind: "pem_block".to_string(),
                    detail: detail.to_string(),
                },
            ));
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
    }

    #[test]
    fn detects_ec_private_pem() {
        let path = PathBuf::from("secrets/ec.key");
        let src = b"-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----\n";
        let findings = SecretsEngine.scan(&path, src);
        assert_eq!(findings[0].rule_id, "SNOOT009");
    }

    #[test]
    fn detects_pkcs8_private_pem() {
        let path = PathBuf::from("secrets/pkcs8.key");
        let src = b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...\n-----END PRIVATE KEY-----\n";
        let findings = SecretsEngine.scan(&path, src);
        assert_eq!(findings[0].rule_id, "SNOOT010");
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
