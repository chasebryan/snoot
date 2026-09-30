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

/// Full PEM armor lines (must begin the trimmed line — avoids self-hits on
/// detector source that merely mentions these labels in strings/comments).
const PEM_PRIVATE_RULES: &[(&str, &str, &str)] = &[
    (
        "-----BEGIN RSA PRIVATE KEY-----",
        "SNOOT003",
        "RSA PRIVATE KEY (PKCS#1 PEM)",
    ),
    (
        "-----BEGIN EC PRIVATE KEY-----",
        "SNOOT009",
        "EC PRIVATE KEY (SEC1 PEM)",
    ),
    (
        "-----BEGIN DSA PRIVATE KEY-----",
        "SNOOT010",
        "DSA PRIVATE KEY (PEM)",
    ),
    (
        "-----BEGIN PRIVATE KEY-----",
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
            let trimmed = line.trim();
            // Prefer the most specific armor match (RSA/EC/DSA before generic).
            let mut matched: Option<(&str, &str)> = None;
            for (armor, rule_id, detail) in PEM_PRIVATE_RULES {
                if trimmed.starts_with(armor) {
                    matched = Some((rule_id, detail));
                    break;
                }
            }
            if let Some((rule_id, detail)) = matched {
                if let Some(rule) = RuleRegistry::by_id(rule_id) {
                    findings.push(Finding::new(
                        &rule,
                        path_str.clone(),
                        Some((idx + 1) as u32),
                        Some(trimmed.to_string()),
                        Evidence {
                            kind: "pem_block".to_string(),
                            detail: detail.to_string(),
                        },
                    ));
                }
            }

            // Classical X.509 cert inventory (info).
            if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
                if let Some(rule) = RuleRegistry::by_id("SNOOT020") {
                    findings.push(Finding::new(
                        &rule,
                        path_str.clone(),
                        Some((idx + 1) as u32),
                        Some(trimmed.to_string()),
                        Evidence {
                            kind: "pem_block".to_string(),
                            detail:
                                "X.509 certificate PEM (classical algorithm assumed until parsed)"
                                    .to_string(),
                        },
                    ));
                }
            }
        }

        // JWK private keys — only in data files; source that embeds example
        // JWKs in string literals is out of scope for this heuristic.
        if jwk_file(path) {
            findings.extend(scan_jwk_private(path, text));
        }

        findings
    }
}

fn jwk_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("json" | "jwk" | "yml" | "yaml" | "txt")
    )
}

fn scan_jwk_private(path: &Path, text: &str) -> Vec<Finding> {
    let lower = text
        .to_ascii_lowercase()
        .replace([' ', '\n', '\r', '\t'], "");
    // Require a private field plus a classical public component so comments
    // that merely mention kty/d do not fire.
    let has_d = lower.contains("\"d\":\"");
    let is_rsa = lower.contains("\"kty\":\"rsa\"") && lower.contains("\"n\":\"");
    let is_ec = lower.contains("\"kty\":\"ec\"") && lower.contains("\"x\":\"");
    if !has_d || !(is_rsa || is_ec) {
        return Vec::new();
    }

    let (rule_id, detail) = if is_rsa {
        ("SNOOT017", "JWK RSA private key (kty=RSA with d)")
    } else {
        ("SNOOT017", "JWK EC private key (kty=EC with d)")
    };

    let Some(rule) = RuleRegistry::by_id(rule_id) else {
        return Vec::new();
    };

    // Locate the first kty line for a useful location.
    let mut line_no = None;
    let mut snippet = None;
    for (idx, line) in text.lines().enumerate() {
        let l = line.to_ascii_lowercase();
        if l.contains("\"kty\"") {
            line_no = Some((idx + 1) as u32);
            snippet = Some(line.trim().chars().take(120).collect());
            break;
        }
    }

    vec![Finding::new(
        &rule,
        path.to_string_lossy().replace('\\', "/"),
        line_no,
        snippet,
        Evidence {
            kind: "jwk".to_string(),
            detail: detail.to_string(),
        },
    )]
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
    fn detects_rsa_jwk() {
        let path = PathBuf::from("secrets/rsa.jwk");
        let src = br#"{ "kty": "RSA", "n": "x", "e": "AQAB", "d": "y" }"#;
        let findings = SecretsEngine.scan(&path, src);
        assert!(
            findings.iter().any(|f| f.rule_id == "SNOOT017"),
            "{findings:?}"
        );
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
