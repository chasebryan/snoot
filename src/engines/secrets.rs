//! Secrets engine: PEM / DER / JWK / key-material scanning + key-size extraction.
//!
//! Detects classical private-key PEM armor and JWKs. For PKCS#1 RSA PEMs,
//! decodes the DER body and reads the modulus INTEGER to report key size.

use std::path::Path;

use base64::Engine as _;

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
        let lines: Vec<&str> = text.lines().collect();
        let mut findings = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            let mut matched: Option<(&str, &str)> = None;
            for (armor, rule_id, detail) in PEM_PRIVATE_RULES {
                if trimmed.starts_with(armor) {
                    matched = Some((rule_id, detail));
                    break;
                }
            }

            if let Some((rule_id, detail)) = matched {
                let end_tag = trimmed.replacen("BEGIN", "END", 1);
                let mut j = i + 1;
                while j < lines.len() && !lines[j].trim().starts_with(&end_tag) {
                    j += 1;
                }
                let body_lines = &lines[i + 1..j.min(lines.len())];
                let mut detail = detail.to_string();
                let mut title_override = None;
                if rule_id == "SNOOT003" {
                    if let Some(bits) = rsa_pkcs1_modulus_bits(body_lines) {
                        detail = format!("{detail}, {bits}-bit");
                        title_override = Some(format!("RSA-{bits} private key material in PEM"));
                    }
                }
                if let Some(rule) = RuleRegistry::by_id(rule_id) {
                    let mut finding = Finding::new(
                        &rule,
                        path_str.clone(),
                        Some((i + 1) as u32),
                        Some(trimmed.to_string()),
                        Evidence {
                            kind: "pem_block".to_string(),
                            detail,
                        },
                    );
                    if let Some(title) = title_override {
                        finding.title = title;
                    }
                    findings.push(finding);
                }
                i = j.saturating_add(1);
                continue;
            }

            if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
                if let Some(rule) = RuleRegistry::by_id("SNOOT020") {
                    findings.push(Finding::new(
                        &rule,
                        path_str.clone(),
                        Some((i + 1) as u32),
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
            i += 1;
        }

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
    let has_d = lower.contains("\"d\":\"");
    let is_rsa = lower.contains("\"kty\":\"rsa\"") && lower.contains("\"n\":\"");
    let is_ec = lower.contains("\"kty\":\"ec\"") && lower.contains("\"x\":\"");
    if !has_d || !(is_rsa || is_ec) {
        return Vec::new();
    }

    let mut detail = if is_rsa {
        "JWK RSA private key (kty=RSA with d)".to_string()
    } else {
        "JWK EC private key (kty=EC with d)".to_string()
    };
    if is_rsa {
        if let Some(bits) = jwk_rsa_modulus_bits(&lower) {
            detail = format!("{detail}, ~{bits}-bit");
        }
    }

    let Some(rule) = RuleRegistry::by_id("SNOOT017") else {
        return Vec::new();
    };

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
            detail,
        },
    )]
}

/// Approximate RSA modulus bit length from a base64url JWK `n` value.
fn jwk_rsa_modulus_bits(compact_lower: &str) -> Option<u32> {
    let key = "\"n\":\"";
    let start = compact_lower.find(key)? + key.len();
    let end = compact_lower[start..].find('"')? + start;
    let n_b64 = &compact_lower[start..end];
    let n_b64 = n_b64.replace('-', "+").replace('_', "/");
    // pad
    let pad = (4 - n_b64.len() % 4) % 4;
    let n_b64 = format!("{n_b64}{}", "=".repeat(pad));
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(n_b64)
        .ok()?;
    Some(bytes.len() as u32 * 8)
}

/// Decode PKCS#1 RSAPrivateKey PEM body and return modulus bit length.
fn rsa_pkcs1_modulus_bits(body_lines: &[&str]) -> Option<u32> {
    let b64: String = body_lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .collect();
    if b64.is_empty() || b64.contains("...") {
        // Truncated fixture bodies — skip size extraction.
        return None;
    }
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    der_rsa_modulus_bits(&der)
}

/// Walk a DER-encoded RSAPrivateKey SEQUENCE and read the modulus INTEGER.
fn der_rsa_modulus_bits(der: &[u8]) -> Option<u32> {
    let mut i = 0usize;
    if *der.get(i)? != 0x30 {
        return None;
    }
    i += 1;
    let (_, next) = der_read_len(der, i)?;
    i = next;
    // version INTEGER
    i = der_skip_tlv(der, i)?;
    // modulus INTEGER
    if *der.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let (len, next) = der_read_len(der, i)?;
    let modulus = der.get(next..next + len)?;
    Some(integer_bit_length(modulus))
}

fn integer_bit_length(bytes: &[u8]) -> u32 {
    let mut bytes = bytes;
    while bytes.first() == Some(&0) && bytes.len() > 1 {
        bytes = &bytes[1..];
    }
    if bytes.is_empty() {
        return 0;
    }
    let leading = bytes[0].leading_zeros();
    (bytes.len() as u32) * 8 - leading
}

fn der_read_len(data: &[u8], i: usize) -> Option<(usize, usize)> {
    let first = *data.get(i)?;
    if first & 0x80 == 0 {
        return Some((first as usize, i + 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for b in data.get(i + 1..i + 1 + n)? {
        len = (len << 8) | (*b as usize);
    }
    Some((len, i + 1 + n))
}

fn der_skip_tlv(data: &[u8], i: usize) -> Option<usize> {
    let _tag = data.get(i)?;
    let (len, next) = der_read_len(data, i + 1)?;
    Some(next + len)
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
    fn extracts_rsa_2048_bit_size() {
        let pem = include_str!("../../tests/fixtures/positive/secrets/rsa2048.key");
        let path = PathBuf::from("secrets/rsa2048.key");
        let findings = SecretsEngine.scan(&path, pem.as_bytes());
        assert_eq!(findings[0].rule_id, "SNOOT003");
        assert!(
            findings[0].evidence.detail.contains("2048-bit"),
            "{}",
            findings[0].evidence.detail
        );
    }

    #[test]
    fn extracts_rsa_512_bit_size() {
        let pem = include_str!("../../tests/fixtures/positive/secrets/rsa512.key");
        let path = PathBuf::from("secrets/rsa512.key");
        let findings = SecretsEngine.scan(&path, pem.as_bytes());
        assert!(
            findings[0].evidence.detail.contains("512-bit"),
            "{}",
            findings[0].evidence.detail
        );
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

    #[test]
    fn integer_bit_length_strips_leading_zero() {
        assert_eq!(integer_bit_length(&[0x00, 0x80]), 8);
        assert_eq!(integer_bit_length(&[0x01]), 1);
    }
}
