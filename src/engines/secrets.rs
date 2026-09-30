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
                if j == lines.len() {
                    i += 1;
                    continue;
                }
                let body_lines = &lines[i + 1..j];
                let body: String = body_lines.iter().map(|line| line.trim()).collect();
                if body.is_empty() {
                    i = j + 1;
                    continue;
                }
                let mut detail = detail.to_string();
                let mut title_override = None;
                if rule_id == "SNOOT003" {
                    if let Some(bits) = rsa_pkcs1_modulus_bits(body_lines) {
                        detail = format!("{detail}, {bits}-bit");
                        title_override = Some(format!("RSA-{bits} private key material in PEM"));
                    }
                } else if rule_id == "SNOOT010" && trimmed.contains("BEGIN PRIVATE KEY") {
                    if let Some(bits) = pkcs8_rsa_modulus_bits(body_lines) {
                        detail = format!("RSA PRIVATE KEY (PKCS#8 PEM), {bits}-bit");
                        title_override =
                            Some(format!("RSA-{bits} private key material in PEM (PKCS#8)"));
                    }
                }
                if let Some(rule) = RuleRegistry::by_id(rule_id) {
                    let mut finding = Finding::new(
                        &rule,
                        path_str.clone(),
                        Some((i + 1) as u32),
                        Some(body),
                        Evidence {
                            kind: "pem_block".to_string(),
                            detail,
                        },
                    );
                    if let Some(title) = title_override {
                        finding.title = title;
                    }
                    finding.location.snippet = Some(trimmed.to_string());
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
    let Ok(document) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(rule) = RuleRegistry::by_id("SNOOT017") else {
        return Vec::new();
    };
    let keys = document.get("keys").and_then(|keys| keys.as_array());
    let candidates: Vec<_> = match keys {
        Some(keys) => keys.iter().collect(),
        None => vec![&document],
    };
    let mut findings = Vec::new();
    for key in candidates {
        let string = |field| {
            key.get(field)
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty())
        };
        let Some(kind @ ("RSA" | "EC")) = string("kty") else {
            continue;
        };
        if string("d").is_none() || string(if kind == "RSA" { "n" } else { "x" }).is_none() {
            continue;
        }
        let mut detail = format!("JWK {kind} private key (kty={kind} with d)");
        if kind == "RSA" {
            if let Some(bits) = string("n").and_then(jwk_rsa_modulus_bits) {
                detail = format!("{detail}, {bits}-bit");
            }
        }
        let mut finding = Finding::new(
            &rule,
            path.to_string_lossy().replace('\\', "/"),
            None,
            Some(serde_json::to_string(key).expect("JSON value serializes")),
            Evidence {
                kind: "jwk".to_string(),
                detail,
            },
        );
        // JSON parsing does not provide source spans. Omit the line instead of
        // guessing, and never include private fields in the displayed snippet.
        finding.location.snippet = Some(format!("JWK {kind} private key [redacted]"));
        findings.push(finding);
    }
    findings
}

fn jwk_rsa_modulus_bits(modulus: &str) -> Option<u32> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(modulus.trim_end_matches('='))
        .ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(integer_bit_length(&bytes))
}

fn decode_pem_body(body_lines: &[&str]) -> Option<Vec<u8>> {
    let b64: String = body_lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .collect();
    if b64.is_empty() || b64.contains("...") {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Decode PKCS#1 RSAPrivateKey PEM body and return modulus bit length.
fn rsa_pkcs1_modulus_bits(body_lines: &[&str]) -> Option<u32> {
    der_rsa_modulus_bits(&decode_pem_body(body_lines)?)
}

/// PKCS#8 PrivateKeyInfo wrapping an RSA private key (OID 1.2.840.113549.1.1.1).
fn pkcs8_rsa_modulus_bits(body_lines: &[&str]) -> Option<u32> {
    let der = decode_pem_body(body_lines)?;
    // rsaEncryption OID
    const RSA_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let oid_pos = der.windows(RSA_OID.len()).position(|w| w == RSA_OID)?;
    let mut i = oid_pos + RSA_OID.len();
    // Optional NULL parameters.
    if der.get(i..i + 2) == Some(&[0x05, 0x00]) {
        i += 2;
    }
    // OCTET STRING wrapping RSAPrivateKey.
    if *der.get(i)? != 0x04 {
        return None;
    }
    i += 1;
    let (len, next) = der_read_len(&der, i)?;
    let rsa_der = der.get(next..next + len)?;
    der_rsa_modulus_bits(rsa_der)
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
    fn extracts_pkcs8_rsa_2048_bit_size() {
        let pem = include_str!("../../tests/fixtures/positive/secrets/rsa2048-pkcs8.key");
        let path = PathBuf::from("secrets/rsa2048-pkcs8.key");
        let findings = SecretsEngine.scan(&path, pem.as_bytes());
        assert_eq!(findings[0].rule_id, "SNOOT010");
        assert!(
            findings[0].evidence.detail.contains("2048-bit"),
            "{}",
            findings[0].evidence.detail
        );
        assert!(findings[0].title.contains("RSA-2048"));
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

    #[test]
    fn changed_pem_body_changes_fingerprint_without_exposing_payload() {
        let first = "-----BEGIN RSA PRIVATE KEY-----\nQUJDREVGRw==\n-----END RSA PRIVATE KEY-----";
        let second = first.replace("QUJDREVGRw==", "SElKS0xNTg==");
        let a = SecretsEngine.scan(Path::new("secret.pem"), first.as_bytes());
        let b = SecretsEngine.scan(Path::new("secret.pem"), second.as_bytes());
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_ne!(a[0].fingerprint, b[0].fingerprint);
        assert!(!serde_json::to_string(&a).unwrap().contains("QUJDREVGRw=="));
    }

    #[test]
    fn jwk_fields_must_belong_to_the_same_key_and_payloads_stay_redacted() {
        let unrelated = br#"{"keys":[{"kty":"RSA","n":"gA"},{"d":"SECRET"}]}"#;
        assert!(SecretsEngine
            .scan(Path::new("keys.jwk"), unrelated)
            .is_empty());
        let first = br#"{"kty":"RSA","n":"gA","d":"SECRET"}"#;
        let second = br#"{"kty":"RSA","n":"gA","d":"CHANGED"}"#;
        let a = SecretsEngine.scan(Path::new("keys.jwk"), first);
        let b = SecretsEngine.scan(Path::new("keys.jwk"), second);
        assert_eq!(a.len(), 1);
        assert_ne!(a[0].fingerprint, b[0].fingerprint);
        assert!(!serde_json::to_string(&a).unwrap().contains("SECRET"));
        assert_eq!(jwk_rsa_modulus_bits("gA"), Some(8));
        assert_eq!(jwk_rsa_modulus_bits("AQ"), Some(1));
    }
}
