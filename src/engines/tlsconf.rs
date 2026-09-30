//! TLS-config engine: TLS configuration string scanning.
//!
//! **Job** (DESIGN.md §5): find TLS configurations — nginx
//! `ssl_protocols` / `ssl_ciphers`, Apache `SSLProtocol` /
//! `SSLCipherSuite`, Caddyfile `tls` blocks, openssl.cnf `MinProtocol` /
//! `CipherString` — and flag:
//!
//! - SNOOT018: protocols below TLS 1.2 explicitly enabled (SSLv2/SSLv3/
//!   TLS 1.0/TLS 1.1). Explicit *disables* (`-SSLv3`) are honored — an
//!   admin who turned the weak protocols off gets no finding.
//! - SNOOT019: cipher strings enabling RC4, (3)DES, export, NULL,
//!   anonymous, or MD5-based suites.
//! - SNOOT005: TLS configured with no hybrid post-quantum key-exchange
//!   group (X25519MLKEM768 and friends) anywhere in the file.
//!
//! Line-based directive parsing, no full config grammar — v1 recognizes the
//! common directive shapes across servers.
//!
//! **Status**: week-3 milestone, implemented.

use std::collections::HashSet;
use std::path::Path;

use crate::engines::Engine;
use crate::model::{Evidence, Finding};
use crate::rules::RuleRegistry;

pub struct TlsConfEngine;

/// Protocol directives, longest first (so `ssl_protocols` wins over the
/// generic `protocols` fallback used for Caddyfiles).
const PROTOCOL_DIRECTIVES: &[&str] = &["ssl_protocols", "sslprotocol", "minprotocol", "protocols"];
const CIPHER_DIRECTIVES: &[&str] = &["ssl_ciphers", "sslciphersuite", "cipherstring", "ciphers"];

/// Tokens that indicate a hybrid PQC key-exchange group is configured.
const HYBRID_TOKENS: &[&str] = &[
    "x25519mlkem768",
    "mlkem768",
    "ml-kem",
    "mlkem",
    "x25519kyber768",
    "kyber",
    "hybrid",
];

/// If `line` (lowercased, trimmed) is one of the named directives, return
/// the value part. Matches `name value`, `name = value`, `name: value`.
fn directive_value<'a>(line: &'a str, names: &[&str]) -> Option<&'a str> {
    for name in names {
        let Some(rest) = line.strip_prefix(name) else {
            continue;
        };
        match rest.chars().next() {
            Some(c) if c.is_whitespace() || c == '=' || c == ':' => {
                let value = rest
                    .trim_start_matches(|c: char| c.is_whitespace() || c == '=' || c == ':')
                    .trim()
                    .trim_end_matches(';')
                    .trim();
                if !value.is_empty() {
                    return Some(value);
                }
            }
            _ => continue,
        }
    }
    None
}

/// True when a cipher-suite token (uppercased) is classically weak.
fn weak_suite(suite: &str) -> bool {
    let s = suite.to_ascii_uppercase();
    s.contains("RC4")
        || s.contains("DES") // DES-CBC-*, DES-EDE3-*, *3DES*
        || s.starts_with("EXP")
        || s.contains("EXPORT")
        || s.contains("NULL")
        || s.starts_with("ADH")
        || s.starts_with("AECDH")
        || s.contains("ANON")
        || s.contains("MD5")
}

fn push_finding(
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
    rule_id: &str,
    path: &Path,
    line: Option<u32>,
    snippet: &str,
    detail: String,
) {
    let Some(rule) = RuleRegistry::by_id(rule_id) else {
        return;
    };
    let snippet: String = snippet.trim().chars().take(160).collect();
    let finding = Finding::new(
        &rule,
        path.to_string_lossy(),
        line,
        Some(snippet),
        Evidence {
            kind: "tls_config".to_string(),
            detail,
        },
    );
    if seen.insert(finding.fingerprint.clone()) {
        findings.push(finding);
    }
}

impl Engine for TlsConfEngine {
    fn name(&self) -> &'static str {
        "tlsconf"
    }

    fn file_matches(&self, path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_ascii_lowercase();
            if lower == "caddyfile"
                || lower.contains("nginx")
                || lower.contains("apache")
                || lower.contains("ssl")
                || lower.contains("tls")
            {
                return true;
            }
        }
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("conf" | "cnf" | "cfg" | "ini")
        )
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding> {
        let text = String::from_utf8_lossy(content);
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let mut saw_tls = false;
        let mut saw_hybrid = false;
        let mut first_tls: Option<(u32, String)> = None;

        for (i, raw) in text.lines().enumerate() {
            let line_no = i as u32 + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let low = line.to_ascii_lowercase();
            if HYBRID_TOKENS.iter().any(|t| low.contains(t)) {
                saw_hybrid = true;
            }

            if let Some(value) = directive_value(&low, PROTOCOL_DIRECTIVES) {
                saw_tls = true;
                if first_tls.is_none() {
                    first_tls = Some((line_no, line.to_string()));
                }
                for tok in value
                    .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let negated = tok.starts_with('-');
                    let bare = tok.trim_start_matches(['-', '+']).trim_end_matches(';');
                    if matches!(bare, "sslv2" | "sslv3" | "tlsv1" | "tlsv1.0" | "tlsv1.1")
                        && !negated
                    {
                        push_finding(
                            &mut findings,
                            &mut seen,
                            "SNOOT018",
                            path,
                            Some(line_no),
                            line,
                            format!("weak TLS protocol enabled: {tok}"),
                        );
                    }
                }
            }

            if let Some(value) = directive_value(&low, CIPHER_DIRECTIVES) {
                saw_tls = true;
                if first_tls.is_none() {
                    first_tls = Some((line_no, line.to_string()));
                }
                for suite in value
                    .split(|c: char| c == ':' || c == ',' || c == ';' || c.is_whitespace())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    if weak_suite(suite) {
                        push_finding(
                            &mut findings,
                            &mut seen,
                            "SNOOT019",
                            path,
                            Some(line_no),
                            line,
                            format!("weak cipher suite enabled: {suite}"),
                        );
                    }
                }
            }
        }

        // TLS is configured but nothing negotiates a hybrid PQC group.
        if saw_tls && !saw_hybrid {
            let (line, snippet) = match &first_tls {
                Some((n, s)) => (Some(*n), s.clone()),
                None => (None, String::new()),
            };
            push_finding(
                &mut findings,
                &mut seen,
                "SNOOT005",
                path,
                line,
                &snippet,
                "TLS configured without a hybrid post-quantum key-exchange group".to_string(),
            );
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(path: &str, content: &str) -> Vec<Finding> {
        TlsConfEngine.scan(Path::new(path), content.as_bytes())
    }

    fn rule_ids(findings: &[Finding]) -> HashSet<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn nginx_weak_config_flags_everything() {
        let findings = scan(
            "nginx.conf",
            "server {\n    listen 443 ssl;\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n    ssl_ciphers RC4-SHA:DES-CBC3-SHA:AES128-SHA;\n}\n",
        );
        let ids = rule_ids(&findings);
        assert!(ids.contains("SNOOT018"), "missing weak-protocol: {ids:?}");
        assert!(ids.contains("SNOOT019"), "missing weak-cipher: {ids:?}");
        assert!(ids.contains("SNOOT005"), "missing no-hybrid: {ids:?}");
        // Two weak protocols → two SNOOT018 findings, distinct fingerprints.
        assert_eq!(
            findings.iter().filter(|f| f.rule_id == "SNOOT018").count(),
            2
        );
        let proto = findings.iter().find(|f| f.rule_id == "SNOOT018").unwrap();
        assert_eq!(proto.location.line, Some(3));
        assert_eq!(proto.severity, crate::model::Severity::High);
    }

    #[test]
    fn nginx_good_config_is_clean() {
        let findings = scan(
            "nginx.conf",
            "server {\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;\n    ssl_groups X25519MLKEM768:X25519;\n}\n",
        );
        assert!(findings.is_empty(), "unexpected: {findings:?}");
    }

    #[test]
    fn apache_explicit_disables_are_honored() {
        // Admin turned the weak protocols off: no SNOOT018, but still no
        // hybrid group → SNOOT005 only.
        let findings = scan(
            "apache.conf",
            "SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256\n",
        );
        let ids = rule_ids(&findings);
        assert!(
            !ids.contains("SNOOT018"),
            "negated protocols flagged: {ids:?}"
        );
        assert!(!ids.contains("SNOOT019"), "clean ciphers flagged: {ids:?}");
        assert!(ids.contains("SNOOT005"), "missing no-hybrid: {ids:?}");
    }

    #[test]
    fn openssl_cnf_shapes() {
        let findings = scan(
            "openssl.cnf",
            "[system_default_sect]\nCipherString = DEFAULT@SECLEVEL=2\nMinProtocol = TLSv1.1\n",
        );
        let ids = rule_ids(&findings);
        assert!(
            ids.contains("SNOOT018"),
            "missing weak MinProtocol: {ids:?}"
        );
        assert!(!ids.contains("SNOOT019"), "SECLEVEL=2 flagged: {ids:?}");
    }

    #[test]
    fn files_without_tls_directives_are_silent() {
        assert!(scan("app.conf", "port = 8080\nworkers = 4\n").is_empty());
        assert!(scan("notes.conf", "# nothing here\n").is_empty());
    }

    #[test]
    fn file_matching_covers_config_names() {
        let engine = TlsConfEngine;
        for p in [
            "nginx.conf",
            "Caddyfile",
            "ssl.conf",
            "apache2.cfg",
            "openssl.cnf",
        ] {
            assert!(engine.file_matches(Path::new(p)), "no match: {p}");
        }
        assert!(!engine.file_matches(Path::new("main.rs")));
    }
}
