//! TLS-config engine: TLS configuration string scanning.
//!
//! Flags configs that speak TLS but never mention a hybrid PQC group
//! (`X25519MLKEM768`, `SecP256r1MLKEM768`, etc.). Heuristic: presence of TLS
//! protocol/cipher/curve directives without a known hybrid token → SNOOT005.
//!
//! **Status**: week-2 partial (DESIGN listed week 3). Covers nginx/Apache-
//! style directives and common filenames; deeper virtual-host parsing later.

use std::path::Path;

use crate::engines::Engine;
use crate::model::{Evidence, Finding};
use crate::rules::RuleRegistry;

pub struct TlsConfEngine;

/// Tokens that indicate a hybrid PQC key-exchange group is configured.
const HYBRID_TOKENS: &[&str] = &[
    "x25519mlkem768",
    "secp256r1mlkem768",
    "secp384r1mlkem1024",
    "x25519kyber768",
    "mlkem768",
    "ml-kem",
    "mlkem",
    "kyber768",
    "kyber1024",
];

/// Directives / keywords that mean "this file configures TLS".
const TLS_MARKERS: &[&str] = &[
    "ssl_protocols",
    "ssl_ciphers",
    "ssl_ecdh_curve",
    "ssl_conf_command",
    "sslprotocol",
    "sslciphersuite",
    "sslengine",
    "tls1.2",
    "tls1.3",
    "tlsv1.2",
    "tlsv1.3",
    "curves =",
    "curvelist",
];

impl Engine for TlsConfEngine {
    fn name(&self) -> &'static str {
        "tlsconf"
    }

    fn file_matches(&self, path: &Path) -> bool {
        let ext = path.extension().and_then(|e| e.to_str());
        let is_config_ext = matches!(ext, Some("conf" | "cnf" | "cfg" | "ini" | "yml" | "yaml"));
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_ascii_lowercase();
            if lower == "caddyfile" {
                return true;
            }
            // Name hints only count for config-like files — never for
            // `tlsconf.rs` / `ssl.rs` source that merely implements detection.
            if is_config_ext
                && (lower.contains("nginx")
                    || lower.contains("apache")
                    || lower.contains("httpd")
                    || lower.contains("ssl")
                    || lower.contains("tls"))
            {
                return true;
            }
        }
        matches!(ext, Some("conf" | "cnf" | "cfg" | "ini"))
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding> {
        let Ok(text) = std::str::from_utf8(content) else {
            return Vec::new();
        };
        let lower = text.to_ascii_lowercase();

        let has_tls = TLS_MARKERS.iter().any(|m| lower.contains(m));
        if !has_tls {
            return Vec::new();
        }
        let has_hybrid = HYBRID_TOKENS.iter().any(|t| lower.contains(t));
        if has_hybrid {
            return Vec::new();
        }

        let Some(rule) = RuleRegistry::by_id("SNOOT005") else {
            return Vec::new();
        };

        // Point at the first TLS marker line for a useful location.
        let mut line_no = None;
        let mut snippet = None;
        for (idx, line) in text.lines().enumerate() {
            let l = line.to_ascii_lowercase();
            if TLS_MARKERS.iter().any(|m| l.contains(m)) {
                line_no = Some((idx + 1) as u32);
                snippet = Some(line.trim().to_string());
                break;
            }
        }

        let path_str = path.to_string_lossy().replace('\\', "/");
        vec![Finding::new(
            &rule,
            path_str,
            line_no,
            snippet,
            Evidence {
                kind: "tls_config".to_string(),
                detail: "TLS config present with no hybrid PQC group token".to_string(),
            },
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn flags_classical_nginx_tls() {
        let path = PathBuf::from("nginx-ssl.conf");
        let src = b"server {\n  ssl_protocols TLSv1.2 TLSv1.3;\n  ssl_ciphers HIGH:!aNULL;\n}\n";
        let findings = TlsConfEngine.scan(&path, src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT005");
    }

    #[test]
    fn allows_hybrid_group() {
        let path = PathBuf::from("nginx-ssl.conf");
        let src = b"ssl_protocols TLSv1.3;\nssl_conf_command Groups X25519MLKEM768:X25519;\n";
        let findings = TlsConfEngine.scan(&path, src);
        assert!(findings.is_empty());
    }
}
