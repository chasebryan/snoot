//! TLS-config engine: TLS configuration string scanning.
//!
//! **Job** (DESIGN.md §5): find TLS configurations — nginx
//! `ssl_protocols` / `ssl_ciphers`, Apache `SSLProtocol` /
//! `SSLCipherSuite`, Caddyfile `tls` blocks, language-level TLS setup
//! (`ssl.SSLContext`, `tls.Config`, `SSL_CTX_new`) — and flag configurations
//! that negotiate classical-only key exchange with no hybrid post-quantum
//! group (e.g. X25519+ML-KEM-768, `X25519MLKEM768`).
//!
//! This is where SNOOT005 lives. The engine understands "this config pins
//! TLS 1.2 with ECDHE-only ciphers" as a medium finding with a concrete
//! remediation (enable the hybrid group), not just a version string.
//!
//! **Status**: week-3 milestone. File matching is real; config-shape
//! recognition lands in week 3.

use std::path::Path;

use crate::engines::Engine;
use crate::model::Finding;

pub struct TlsConfEngine;

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

    fn scan(&self, _path: &Path, _content: &[u8]) -> Vec<Finding> {
        // Week 3: recognize server blocks / virtual hosts, extract protocol
        // and cipher-suite directives, check for hybrid PQC groups
        // (X25519MLKEM768 and friends). Emits SNOOT005 for classical-only
        // configs; info findings for the CBOM inventory otherwise.
        Vec::new()
    }
}
