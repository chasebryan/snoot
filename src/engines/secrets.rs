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
//! **Status**: week-3 milestone. File matching is real; PEM/DER/JWK parsing
//! lands in week 3.

use std::path::Path;

use crate::engines::Engine;
use crate::model::Finding;

pub struct SecretsEngine;

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

    fn scan(&self, _path: &Path, _content: &[u8]) -> Vec<Finding> {
        // Week 3: scan for PEM armor boundaries, parse DER with a real ASN.1
        // parser, detect JWK objects, extract (algorithm, key size, private?).
        // Emits SNOOT003 for classical private keys; info-level inventory
        // findings for public keys / certs (CBOM feed).
        Vec::new()
    }
}
