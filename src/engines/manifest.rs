//! Manifest engine: dependency-manifest scanning.
//!
//! Flags direct dependencies known to pull in classical public-key crypto.
//! v1 covers direct manifests only (DESIGN.md §3). No network calls — the
//! package table ships in the binary.
//!
//! **Status**: week-2/3 partial. Table-driven matching for Cargo.toml,
//! package.json, go.mod, and requirements.txt / pyproject.toml. Version-range
//! reasoning and lockfile walks come later.

use std::path::Path;

use crate::engines::Engine;
use crate::model::{Evidence, Finding, Severity};
use crate::rules::RuleRegistry;

pub struct ManifestEngine;

const MANIFEST_FILES: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "go.mod",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "pom.xml",
    "Gemfile",
    "composer.json",
];

/// Known classical-crypto packages → short note for evidence.
/// Package names must be unique; matching is ecosystem-aware via file type.
const CLASSICAL_PACKAGES: &[(&str, &str)] = &[
    // Shared short names (Rust crates / Python packages / etc.)
    ("rsa", "classical RSA library"),
    ("ecdsa", "classical ECDSA library"),
    ("p256", "ECDSA/ECDH P-256"),
    ("p384", "ECDSA/ECDH P-384"),
    ("x25519-dalek", "X25519 key exchange"),
    ("ed25519-dalek", "Ed25519 signatures (inventory)"),
    ("openssl", "OpenSSL bindings — classical defaults"),
    ("ring", "ring — classical RSA/ECDSA/ECDH"),
    ("rustls", "rustls — classical TLS without PQC"),
    // JS
    ("node-forge", "node-forge — classical RSA/ECDSA"),
    ("node-rsa", "node-rsa — classical RSA"),
    ("jsrsasign", "jsrsasign — classical RSA/ECDSA"),
    ("crypto-js", "crypto-js — legacy crypto helpers"),
    // Python-specific names
    ("pycryptodome", "PyCryptodome — classical RSA/ECDSA/DSA"),
    ("pycrypto", "PyCrypto — classical RSA/DSA (unmaintained)"),
    (
        "cryptography",
        "cryptography — classical public-key APIs common",
    ),
    // Go module paths
    ("golang.org/x/crypto", "x/crypto — classical helpers"),
];

impl Engine for ManifestEngine {
    fn name(&self) -> &'static str {
        "manifest"
    }

    fn file_matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| MANIFEST_FILES.contains(&n))
            .unwrap_or(false)
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding> {
        let Ok(text) = std::str::from_utf8(content) else {
            return Vec::new();
        };
        let Some(rule) = RuleRegistry::by_id("SNOOT016") else {
            return Vec::new();
        };

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let path_str = path.to_string_lossy().replace('\\', "/");
        let mut findings = Vec::new();

        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            // Skip Cargo.toml [package] name = "rsa" style by requiring dep syntax.
            if !looks_like_dependency_line(file_name, trimmed) {
                continue;
            }
            for (pkg, note) in CLASSICAL_PACKAGES {
                if line_mentions_package(file_name, trimmed, pkg) {
                    // Ed25519 deps are inventory-only — remap severity via rule
                    // title; SNOOT016 is medium for classical. For ed25519 use
                    // info by skipping? Keep medium for all table hits; Ed25519
                    // crate still indicates crypto surface.
                    let snippet = trimmed.to_string();
                    let mut finding = Finding::new(
                        &rule,
                        path_str.clone(),
                        Some((idx + 1) as u32),
                        Some(snippet),
                        Evidence {
                            kind: "manifest_dep".to_string(),
                            detail: note.to_string(),
                        },
                    );
                    // Soften pure Ed25519 inventory hits.
                    if *pkg == "ed25519-dalek" {
                        finding.severity = Severity::Info;
                        finding.title = "Ed25519 dependency (inventory)".to_string();
                    }
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

fn looks_like_dependency_line(file_name: &str, line: &str) -> bool {
    match file_name {
        "Cargo.toml" => {
            // dep = "version" or dep = { ... } — not [section] headers.
            !line.starts_with('[') && line.contains('=')
        }
        "package.json" => line.contains('"') && (line.contains(':') || line.contains(':')),
        "go.mod" => {
            line.starts_with("require ")
                || line.starts_with("\t")
                || (!line.starts_with("module ")
                    && !line.starts_with("go ")
                    && line.split_whitespace().count() >= 2)
        }
        "requirements.txt" | "Pipfile" => true,
        "pyproject.toml" => line.contains('=') || line.contains('"'),
        "pom.xml" => line.contains("<artifactId>") || line.contains("<groupId>"),
        "Gemfile" | "composer.json" => true,
        _ => true,
    }
}

fn line_mentions_package(file_name: &str, line: &str, pkg: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let pkg_l = pkg.to_ascii_lowercase();
    match file_name {
        "Cargo.toml" => {
            // Match `pkg =` or `"pkg" =` at start of dep key.
            let key = lower
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            key == pkg_l
        }
        "package.json" => {
            // "pkg": "version"
            lower.contains(&format!("\"{pkg_l}\""))
        }
        "go.mod" => lower.contains(&pkg_l),
        "requirements.txt" => {
            let name = lower
                .split(&['=', '>', '<', '!', '~', ' ', ';'][..])
                .next()
                .unwrap_or("");
            name == pkg_l || name.starts_with(&format!("{pkg_l}["))
        }
        "pyproject.toml" | "Pipfile" => {
            let key = lower
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            key == pkg_l || lower.contains(&format!("\"{pkg_l}\""))
        }
        _ => lower.contains(&pkg_l),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn flags_cargo_rsa_dep() {
        let path = PathBuf::from("Cargo.toml");
        let src = b"[dependencies]\nrsa = \"0.9\"\nserde = \"1\"\n";
        let findings = ManifestEngine.scan(&path, src);
        assert!(
            findings.iter().any(|f| f.rule_id == "SNOOT016"),
            "{findings:?}"
        );
    }

    #[test]
    fn ignores_non_dep_mention() {
        let path = PathBuf::from("Cargo.toml");
        let src = b"[package]\nname = \"rsa\"\nversion = \"0.1.0\"\n";
        let findings = ManifestEngine.scan(&path, src);
        assert!(findings.is_empty(), "{findings:?}");
    }
}
