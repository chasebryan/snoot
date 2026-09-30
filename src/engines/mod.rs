//! Detection engines: one per finding source.
//!
//! Each engine owns a slice of the detection problem and exposes the same
//! [`Engine`] interface, so the scanner in `scanner.rs` stays dumb:
//!
//! - [`code`] — tree-sitter AST queries over source files (API-call detection)
//! - [`secrets`] — PEM / DER / JWK / key-material scanning + key-size extraction
//! - [`manifest`] — dependency manifests (Cargo.toml, package.json, go.mod, …)
//! - [`tlsconf`] — TLS configuration strings (protocol versions, cipher suites)
//!
//! Week 2: code engine covers all v1 languages; secrets detects PEM armor;
//! TLS config flags classical-only configs; manifest engine flags known
//! classical-crypto direct dependencies.

pub mod code;
pub mod manifest;
pub mod secrets;
pub mod tlsconf;

pub use code::CodeEngine;
pub use manifest::ManifestEngine;
pub use secrets::SecretsEngine;
pub use tlsconf::TlsConfEngine;

use std::path::Path;

use crate::model::Finding;

/// A detection engine: decides which files are in scope and scans them.
pub trait Engine {
    /// Short engine name for diagnostics, e.g. "code".
    // Week-1 API surface: used in scan diagnostics starting week 2.
    #[allow(dead_code)]
    fn name(&self) -> &'static str;

    /// Cheap pre-filter: is this file worth reading for this engine?
    fn file_matches(&self, path: &Path) -> bool;

    /// Scan one file's bytes; return zero or more findings.
    /// `path` is relative to the scan root, for portable finding fingerprints.
    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding>;
}
