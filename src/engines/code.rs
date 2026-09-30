//! Code engine: tree-sitter based API-call detection, per language.
//!
//! **Job** (DESIGN.md §5): parse each source file with the tree-sitter grammar
//! for its language, run the per-language queries attached to each rule in
//! [`crate::rules::RuleRegistry`], and emit a finding per match — e.g.
//! `Rsa::generate` (Rust), `Crypto.PublicKey.RSA.generate` (Python),
//! `rsa.GenerateKey` (Go), `crypto.createSign` (Node), `KeyPairGenerator`
//! (Java), `RSA_generate_key` (OpenSSL C).
//!
//! AST queries catch API usage precisely where regexes drown in false
//! positives (comments, string literals, similarly-named locals). Rules stay
//! data: adding a language means adding query strings in `rules.rs`, not new
//! control flow here.
//!
//! **Status**: week-2 milestone. File matching and the tree-sitter wiring
//! below are real; query execution lands with the remaining grammars.

use std::path::Path;

use crate::engines::Engine;
use crate::model::Finding;

pub struct CodeEngine;

impl Engine for CodeEngine {
    fn name(&self) -> &'static str {
        "code"
    }

    fn file_matches(&self, path: &Path) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(
                "rs" | "py"
                    | "go"
                    | "js"
                    | "jsx"
                    | "ts"
                    | "tsx"
                    | "mjs"
                    | "cjs"
                    | "java"
                    | "c"
                    | "h"
                    | "cpp"
                    | "hpp"
                    | "cc"
                    | "cxx"
            )
        )
    }

    fn scan(&self, _path: &Path, _content: &[u8]) -> Vec<Finding> {
        // Week 2: parse with `parser_for`, run each rule's queries for the
        // file's language, map captures to findings. Returns no findings yet.
        Vec::new()
    }
}

/// tree-sitter [`Parser`](tree_sitter::Parser) for a supported v1 language.
///
/// This proves the grammar-crate wiring at compile time; week 2 adds the
/// remaining grammars (see commented deps in Cargo.toml) and the query loop.
#[allow(dead_code)]
fn parser_for(language: &str) -> Option<tree_sitter::Parser> {
    let ts_language = match language {
        "rust" => tree_sitter_rust::LANGUAGE,
        "python" => tree_sitter_python::LANGUAGE,
        _ => return None, // week 2: go, javascript, typescript, java, c, cpp
    };
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_language.into()).ok()?;
    Some(parser)
}

/// Languages covered in v1 (DESIGN.md §7).
// Week-1 API surface: consumed by the code engine starting week 2.
#[allow(dead_code)]
pub fn supported_languages() -> &'static [&'static str] {
    &[
        "rust",
        "python",
        "go",
        "javascript",
        "typescript",
        "java",
        "c",
        "cpp",
    ]
}
