//! Code engine: tree-sitter based API-call detection, per language.
//!
//! **Job** (DESIGN.md §5): parse each source file with the tree-sitter grammar
//! for its language, run the per-language queries attached to each rule in
//! [`crate::rules::RuleRegistry`], and emit a finding per match.
//!
//! **Status**: week-2. All v1 languages are wired (Rust, Python, Go,
//! JavaScript, TypeScript, Java, C, C++).

use std::path::Path;

use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

use crate::engines::Engine;
use crate::model::{Evidence, Finding};
use crate::rules::RuleRegistry;

pub struct CodeEngine;

impl Engine for CodeEngine {
    fn name(&self) -> &'static str {
        "code"
    }

    fn file_matches(&self, path: &Path) -> bool {
        language_id(path).is_some()
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding> {
        let Some(language) = language_id(path) else {
            return Vec::new();
        };
        let Some(ts_language) = ts_language(language) else {
            return Vec::new();
        };

        let mut parser = Parser::new();
        if parser.set_language(&ts_language).is_err() {
            return Vec::new();
        }
        let Some(tree) = parser.parse(content, None) else {
            return Vec::new();
        };

        let path_str = path_string(path);
        let mut findings = Vec::new();

        for rule in RuleRegistry::all() {
            for lq in rule.queries.iter().filter(|q| q.language == language) {
                let query = match Query::new(&ts_language, &lq.query) {
                    Ok(q) => q,
                    Err(_) => continue,
                };
                let mut cursor = QueryCursor::new();
                let mut matches = cursor.matches(&query, tree.root_node(), content);
                while let Some(m) = matches.next() {
                    let Some(capture) = m.captures.first() else {
                        continue;
                    };
                    let node = capture.node;
                    let line = (node.start_position().row + 1) as u32;
                    let snippet = snippet_for(node, content);
                    findings.push(Finding::new(
                        &rule,
                        path_str.clone(),
                        Some(line),
                        Some(snippet.clone()),
                        Evidence {
                            kind: "api_call".to_string(),
                            detail: snippet,
                        },
                    ));
                }
            }
        }

        findings
    }
}

fn language_id(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => Some("rust"),
        Some("py") => Some("python"),
        Some("go") => Some("go"),
        Some("js" | "jsx" | "mjs" | "cjs") => Some("javascript"),
        Some("ts" | "tsx") => Some("typescript"),
        Some("java") => Some("java"),
        Some("c" | "h") => Some("c"),
        Some("cpp" | "hpp" | "cc" | "cxx") => Some("cpp"),
        _ => None,
    }
}

fn ts_language(language: &str) -> Option<tree_sitter::Language> {
    match language {
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        _ => None,
    }
}

#[allow(dead_code)]
fn parser_for(language: &str) -> Option<Parser> {
    let ts_language = ts_language(language)?;
    let mut parser = Parser::new();
    parser.set_language(&ts_language).ok()?;
    Some(parser)
}

fn snippet_for(node: tree_sitter::Node<'_>, content: &[u8]) -> String {
    let mut cur = node;
    let mut chosen = node;
    while let Some(parent) = cur.parent() {
        match parent.kind() {
            "call_expression" | "call" | "method_invocation" => {
                chosen = parent;
                break;
            }
            _ => cur = parent,
        }
    }
    let text = chosen
        .utf8_text(content)
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    truncate(&text, 120)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let trimmed: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{trimmed}…")
    }
}

#[allow(dead_code)]
pub fn supported_languages() -> &'static [&'static str] {
    live_languages()
}

#[allow(dead_code)]
pub fn live_languages() -> &'static [&'static str] {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_rust_rsa_generate() {
        let path = PathBuf::from("src/keys.rs");
        let src = b"fn make() { let _k = Rsa::generate(&mut rng, 2048); }\n";
        let findings = CodeEngine.scan(&path, src);
        assert!(
            findings.iter().any(|f| f.rule_id == "SNOOT001"),
            "expected SNOOT001, got: {findings:?}"
        );
    }

    #[test]
    fn detects_go_rsa_generate() {
        let path = PathBuf::from("keys.go");
        let src = b"package main\nfunc f() { rsa.GenerateKey(rand.Reader, 2048) }\n";
        let findings = CodeEngine.scan(&path, src);
        assert!(
            findings.iter().any(|f| f.rule_id == "SNOOT001"),
            "expected SNOOT001, got: {findings:?}"
        );
    }

    #[test]
    fn detects_js_create_sign() {
        let path = PathBuf::from("sign.js");
        let src = b"const s = crypto.createSign('RSA-SHA256');\n";
        let findings = CodeEngine.scan(&path, src);
        assert!(
            findings.iter().any(|f| f.rule_id == "SNOOT008"),
            "expected SNOOT008, got: {findings:?}"
        );
    }

    #[test]
    fn detects_c_rsa_generate() {
        let path = PathBuf::from("keys.c");
        let src = b"void f() { RSA_generate_key_ex(rsa, 2048, e, NULL); }\n";
        let findings = CodeEngine.scan(&path, src);
        assert!(
            findings.iter().any(|f| f.rule_id == "SNOOT001"),
            "expected SNOOT001, got: {findings:?}"
        );
    }

    #[test]
    fn ignores_rsa_in_comments_and_strings() {
        let path = PathBuf::from("src/noise.rs");
        let src = br#"
// Rsa::generate is mentioned in a comment only
fn docs() {
    let _s = "Rsa::generate(&mut rng, 2048)";
}
"#;
        let findings = CodeEngine.scan(&path, src);
        assert!(
            findings.is_empty(),
            "comment/string should not match, got: {findings:?}"
        );
    }

    #[test]
    fn live_languages_are_wired() {
        for lang in live_languages() {
            assert!(ts_language(lang).is_some(), "missing grammar for {lang}");
        }
    }
}
