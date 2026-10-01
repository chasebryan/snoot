//! Code engine: tree-sitter based API-call detection, per language.
//!
//! **Job** (DESIGN.md §5): parse each source file with the tree-sitter grammar
//! for its language, run the per-language queries attached to each rule in
//! [`crate::rules::RuleRegistry`], and emit a finding per match — e.g.
//! `RsaPrivateKey::new` (Rust), `Crypto.PublicKey.RSA.generate` (Python),
//! `rsa.GenerateKey` (Go), `crypto.generateKeyPairSync('rsa', …)` (Node),
//! `KeyPairGenerator.getInstance("RSA")` (Java).
//!
//! AST queries catch API usage precisely where regexes drown in false
//! positives (comments, string literals, similarly-named locals). Rules stay
//! data: adding a language means adding query strings in `rules.rs`, not new
//! control flow here.
//!
//! TypeScript is a syntactic superset of JavaScript for the API-call shapes
//! we match, so `javascript`-tagged queries also run against `typescript`
//! and `tsx` files — compiled against the TS/TSX grammar, not the JS one
//! (see [`query_languages`]).
//!
//! **Status**: week 2 — implemented. Queries are compiled once per process
//! (see [`compiled`]); a bad query is skipped at runtime but fails the
//! `all_registry_queries_compile` test, so CI catches it.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use tree_sitter::StreamingIterator;

use crate::engines::Engine;
use crate::model::{Evidence, Finding};
use crate::rules::RuleRegistry;

pub struct CodeEngine;

/// File languages with a wired tree-sitter grammar.
const FILE_LANGUAGES: &[&str] = &[
    "rust",
    "python",
    "go",
    "javascript",
    "typescript",
    "tsx",
    "java",
    "c",
    "cpp",
];

/// Map a file extension to a tree-sitter language name.
fn language_for_extension(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "rs" => "rust",
        "py" => "python",
        "go" => "go",
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "ts" | "mts" | "cts" => "typescript",
        "tsx" => "tsx",
        "java" => "java",
        "c" | "h" => "c",
        "cpp" | "hpp" | "cc" | "cxx" => "cpp",
        _ => return None,
    })
}

/// The tree-sitter [`tree_sitter::Language`] for a language name, if we ship
/// its grammar.
fn ts_language(language: &str) -> Option<tree_sitter::Language> {
    let func = match language {
        "rust" => tree_sitter_rust::LANGUAGE,
        "python" => tree_sitter_python::LANGUAGE,
        "go" => tree_sitter_go::LANGUAGE,
        "javascript" => tree_sitter_javascript::LANGUAGE,
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX,
        "java" => tree_sitter_java::LANGUAGE,
        "c" => tree_sitter_c::LANGUAGE,
        "cpp" => tree_sitter_cpp::LANGUAGE,
        _ => return None,
    };
    Some(func.into())
}

/// Rule-query languages that apply to a file of the given language.
///
/// TypeScript/TSX files run `typescript`- (or `tsx`-) tagged queries plus the
/// `javascript`-tagged ones; every other language runs only its own.
fn query_languages(file_language: &'static str) -> Vec<&'static str> {
    match file_language {
        "typescript" => vec!["typescript", "javascript"],
        "tsx" => vec!["tsx", "typescript", "javascript"],
        "cpp" => vec!["cpp", "c"],
        other => vec![other],
    }
}

/// One rule's queries, compiled against one file-language grammar.
struct CompiledQuery {
    rule_index: usize,
    query: tree_sitter::Query,
}

struct CompiledLanguage {
    language: &'static str,
    queries: Vec<CompiledQuery>,
}

/// All registry queries, compiled once per process against every grammar
/// they can run against. A query that fails to compile is skipped here (with
/// a stderr note) but fails `all_registry_queries_compile` in CI.
static COMPILED: OnceLock<Vec<CompiledLanguage>> = OnceLock::new();

fn compiled() -> &'static Vec<CompiledLanguage> {
    COMPILED.get_or_init(|| {
        let rules = RuleRegistry::all();
        let mut out = Vec::new();
        for &file_lang in FILE_LANGUAGES {
            let Some(ts_lang) = ts_language(file_lang) else {
                continue;
            };
            let mut queries = Vec::new();
            for (i, rule) in rules.iter().enumerate() {
                for lq in &rule.queries {
                    if !query_languages(file_lang).contains(&lq.language.as_str()) {
                        continue;
                    }
                    match tree_sitter::Query::new(&ts_lang, &lq.query) {
                        Ok(query) => queries.push(CompiledQuery {
                            rule_index: i,
                            query,
                        }),
                        Err(e) => eprintln!(
                            "snoot: rule {} query for '{}' does not compile against the '{file_lang}' grammar: {e}",
                            rule.id, lq.language,
                        ),
                    }
                }
            }
            out.push(CompiledLanguage {
                language: file_lang,
                queries,
            });
        }
        out
    })
}

impl Engine for CodeEngine {
    fn name(&self) -> &'static str {
        "code"
    }

    fn file_matches(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .and_then(language_for_extension)
            .is_some()
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let Some(file_lang) = language_for_extension(ext) else {
            return Vec::new();
        };
        let Some(ts_lang) = ts_language(file_lang) else {
            return Vec::new();
        };
        let Some(compiled_lang) = compiled().iter().find(|c| c.language == file_lang) else {
            return Vec::new();
        };
        if compiled_lang.queries.is_empty() {
            return Vec::new();
        }

        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&ts_lang).is_err() {
            return Vec::new();
        }
        let Some(tree) = parser.parse(content, None) else {
            return Vec::new();
        };
        let root = tree.root_node();

        let rules = RuleRegistry::all();
        let path_str = path.to_string_lossy().replace('\\', "/");
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = tree_sitter::QueryCursor::new();

        for cq in &compiled_lang.queries {
            let rule = &rules[cq.rule_index];
            let mut query_matches = cursor.matches(&cq.query, root, content);
            while let Some(m) = query_matches.next() {
                // Span covering every capture in the match.
                let mut start = usize::MAX;
                let mut end = 0;
                let mut start_row = 0u32;
                for cap in m.captures {
                    let node = cap.node;
                    if node.start_byte() < start {
                        start = node.start_byte();
                        start_row = node.start_position().row as u32;
                    }
                    end = end.max(node.end_byte());
                }
                if start == usize::MAX || end <= start {
                    continue;
                }
                // Include arguments in the fingerprint, even when queries only capture the callee.
                let mut node = m.captures[0].node;
                while let Some(parent) = node.parent() {
                    if matches!(
                        parent.kind(),
                        "call_expression" | "call" | "method_invocation" | "new_expression"
                    ) && parent.start_byte() <= start
                        && parent.end_byte() >= end
                    {
                        node = parent;
                        break;
                    }
                    node = parent;
                }
                if matches!(
                    node.kind(),
                    "call_expression" | "call" | "method_invocation" | "new_expression"
                ) {
                    start = node.start_byte();
                    end = node.end_byte();
                    start_row = node.start_position().row as u32;
                }
                let full = String::from_utf8_lossy(&content[start..end.min(content.len())])
                    .trim()
                    .to_string();
                let displayed = if full.contains("PRIVATE KEY") {
                    "<API call containing key material; redacted>".to_string()
                } else {
                    full.chars().take(160).collect()
                };
                let mut finding = Finding::new(
                    rule,
                    path_str.clone(),
                    Some(start_row + 1),
                    Some(full),
                    Evidence {
                        kind: "api_call".to_string(),
                        detail: format!("{} API call ({file_lang})", rule.title),
                    },
                );
                finding.location.snippet = Some(displayed);
                let line_start = content[..start]
                    .iter()
                    .rposition(|b| *b == b'\n')
                    .map_or(0, |i| i + 1);
                finding.location.column = Some(
                    String::from_utf8_lossy(&content[line_start..start])
                        .chars()
                        .count() as u32
                        + 1,
                );
                if seen.insert((
                    finding.fingerprint.clone(),
                    finding.location.line,
                    finding.location.column,
                )) {
                    findings.push(finding);
                }
            }
        }
        findings
    }
}

/// Languages with a wired tree-sitter grammar (DESIGN.md §7).
// Public API surface for future engine/diagnostic use.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The single most important test in the codebase: every tree-sitter
    /// query string in the rule registry must compile against every grammar
    /// it can run against. Query strings are data, so a typo would otherwise
    /// surface only as silent non-matches at runtime.
    #[test]
    fn all_registry_queries_compile() {
        let rules = RuleRegistry::all();
        assert!(!rules.is_empty(), "rule registry is empty");
        let mut count = 0;
        for rule in &rules {
            for lq in &rule.queries {
                let file_langs: Vec<&'static str> = FILE_LANGUAGES
                    .iter()
                    .copied()
                    .filter(|f| query_languages(f).contains(&lq.language.as_str()))
                    .collect();
                assert!(
                    !file_langs.is_empty(),
                    "rule {} query tagged with unknown language '{}'",
                    rule.id,
                    lq.language
                );
                for file_lang in file_langs {
                    let ts_lang = ts_language(file_lang)
                        .unwrap_or_else(|| panic!("no grammar for '{file_lang}'"));
                    if let Err(e) = tree_sitter::Query::new(&ts_lang, &lq.query) {
                        panic!(
                            "rule {} query for '{}' does not compile against the '{file_lang}' grammar: {e}\n{}",
                            rule.id, lq.language, lq.query
                        );
                    }
                    count += 1;
                }
            }
        }
        assert!(count > 0, "registry has no queries at all");
    }

    #[test]
    fn extension_mapping_covers_advertised_languages() {
        for (ext, lang) in [
            ("rs", "rust"),
            ("py", "python"),
            ("go", "go"),
            ("js", "javascript"),
            ("ts", "typescript"),
            ("tsx", "tsx"),
            ("java", "java"),
            ("c", "c"),
            ("h", "c"),
            ("cpp", "cpp"),
            ("hpp", "cpp"),
        ] {
            assert_eq!(language_for_extension(ext), Some(lang));
            assert!(ts_language(lang).is_some(), "no grammar wired for '{lang}'");
        }
    }

    /// Count query matches of `query_src` against `code` in `ts_lang`.
    fn count_matches(
        ts_lang: &tree_sitter::Language,
        query_src: &str,
        code: &str,
    ) -> Result<usize, String> {
        let query = tree_sitter::Query::new(ts_lang, query_src).map_err(|e| e.to_string())?;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(ts_lang).map_err(|e| e.to_string())?;
        let tree = parser.parse(code, None).ok_or("parse returned None")?;
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), code.as_bytes());
        let mut n = 0;
        while matches.next().is_some() {
            n += 1;
        }
        Ok(n)
    }

    /// Positive fixtures: every single query in the registry must fire on at
    /// least one minimal snippet in its own language. Structurally valid but
    /// semantically dead queries (wrong attribute depth, wrong node names —
    /// the week-1 SNOOT001 bug class) fail here instead of silently missing
    /// at runtime. Format: (rule id, query language, code).
    #[test]
    fn every_query_fires_on_fixture() {
        let fixtures: &[(&str, &str, &str)] = &[
            ("SNOOT001", "python", "RSA.generate(2048)"),
            ("SNOOT001", "python", "rsa.generate_private_key(public_exponent=65537, key_size=2048)"),
            ("SNOOT001", "javascript", "const key = new NodeRSA({b: 2048});"),
            // SNOOT001 — RSA key generation
            ("SNOOT001", "rust", "fn f() { let k = Rsa::generate(2048); }"),
            (
                "SNOOT001",
                "rust",
                "fn f() { let k = RsaPrivateKey::new(&mut rng, 2048).unwrap(); }",
            ),
            (
                "SNOOT001",
                "python",
                "import Crypto.PublicKey.RSA\nkey = Crypto.PublicKey.RSA.generate(2048)",
            ),
            (
                "SNOOT001",
                "python",
                "import rsa\npub, priv = rsa.newkeys(2048)",
            ),
            (
                "SNOOT001",
                "go",
                "package main\nimport \"crypto/rsa\"\nimport \"crypto/rand\"\nfunc f() { rsa.GenerateKey(rand.Reader, 2048) }",
            ),
            (
                "SNOOT001",
                "javascript",
                "const crypto = require('crypto');\nconst k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });",
            ),
            (
                "SNOOT001",
                "java",
                "class A { void f() throws Exception { KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\"); } }",
            ),
            // SNOOT002 — ECDSA signing
            (
                "SNOOT002",
                "rust",
                "fn f() { let sk = SigningKey::random(&mut rng); }",
            ),
            (
                "SNOOT002",
                "python",
                "from ecdsa import SigningKey\nsk = SigningKey.generate()",
            ),
            (
                "SNOOT002",
                "python",
                "import ecdsa\nsk = ecdsa.SigningKey.generate()",
            ),
            (
                "SNOOT002",
                "go",
                "package main\nimport \"crypto/ecdsa\"\nimport \"crypto/elliptic\"\nimport \"crypto/rand\"\nfunc f() { ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }",
            ),
            (
                "SNOOT002",
                "javascript",
                "const crypto = require('crypto');\nconst k = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });",
            ),
            (
                "SNOOT002",
                "java",
                "class A { void f() throws Exception { KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"EC\"); } }",
            ),
            (
                "SNOOT002",
                "java",
                "class A { void f() throws Exception { Signature s = Signature.getInstance(\"SHA256withECDSA\"); } }",
            ),
            // SNOOT004 — weak Diffie-Hellman parameters
            ("SNOOT004", "rust", "fn f() { let p = Dh::generate(1024); }"),
            (
                "SNOOT004",
                "python",
                "from cryptography.hazmat.primitives.asymmetric import dh\np = dh.generate_parameters(generator=2, key_size=1024)",
            ),
            (
                "SNOOT004",
                "javascript",
                "const crypto = require('crypto');\nconst dh = crypto.getDiffieHellman('modp1');",
            ),
            // SNOOT006 — DSA key generation
            (
                "SNOOT006",
                "java",
                "class A { void f() throws Exception { KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"DSA\"); } }",
            ),
            (
                "SNOOT006",
                "python",
                "import Crypto.PublicKey.DSA\nkey = Crypto.PublicKey.DSA.generate(2048)",
            ),
            (
                "SNOOT006",
                "javascript",
                "const crypto = require('crypto');\nconst k = crypto.generateKeyPairSync('dsa', { modulusLength: 2048 });",
            ),
            (
                "SNOOT006",
                "rust",
                "fn f() { let d = Dsa::generate(2048).unwrap(); }",
            ),
            // SNOOT007 — ECDH key exchange
            (
                "SNOOT007",
                "go",
                "package main\nimport \"crypto/ecdh\"\nimport \"crypto/rand\"\nfunc f() { ecdh.P256().GenerateKey(rand.Reader) }",
            ),
            (
                "SNOOT007",
                "javascript",
                "const crypto = require('crypto');\nconst e = crypto.createECDH('secp256k1');",
            ),
            (
                "SNOOT007",
                "java",
                "class A { void f() throws Exception { KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\"); } }",
            ),
            (
                "SNOOT007",
                "python",
                "from cryptography.hazmat.primitives.asymmetric import ec\nkex = ec.ECDH()",
            ),
            (
                "SNOOT007",
                "rust",
                "fn f() { let s = EphemeralSecret::random(&mut rng); }",
            ),
            // SNOOT008 — weak elliptic curves
            (
                "SNOOT008",
                "go",
                "package main\nimport \"crypto/elliptic\"\nfunc f() { c := elliptic.P192() }",
            ),
            (
                "SNOOT008",
                "java",
                "class A { void f() { new ECGenParameterSpec(\"secp192r1\"); } }",
            ),
            (
                "SNOOT008",
                "python",
                "from cryptography.hazmat.primitives.asymmetric import ec\nc = ec.SECP192R1()",
            ),
            (
                "SNOOT008",
                "javascript",
                "const crypto = require('crypto');\nconst e = crypto.createECDH('secp192r1');",
            ),
            ("SNOOT008", "rust", "fn f() { let c: P192 = foo(); }"),
            // SNOOT010 — RSA encryption/decryption
            (
                "SNOOT010",
                "go",
                "package main\nimport \"crypto/rsa\"\nimport \"crypto/rand\"\nfunc f() { rsa.EncryptPKCS1v15(rand.Reader, pub, msg) }",
            ),
            (
                "SNOOT010",
                "javascript",
                "const crypto = require('crypto');\nconst e = crypto.publicEncrypt(key, data);",
            ),
            (
                "SNOOT010",
                "java",
                "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"RSA/ECB/PKCS1Padding\"); } }",
            ),
            (
                "SNOOT010",
                "python",
                "from Crypto.Cipher import PKCS1_v1_5\nc = PKCS1_v1_5.new(key)",
            ),
            ("SNOOT010", "rust", "fn f() { let p = Pkcs1v15Encrypt; }"),
            // SNOOT011 — DSA signing
            (
                "SNOOT011",
                "java",
                "class A { void f() throws Exception { Signature s = Signature.getInstance(\"SHA256withDSA\"); } }",
            ),
            (
                "SNOOT011",
                "python",
                "from Crypto.Signature import DSS\nh = DSS.new(key, 'fips-186-3')",
            ),
            // SNOOT012 — finite-field Diffie-Hellman
            (
                "SNOOT012",
                "javascript",
                "const crypto = require('crypto');\nconst d = crypto.createDiffieHellman(2048);",
            ),
            (
                "SNOOT012",
                "java",
                "class A { void f() throws Exception { KeyAgreement ka = KeyAgreement.getInstance(\"DH\"); } }",
            ),
            (
                "SNOOT012",
                "python",
                "from cryptography.hazmat.primitives.asymmetric import dh\np = dh.generate_parameters(generator=2, key_size=2048)",
            ),
            // SNOOT013 — legacy hashes
            (
                "SNOOT013",
                "go",
                "package main\nimport \"crypto/md5\"\nfunc f() { h := md5.New() }",
            ),
            (
                "SNOOT013",
                "javascript",
                "const crypto = require('crypto');\nconst h = crypto.createHash('md5');",
            ),
            (
                "SNOOT013",
                "java",
                "class A { void f() throws Exception { MessageDigest md = MessageDigest.getInstance(\"MD5\"); } }",
            ),
            ("SNOOT013", "python", "import hashlib\nh = hashlib.md5()"),
            ("SNOOT013", "rust", "fn f() { let h = Md5::new(); }"),
            ("SNOOT013", "rust", "fn f() { let d = md5::compute(b\"x\"); }"),
            // SNOOT014 — classical JWT algorithms
            (
                "SNOOT014",
                "javascript",
                "const t = jwt.sign(payload, key, { algorithm: 'RS256' });",
            ),
            (
                "SNOOT014",
                "python",
                "token = jwt.encode(payload, key, algorithm='RS256')",
            ),
            (
                "SNOOT014",
                "java",
                "class A { void f() { b.signWith(key, SignatureAlgorithm.RS256); } }",
            ),
            ("SNOOT014", "rust", "fn f() { let a = Algorithm::RS256; }"),
            (
                "SNOOT014",
                "go",
                "package main\nimport \"github.com/golang-jwt/jwt\"\nfunc f() { t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims) }",
            ),
            // C — OpenSSL EVP / legacy API shapes
            (
                "SNOOT001",
                "c",
                "void f() { RSA *r = RSA_generate_key(2048, RSA_F4, NULL, NULL); }",
            ),
            (
                "SNOOT001",
                "c",
                "void f() { EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); }",
            ),
            (
                "SNOOT002",
                "c",
                "void f() { ECDSA_sign(0, dgst, 32, sig, &siglen, eckey); }",
            ),
            (
                "SNOOT007",
                "c",
                "void f() { ECDH_compute_key(secret, 32, pub_point, ecdh, NULL); }",
            ),
            (
                "SNOOT010",
                "c",
                "void f() { RSA_public_encrypt(256, in, out, rsa, RSA_PKCS1_PADDING); }",
            ),
            (
                "SNOOT012",
                "c",
                "void f() { DH_compute_key(secret, pub_key, dh); }",
            ),
            (
                "SNOOT013",
                "c",
                "void f() { MD5(d, n, md); }",
            ),
        ];

        for rule in RuleRegistry::all() {
            for lq in &rule.queries {
                let relevant: Vec<&str> = fixtures
                    .iter()
                    .filter(|(id, lang, _)| *id == rule.id && *lang == lq.language)
                    .map(|(_, _, code)| *code)
                    .collect();
                assert!(
                    !relevant.is_empty(),
                    "rule {} has a {} query with no positive fixture",
                    rule.id,
                    lq.language
                );
                let file_lang = FILE_LANGUAGES
                    .iter()
                    .find(|f| query_languages(f).contains(&lq.language.as_str()))
                    .unwrap();
                let ts_lang = ts_language(file_lang).unwrap();
                let mut fired = false;
                for code in relevant {
                    match count_matches(&ts_lang, &lq.query, code) {
                        Ok(n) if n > 0 => {
                            fired = true;
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => panic!(
                            "rule {} {} query failed on fixture: {e}",
                            rule.id, lq.language
                        ),
                    }
                }
                assert!(
                    fired,
                    "rule {} {} query matched none of its fixtures — dead query?\n{}",
                    rule.id, lq.language, lq.query
                );
            }
        }
    }
}
