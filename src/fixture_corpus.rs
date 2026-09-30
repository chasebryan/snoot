//! Fixture corpus: end-to-end rule-set assertions over real files.
//!
//! `tests/fixtures/` holds real files (openssl-generated keys, hand-written
//! configs, manifests) exercising every engine. This module is part of the
//! crate's own test suite (integration tests under `tests/` can't import a
//! binary crate, so the corpus lives here under `#[cfg(test)]`).
//!
//! Each entry pins the *exact set* of rule IDs a fixture must produce — no
//! stray findings, no silent misses. Adding a fixture means adding one line
//! to [`fixture_corpus_rule_sets`].

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::engines::{CodeEngine, Engine, ManifestEngine, SecretsEngine, TlsConfEngine};

fn engine_for(path: &Path) -> Box<dyn Engine> {
    let dir = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let engine: Box<dyn Engine> = match dir {
        "code" => Box::new(CodeEngine),
        "secrets" => Box::new(SecretsEngine),
        "manifest" => Box::new(ManifestEngine),
        "tlsconf" => Box::new(TlsConfEngine),
        other => panic!("fixture_corpus: unknown fixture dir {other:?} for {path:?}"),
    };
    assert!(
        engine.file_matches(path),
        "fixture_corpus: engine {} does not match {path:?}",
        engine.name()
    );
    engine
}

fn rule_ids_for(path: &Path) -> BTreeSet<String> {
    let engine = engine_for(path);
    let content = fs::read(path).unwrap();
    engine
        .scan(path, &content)
        .into_iter()
        .map(|f| f.rule_id)
        .collect()
}

fn expect(relative: &str, rules: &[&str]) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative);
    let got = rule_ids_for(&path);
    let want: BTreeSet<String> = rules.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "fixture_corpus: {relative}");
}

#[test]
fn fixture_corpus_rule_sets() {
    // code
    expect(
        "code/rust_positive.rs",
        &["SNOOT001", "SNOOT002", "SNOOT013"],
    );
    expect("code/rust_negative.rs", &[]);
    expect(
        "code/python_positive.py",
        &["SNOOT001", "SNOOT002", "SNOOT013", "SNOOT014"],
    );
    expect("code/python_negative.py", &[]);
    expect("code/go_positive.go", &["SNOOT001", "SNOOT013"]);
    expect("code/go_negative.go", &[]);
    expect("code/js_positive.js", &["SNOOT001", "SNOOT014"]);
    expect("code/js_negative.js", &[]);
    expect("code/java_positive.java", &["SNOOT001", "SNOOT002"]);
    expect("code/java_negative.java", &[]);
    expect("code/c_positive.c", &["SNOOT001", "SNOOT002"]);
    expect("code/c_negative.c", &[]);

    // secrets
    expect("secrets/rsa_private.pem", &["SNOOT003"]);
    expect("secrets/ec_private.pem", &["SNOOT009"]);
    expect("secrets/pgp_private.asc", &["SNOOT015"]);
    expect("secrets/clean.txt", &[]);
    // week 4: DER blobs, X.509 certs, JWK (openssl-generated + hand-written)
    expect("secrets/rsa_key.der", &["SNOOT003"]);
    expect("secrets/ec_key.der", &["SNOOT009"]);
    expect("secrets/rsa_cert.pem", &["SNOOT020"]);
    expect("secrets/ecdsa_cert.pem", &["SNOOT021"]);
    expect("secrets/ed25519_cert.pem", &["SNOOT022"]);
    expect("secrets/jwk_rsa.json", &["SNOOT003"]);
    expect("secrets/jwk_ec.json", &["SNOOT022"]);

    // manifest
    expect("manifest/Cargo.toml", &["SNOOT017"]);
    expect("manifest/package.json", &["SNOOT016"]);
    expect("manifest/requirements.txt", &["SNOOT017"]);
    expect("manifest/go.mod", &["SNOOT017"]);

    // tlsconf
    expect(
        "tlsconf/nginx_weak.conf",
        &["SNOOT005", "SNOOT018", "SNOOT019"],
    );
    expect("tlsconf/nginx_good.conf", &[]);
}
