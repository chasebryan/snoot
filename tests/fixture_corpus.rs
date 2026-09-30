//! Fixture-corpus accuracy tests (DESIGN.md §10).
//!
//! Every live rule has at least one known-positive and one known-negative
//! sample under `tests/fixtures/`. These drive the CLI end-to-end so a
//! regression that only shows up through scan orchestration still fails CI.

use std::path::{Path, PathBuf};
use std::process::Command;

fn snoot() -> Command {
    let exe = env!("CARGO_BIN_EXE_snoot");
    Command::new(exe)
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn scan_json(root: &Path) -> serde_json::Value {
    let out = snoot()
        .arg("scan")
        .arg(root)
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .output()
        .expect("run snoot scan");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("bad json ({e}): {stdout}"))
}

fn finding_ids(doc: &serde_json::Value) -> Vec<String> {
    doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn positives_fire_expected_rules() {
    let root = fixtures_root().join("positive");
    assert!(root.is_dir(), "missing fixture dir {}", root.display());

    let doc = scan_json(&root);
    let ids = finding_ids(&doc);

    for expected in ["SNOOT001", "SNOOT002", "SNOOT003", "SNOOT004"] {
        assert!(
            ids.iter().any(|id| id == expected),
            "positive corpus missing {expected}; got {ids:?}"
        );
    }
}

#[test]
fn negatives_stay_clean() {
    let root = fixtures_root().join("negative");
    assert!(root.is_dir(), "missing fixture dir {}", root.display());

    let doc = scan_json(&root);
    let findings = doc["findings"].as_array().unwrap();
    assert!(
        findings.is_empty(),
        "negative corpus should be clean, got: {findings:?}"
    );
}
