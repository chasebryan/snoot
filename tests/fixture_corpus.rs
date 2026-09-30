//! Fixture-corpus accuracy tests (DESIGN.md §10).

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

    for expected in [
        "SNOOT001", "SNOOT002", "SNOOT003", "SNOOT004", "SNOOT005", "SNOOT006", "SNOOT007",
        "SNOOT008", "SNOOT009", "SNOOT010", "SNOOT016",
    ] {
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

#[test]
fn multi_language_positives_detected() {
    let root = fixtures_root().join("positive");
    let doc = scan_json(&root);
    let paths: Vec<&str> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["location"]["path"].as_str().unwrap())
        .collect();

    for needle in [
        "/go/",
        "/javascript/",
        "/typescript/",
        "/java/",
        "/c/",
        "/cpp/",
        "/tls/",
    ] {
        assert!(
            paths.iter().any(|p| p.contains(needle)),
            "expected a finding under *{needle}*, got {paths:?}"
        );
    }
}
