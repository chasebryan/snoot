//! Smoke tests for the snoot CLI binary.
//!
//! Week 1: exercise the flags end to end via `CARGO_BIN_EXE_snoot`.
//! Later weeks add fixture-corpus accuracy tests per rule (DESIGN.md §10).

use std::process::Command;

fn snoot() -> Command {
    let exe = env!("CARGO_BIN_EXE_snoot");
    Command::new(exe)
}

#[test]
fn version_flag_works() {
    let out = snoot()
        .arg("--version")
        .output()
        .expect("run snoot --version");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("snoot"),
        "unexpected --version output: {stdout}"
    );
}

#[test]
fn rules_lists_rule_ids() {
    let out = snoot().arg("rules").output().expect("run snoot rules");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for i in 1..=20 {
        let id = format!("SNOOT{i:03}");
        assert!(stdout.contains(&id), "rules output missing {id}");
    }
}

#[test]
fn scan_empty_dir_reports_no_findings() {
    let dir = std::env::temp_dir().join("snoot-smoke-empty");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let out = snoot()
        .arg("scan")
        .arg(&dir)
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
    assert!(
        stdout.contains("\"findings\": []"),
        "expected empty findings, got: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_help_mentions_formats() {
    let out = snoot()
        .arg("scan")
        .arg("--help")
        .output()
        .expect("run snoot scan --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--format",
        "--fail-on",
        "--baseline",
        "--no-color",
        "--quiet",
    ] {
        assert!(stdout.contains(flag), "scan --help missing {flag}");
    }
}

#[test]
fn init_and_baseline_suppress_findings() {
    let dir = std::env::temp_dir().join("snoot-smoke-baseline");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("src/keys.rs"),
        "fn f() { let _ = Rsa::generate(&mut rng, 2048); }\n",
    )
    .unwrap();

    let baseline = dir.join(".snoot-baseline.json");
    let init = snoot()
        .arg("init")
        .arg(&dir)
        .arg("--output")
        .arg(&baseline)
        .output()
        .expect("snoot init");
    assert!(
        init.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(baseline.is_file());

    let scan = snoot()
        .arg("scan")
        .arg(&dir)
        .arg("--baseline")
        .arg(&baseline)
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .output()
        .expect("snoot scan --baseline");
    assert!(
        scan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let stdout = String::from_utf8_lossy(&scan.stdout);
    assert!(
        stdout.contains("\"findings\": []"),
        "baseline should suppress, got: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
