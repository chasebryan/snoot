//! Public CLI contracts: baselines, error exits, and machine-readable reports.

use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Output};

fn snoot() -> Command {
    Command::new(env!("CARGO_BIN_EXE_snoot"))
}

fn successful(output: Output) -> Output {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn scan(root: &Path, baseline: Option<&Path>) -> Output {
    let mut command = snoot();
    command
        .arg("scan")
        .arg(root)
        .args(["--format", "json", "--fail-on", "high", "--quiet"]);
    if let Some(path) = baseline {
        command.arg("--baseline").arg(path);
    }
    command.output().unwrap()
}

fn document(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "invalid report ({err}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn init(root: &Path, path: &Path) -> Output {
    snoot()
        .arg("init")
        .arg(root)
        .arg("--output")
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn baseline_round_trip_is_portable_and_survives_line_shifts() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let source = "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n";
    std::fs::write(first.path().join("keys.py"), source).unwrap();
    let baseline = first.path().join("baseline.json");
    successful(init(first.path(), &baseline));
    let recorded: Value = serde_json::from_slice(&std::fs::read(&baseline).unwrap()).unwrap();
    assert_eq!(recorded["version"], 1);
    assert_eq!(recorded["fingerprints"].as_array().unwrap().len(), 1);
    let before = document(&scan(first.path(), None));
    assert_eq!(before["findings"][0]["location"]["path"], "keys.py");

    std::fs::write(
        second.path().join("keys.py"),
        format!("\n# moved down\n{source}"),
    )
    .unwrap();
    let after = document(&scan(second.path(), None));
    assert_eq!(
        before["findings"][0]["fingerprint"],
        after["findings"][0]["fingerprint"]
    );
    let suppressed = document(&successful(scan(second.path(), Some(&baseline))));
    assert!(suppressed["findings"].as_array().unwrap().is_empty());
    assert_eq!(suppressed["stats"]["findings_suppressed"], 1);

    std::fs::write(second.path().join("new.py"), source).unwrap();
    let output = scan(second.path(), Some(&baseline));
    assert_eq!(output.status.code(), Some(2));
    let new = document(&output);
    assert_eq!(new["findings"].as_array().unwrap().len(), 1);
    assert_eq!(new["findings"][0]["location"]["path"], "new.py");
}

#[test]
fn changed_call_after_display_limit_is_not_suppressed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.py");
    let padding = "x".repeat(140);
    std::fs::write(
        &path,
        format!("rsa.generate_private_key({padding}, key_size=2048)"),
    )
    .unwrap();
    let baseline = dir.path().join("baseline.json");
    successful(init(dir.path(), &baseline));
    std::fs::write(
        &path,
        format!("rsa.generate_private_key({padding}, key_size=4096)"),
    )
    .unwrap();
    let output = scan(dir.path(), Some(&baseline));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(document(&output)["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn baseline_writes_are_deterministic_and_require_force_to_replace() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("keys.py"),
        "RSA.generate(2048)\nRSA.generate(4096)",
    )
    .unwrap();
    let first = dir.path().join("first.json");
    let second = dir.path().join("second.json");
    successful(init(dir.path(), &first));
    successful(init(dir.path(), &second));
    let original = std::fs::read(&first).unwrap();
    assert_eq!(original, std::fs::read(&second).unwrap());
    assert_eq!(init(dir.path(), &first).status.code(), Some(3));
    assert_eq!(original, std::fs::read(&first).unwrap());
    std::fs::write(dir.path().join("keys.py"), "# cleaned up\n").unwrap();
    successful(
        snoot()
            .arg("init")
            .arg(dir.path())
            .arg("--output")
            .arg(&first)
            .arg("--force")
            .output()
            .unwrap(),
    );
    assert_ne!(original, std::fs::read(&first).unwrap());
}

#[test]
fn invalid_scan_paths_and_baselines_fail_without_a_clean_report() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    assert_eq!(scan(&missing, None).status.code(), Some(3));
    assert_eq!(scan(dir.path(), Some(&missing)).status.code(), Some(3));
    let baseline = dir.path().join("bad.json");
    for content in ["not json", r#"{"version":99,"fingerprints":[]}"#] {
        std::fs::write(&baseline, content).unwrap();
        let output = scan(dir.path(), Some(&baseline));
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(
        init(&missing, &dir.path().join("new.json")).status.code(),
        Some(3)
    );
    assert!(!dir.path().join("new.json").exists());
}

#[test]
fn relative_absolute_and_single_file_paths_have_portable_fingerprints() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("keys.py");
    std::fs::write(&source, "RSA.generate(2048)").unwrap();
    let absolute = document(&scan(dir.path(), None));
    let single = document(&scan(&source, None));
    let relative = successful(
        snoot()
            .current_dir(dir.path())
            .args(["scan", ".", "--format", "json"])
            .output()
            .unwrap(),
    );
    let relative = document(&relative);
    assert_eq!(absolute["findings"], single["findings"]);
    assert_eq!(absolute["findings"], relative["findings"]);
}

#[test]
fn fail_on_compares_severity_and_writes_report_before_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("keys.py"), "RSA.generate(2048)").unwrap();
    for (severity, code) in [
        ("critical", 0),
        ("high", 2),
        ("medium", 2),
        ("low", 2),
        ("info", 2),
    ] {
        let path = dir.path().join("report.json");
        let output = snoot()
            .arg("scan")
            .arg(dir.path())
            .args(["--format", "json", "--quiet", "--fail-on", severity])
            .arg("--output")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code));
        let report: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn multiple_reports_are_separate_documents_and_rescans_exclude_outputs() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("keys.py"), "RSA.generate(2048)").unwrap();
    let reports = dir.path().join("reports");
    for _ in 0..2 {
        successful(
            snoot()
                .arg("scan")
                .arg(dir.path())
                .args([
                    "--format", "json", "--format", "sarif", "--format", "cbom", "--format",
                    "console",
                ])
                .arg("--output")
                .arg(&reports)
                .output()
                .unwrap(),
        );
        for name in ["snoot.json", "snoot.sarif", "snoot.cdx.json"] {
            let report: Value =
                serde_json::from_slice(&std::fs::read(reports.join(name)).unwrap()).unwrap();
            assert!(report.is_object());
        }
        let report: Value =
            serde_json::from_slice(&std::fs::read(reports.join("snoot.json")).unwrap()).unwrap();
        assert_eq!(report["stats"]["files_scanned"], 1);
    }
    let output = snoot()
        .arg("scan")
        .arg(dir.path())
        .args(["--format", "json", "--format", "sarif"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
}

#[test]
fn output_errors_are_reported_and_inputs_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("keys.py");
    std::fs::write(&source, "RSA.generate(2048)").unwrap();
    for output in [
        source.clone(),
        dir.path().join("absent/report.json"),
        dir.path().to_owned(),
    ] {
        let result = snoot()
            .arg("scan")
            .arg(&source)
            .args(["--format", "json"])
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(3));
    }
    assert_eq!(
        std::fs::read_to_string(&source).unwrap(),
        "RSA.generate(2048)"
    );
    let baseline = dir.path().join("baseline.json");
    successful(init(dir.path(), &baseline));
    let original = std::fs::read(&baseline).unwrap();
    let result = snoot()
        .arg("scan")
        .arg(dir.path())
        .arg("--baseline")
        .arg(&baseline)
        .arg("--output")
        .arg(&baseline)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    assert_eq!(original, std::fs::read(&baseline).unwrap());
}

#[test]
fn sarif_escapes_paths_and_cbom_has_valid_primitive_names() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("key #é.py"), "RSA.generate(2048)").unwrap();
    let sarif = successful(
        snoot()
            .arg("scan")
            .arg(dir.path())
            .args(["--format", "sarif"])
            .output()
            .unwrap(),
    );
    let sarif = document(&sarif);
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "key%20%23%C3%A9.py"
    );
    assert!(result["partialFingerprints"]["snoot/v1"].is_string());
    let cbom = document(&successful(
        snoot()
            .arg("scan")
            .arg(dir.path())
            .args(["--format", "cbom"])
            .output()
            .unwrap(),
    ));
    assert_eq!(cbom["components"][0]["name"], "RSA");
    assert_eq!(
        cbom["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"],
        "unknown"
    );
    assert_eq!(
        cbom["components"][0]["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"],
        json!(["keygen"])
    );
}

#[test]
fn console_respects_no_color_and_reports_suppression_without_claiming_safety() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("keys.py"), "RSA.generate(2048)").unwrap();
    let baseline = dir.path().join("baseline.json");
    successful(init(dir.path(), &baseline));
    let out = successful(
        snoot()
            .arg("scan")
            .arg(dir.path())
            .arg("--baseline")
            .arg(baseline)
            .env("NO_COLOR", "1")
            .env("CLICOLOR_FORCE", "1")
            .output()
            .unwrap(),
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("1 suppressed"));
    assert!(text.contains("supported detectors"));
    assert!(!text.contains('\u{1b}'));
}

#[cfg(unix)]
#[test]
fn unreadable_files_fail_and_symlinks_are_not_followed() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("keys.py");
    std::fs::write(&secret, "RSA.generate(2048)").unwrap();
    symlink(&secret, dir.path().join("linked.py")).unwrap();
    let report = document(&successful(scan(dir.path(), None)));
    assert_eq!(report["stats"]["files_skipped"], 1);
    assert!(report["findings"].as_array().unwrap().is_empty());
    let unreadable = dir.path().join("unreadable.py");
    std::fs::write(&unreadable, "RSA.generate(2048)").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = scan(dir.path(), None);
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(out.status.code(), Some(3));
}
