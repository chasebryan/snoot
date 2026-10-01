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
    let source = "from Crypto.PublicKey import RSA\nkey = rsa.newkeys(2048)\n";
    std::fs::write(first.path().join("keys.py"), source).unwrap();
    let baseline = first.path().join("baseline.json");
    successful(init(first.path(), &baseline));
    let recorded: Value = serde_json::from_slice(&std::fs::read(&baseline).unwrap()).unwrap();
    assert_eq!(recorded["version"], 2);
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
        "rsa.newkeys(2048)\nrsa.newkeys(4096)",
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
    std::fs::write(&source, "rsa.newkeys(2048)").unwrap();
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
    std::fs::write(dir.path().join("keys.py"), "rsa.newkeys(2048)").unwrap();
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
    std::fs::write(dir.path().join("keys.py"), "rsa.newkeys(2048)").unwrap();
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
    std::fs::write(&source, "rsa.newkeys(2048)").unwrap();
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
        "rsa.newkeys(2048)"
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
    std::fs::write(dir.path().join("key #é.py"), "rsa.newkeys(2048)").unwrap();
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
    std::fs::write(dir.path().join("keys.py"), "rsa.newkeys(2048)").unwrap();
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
    std::fs::write(&secret, "rsa.newkeys(2048)").unwrap();
    symlink(&secret, dir.path().join("linked.py")).unwrap();
    let report = document(&successful(scan(dir.path(), None)));
    assert_eq!(report["stats"]["files_skipped"], 1);
    assert!(report["findings"].as_array().unwrap().is_empty());
    let unreadable = dir.path().join("unreadable.py");
    std::fs::write(&unreadable, "rsa.newkeys(2048)").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = scan(dir.path(), None);
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn repeated_calls_preserve_every_location_and_full_argument_identity() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("keys.py"),
        "rsa.newkeys(2048); rsa.newkeys(2048)\nrsa.newkeys(4096)\n",
    )
    .unwrap();
    let doc = document(&scan(dir.path(), None));
    let findings = doc["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0]["fingerprint"], findings[1]["fingerprint"]);
    assert_ne!(
        findings[0]["location"]["column"],
        findings[1]["location"]["column"]
    );
    assert_ne!(findings[0]["fingerprint"], findings[2]["fingerprint"]);
}

#[test]
fn changed_private_material_is_not_suppressed_or_exposed_in_reports() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.pem");
    let armor =
        |body| format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n");
    std::fs::write(&path, armor("FirstPrivateMaterial")).unwrap();
    let baseline = dir.path().join("baseline.json");
    successful(init(dir.path(), &baseline));
    std::fs::write(&path, armor("DifferentPrivateMaterial")).unwrap();
    let result = scan(dir.path(), Some(&baseline));
    assert_eq!(result.status.code(), Some(2));
    for format in ["json", "sarif", "cbom", "console"] {
        let out = successful(
            snoot()
                .arg("scan")
                .arg(dir.path())
                .args(["--format", format])
                .output()
                .unwrap(),
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("DifferentPrivateMaterial"));
    }
    std::fs::write(&path, "no key").unwrap();
    let jwk = dir.path().join("key.jwk");
    std::fs::write(&jwk, r#"{"kty":"RSA","n":"AQAB","d":"first-private"}"#).unwrap();
    let baseline2 = dir.path().join("jwk-baseline.json");
    successful(init(dir.path(), &baseline2));
    std::fs::write(&jwk, r#"{"kty":"RSA","n":"AQAB","d":"second-private"}"#).unwrap();
    let result = scan(dir.path(), Some(&baseline2));
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("second-private"));
}

#[test]
fn cpp_and_modern_typescript_extensions_are_scanned() {
    for (name, source, rule) in [
        (
            "key.cpp",
            "void f(){RSA_generate_key_ex(rsa, 2048, e, 0);}",
            "SNOOT001",
        ),
        (
            "key.mts",
            "crypto.generateKeyPairSync('rsa', {modulusLength: 2048});",
            "SNOOT001",
        ),
        (
            "key.cts",
            "crypto.generateKeyPairSync('rsa', {modulusLength: 2048});",
            "SNOOT001",
        ),
        (
            "key.tsx",
            "const view = <span/>; crypto.generateKeyPairSync('rsa', {modulusLength: 2048});",
            "SNOOT001",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(name), source).unwrap();
        let doc = document(&scan(dir.path(), None));
        assert!(
            doc["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["rule_id"] == rule),
            "missed {name}"
        );
    }
}

#[test]
fn binary_der_keeps_reaching_the_secrets_engine() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("key.der"),
        include_bytes!("fixtures/secrets/rsa_key.der"),
    )
    .unwrap();
    let doc = document(&scan(dir.path(), None));
    assert_eq!(doc["findings"][0]["rule_id"], "SNOOT003");
    assert!(doc["findings"][0]["evidence"]["detail"]
        .as_str()
        .unwrap()
        .contains("2048-bit"));
}

#[test]
fn tls_exclusions_and_comments_do_not_enable_weak_or_hybrid_settings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tls.conf"), "ssl_protocols TLSv1.2 TLSv1.3; # X25519MLKEM768\nssl_ciphers HIGH:!aNULL:!MD5:!3DES;\n# ssl_groups X25519MLKEM768;\n").unwrap();
    let doc = document(&successful(scan(dir.path(), None)));
    let ids: Vec<_> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["SNOOT005"]);
}

#[test]
fn direct_manifest_dependencies_are_scoped_and_aliases_work() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = 'rsa'\nversion = '0.1.0'\n[dependencies]\nmycrypto = { package = 'rust-crypto', version = '0.2' }\n").unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"node-rsa","scripts":{"rsa":"node-forge"},"dependencies":{"node-rsa":"1"}}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("build.gradle"), "// implementation 'org.bouncycastle:bcprov-jdk18on:1.78'\ndef example = 'org.bouncycastle:bcprov-jdk18on:1.78'\n").unwrap();
    let doc = document(&scan(dir.path(), None));
    let findings = doc["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(findings.iter().any(|f| f["rule_id"] == "SNOOT017"));
    assert!(findings.iter().any(|f| f["rule_id"] == "SNOOT016"));
}

#[test]
fn directory_report_outputs_cannot_overwrite_scanned_source_files() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("keys.py");
    std::fs::write(&source, "rsa.newkeys(2048)").unwrap();
    let out = snoot()
        .arg("scan")
        .arg(dir.path())
        .args(["--format", "json", "--output"])
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(
        std::fs::read_to_string(source).unwrap(),
        "rsa.newkeys(2048)"
    );
}

#[test]
fn jwks_reordering_preserves_suppression_for_each_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.jwk");
    let a = r#"{"kty":"RSA","n":"AQAB","d":"first"}"#;
    let b = r#"{"kty":"RSA","n":"AQAC","d":"second"}"#;
    std::fs::write(&path, format!("{{\"keys\":[{a},{b}]}}")).unwrap();
    let baseline = dir.path().join("baseline.json");
    successful(init(dir.path(), &baseline));
    std::fs::write(&path, format!("{{\"keys\":[{b},{a}]}}")).unwrap();
    let doc = document(&successful(scan(dir.path(), Some(&baseline))));
    assert_eq!(doc["stats"]["findings_suppressed"], 2);
}

#[test]
fn invalid_structured_manifests_fail_and_compact_maven_dependencies_are_detected() {
    let dir = tempfile::tempdir().unwrap();
    let package = dir.path().join("package.json");
    std::fs::write(&package, "{invalid}").unwrap();
    assert_eq!(scan(dir.path(), None).status.code(), Some(3));
    std::fs::remove_file(package).unwrap();
    std::fs::write(dir.path().join("pom.xml"), "<project><dependencies><!-- <dependency><artifactId>bcprov-fake</artifactId></dependency> --><dependency><artifactId>bcprov-jdk18on</artifactId><version>1.78</version></dependency></dependencies></project>").unwrap();
    let doc = document(&successful(scan(dir.path(), None)));
    assert_eq!(doc["findings"].as_array().unwrap().len(), 1);
    assert_eq!(doc["findings"][0]["rule_id"], "SNOOT016");
}
