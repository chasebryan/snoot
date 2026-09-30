//! Scan orchestration: walk the tree, dispatch per-file engines, collect findings.
//!
//! The scanner walks files with `walkdir`, honors `.snootignore`, asks each
//! engine whether a file is in scope, dedupes by fingerprint, and applies an
//! optional baseline.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::engines::{CodeEngine, Engine, ManifestEngine, SecretsEngine, TlsConfEngine};
use crate::ignore::{self, IgnoreList};
use crate::model::Finding;

/// Options controlling a scan.
#[derive(Debug)]
pub struct ScanOptions {
    /// Root of the source tree to scan.
    pub root: PathBuf,
    /// Optional baseline file: findings recorded there are suppressed.
    pub baseline: Option<PathBuf>,
    /// Skip files larger than this (bytes). Guards against accidental
    /// multi-gigabyte blobs in the tree.
    pub max_file_bytes: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            baseline: None,
            max_file_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Aggregate statistics for a scan, shown in the console summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub elapsed_ms: u64,
}

/// Everything a scan produced.
#[derive(Debug)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    pub root: PathBuf,
}

/// Directories that are never worth scanning.
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
];

/// Walk `opts.root`, run every engine over every in-scope file, and return
/// the collected findings sorted by severity (descending), then path.
pub fn scan(opts: &ScanOptions) -> anyhow::Result<ScanReport> {
    let started = Instant::now();
    let ignore = IgnoreList::load_from_root(&opts.root);

    let engines: Vec<Box<dyn Engine>> = vec![
        Box::new(CodeEngine),
        Box::new(SecretsEngine),
        Box::new(ManifestEngine),
        Box::new(TlsConfEngine),
    ];

    let mut findings: Vec<Finding> = Vec::new();
    let mut files_scanned: u64 = 0;
    let mut files_skipped: u64 = 0;

    let root = opts.root.clone();
    let walker = walkdir::WalkDir::new(&opts.root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if entry.file_type().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if SKIP_DIRS.contains(&name) {
                        return false;
                    }
                }
                let rel = ignore::rel_path(&root, entry.path());
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                if ignore.ignores_dir(&rel_str) {
                    return false;
                }
            }
            true
        });

    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = ignore::rel_path(&opts.root, path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if ignore.ignores(&rel_str) {
            files_skipped += 1;
            continue;
        }

        let content = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };
        if content.len() as u64 > opts.max_file_bytes {
            files_skipped += 1;
            continue;
        }
        // Skip likely-binary files early (NUL byte heuristic).
        if content.iter().take(8192).any(|&b| b == 0) {
            files_skipped += 1;
            continue;
        }

        files_scanned += 1;
        for engine in &engines {
            if engine.file_matches(path) {
                findings.extend(engine.scan(path, &content));
            }
        }
    }

    // Dedupe identical fingerprints (multiple queries can hit one call site).
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.fingerprint.clone()));

    // DESIGN.md §6: classical crypto in test/example code is medium, not
    // high/critical — still inventoried, but not CI-blocking by default.
    demote_test_path_severity(&mut findings);

    // Apply baseline suppression when requested.
    if let Some(baseline_path) = &opts.baseline {
        match crate::baseline::Baseline::load(baseline_path) {
            Ok(baseline) => {
                findings.retain(|f| !baseline.suppresses(f));
            }
            Err(err) => {
                anyhow::bail!("loading baseline {}: {err:#}", baseline_path.display());
            }
        }
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.location.path.cmp(&b.location.path))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });

    Ok(ScanReport {
        findings,
        stats: ScanStats {
            files_scanned,
            files_skipped,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
        root: opts.root.clone(),
    })
}

fn is_testish_path(path: &str) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    let markers = [
        "/tests/",
        "/test/",
        "/fixtures/",
        "/examples/",
        "/example/",
        "/benches/",
        "/bench/",
        "/testdata/",
        "/__tests__/",
        "/spec/",
    ];
    markers.iter().any(|m| p.contains(m))
        || p.starts_with("tests/")
        || p.starts_with("test/")
        || p.starts_with("fixtures/")
        || p.starts_with("examples/")
        || p.starts_with("benches/")
}

fn demote_test_path_severity(findings: &mut [Finding]) {
    use crate::model::Severity;
    for f in findings {
        if is_testish_path(&f.location.path) && f.severity > Severity::Medium {
            f.severity = Severity::Medium;
        }
    }
}

/// Relativize `path` against the scan root for display, falling back to the
/// full path. Context helper used by reporters.
#[allow(dead_code)]
pub fn display_path(root: &PathBuf, path: &str) -> String {
    PathBuf::from(path)
        .strip_prefix(root)
        .map(|p| p.to_string_lossy().into_owned())
        .with_context(|| format!("strip prefix {}", root.display()))
        .unwrap_or_else(|_| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Severity};
    use crate::rules::RuleRegistry;

    #[test]
    fn demotes_critical_in_tests_dir() {
        let rule = RuleRegistry::by_id("SNOOT003").unwrap();
        let mut finding = crate::model::Finding::new(
            &rule,
            "tests/examples/key.pem",
            Some(1),
            Some("-----BEGIN RSA PRIVATE KEY-----".into()),
            Evidence {
                kind: "pem_block".into(),
                detail: "RSA".into(),
            },
        );
        assert_eq!(finding.severity, Severity::Critical);
        demote_test_path_severity(std::slice::from_mut(&mut finding));
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn keeps_critical_in_app_code() {
        let rule = RuleRegistry::by_id("SNOOT003").unwrap();
        let mut finding = crate::model::Finding::new(
            &rule,
            "src/auth/keys.pem",
            Some(1),
            Some("-----BEGIN RSA PRIVATE KEY-----".into()),
            Evidence {
                kind: "pem_block".into(),
                detail: "RSA".into(),
            },
        );
        demote_test_path_severity(std::slice::from_mut(&mut finding));
        assert_eq!(finding.severity, Severity::Critical);
    }
}
