//! Scan orchestration: walk the tree, dispatch per-file engines, collect findings.
//!
//! The scanner itself owns no detection logic — it walks files with `walkdir`,
//! asks each engine whether a file is in scope (`Engine::file_matches`), and
//! aggregates the findings. Week 1: the walk and dispatch are real; the
//! engines return what they can (currently stubs, see `engines/`).

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context;
use glob::{MatchOptions, Pattern};
use serde::{Deserialize, Serialize};

use crate::baseline::Baseline;
use crate::engines::{CodeEngine, Engine, ManifestEngine, SecretsEngine, TlsConfEngine};
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
    /// Glob patterns (matched against the path relative to `root`, with
    /// `/` separators) to exclude from the scan. Repeatable; a pattern
    /// matching a directory prunes the whole subtree.
    pub exclude: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            baseline: None,
            max_file_bytes: 4 * 1024 * 1024,
            exclude: Vec::new(),
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

/// Glob match options for `--exclude`: `/` is a real separator (so `*`
/// doesn't cross directory boundaries, `**` does), matching is
/// case-sensitive, and leading dots need no special treatment.
fn exclude_match_options() -> MatchOptions {
    MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    }
}

/// Compile `--exclude` patterns once. An invalid pattern fails the scan
/// loudly — silently ignoring a user's exclusion would be a lie in CI.
fn compile_excludes(patterns: &[String]) -> anyhow::Result<Vec<Pattern>> {
    patterns
        .iter()
        .map(|p| Pattern::new(p).with_context(|| format!("invalid --exclude pattern '{p}'")))
        .collect()
}

/// Match a walkdir entry's root-relative path against the exclude patterns.
/// Both files and directories are checked so a matching directory prunes
/// its whole subtree.
fn is_excluded(root: &std::path::Path, path: &std::path::Path, excludes: &[Pattern]) -> bool {
    if excludes.is_empty() {
        return false;
    }
    let rel = path
        .strip_prefix(root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    // Also try the bare file name, so `--exclude '*.pem'` works without
    // a directory prefix.
    let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned());
    let opts = exclude_match_options();
    excludes.iter().any(|pat| {
        pat.matches_with(&rel, opts)
            || file_name
                .as_deref()
                .is_some_and(|n| pat.matches_with(n, opts))
    })
}

/// Walk `opts.root`, run every engine over every in-scope file, and return
/// the collected findings sorted by severity (descending), then path.
pub fn scan(opts: &ScanOptions) -> anyhow::Result<ScanReport> {
    let started = Instant::now();
    let excludes = compile_excludes(&opts.exclude)?;

    let engines: Vec<Box<dyn Engine>> = vec![
        Box::new(CodeEngine),
        Box::new(SecretsEngine),
        Box::new(ManifestEngine),
        Box::new(TlsConfEngine),
    ];

    let mut findings: Vec<Finding> = Vec::new();
    let mut files_scanned: u64 = 0;
    let mut files_skipped: u64 = 0;

    let walker = walkdir::WalkDir::new(&opts.root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            // Prune skipped directories before descending into them.
            if entry.file_type().is_dir() {
                if is_excluded(&opts.root, entry.path(), &excludes) {
                    return false;
                }
                if let Some(name) = entry.file_name().to_str() {
                    return !SKIP_DIRS.contains(&name);
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
        if is_excluded(&opts.root, path, &excludes) {
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
        // Skip likely-binary files early (NUL byte heuristic) — unless a
        // binary-tolerant engine (secrets, for DER blobs) claims the file.
        let looks_binary = content.iter().take(8192).any(|&b| b == 0);
        if looks_binary
            && !engines
                .iter()
                .any(|e| e.tolerates_binary() && e.file_matches(path))
        {
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

    // Baseline suppression: findings already triaged in the baseline file
    // are dropped before sorting/reporting. A missing or invalid baseline
    // fails the scan loudly — silently skipping suppression would hide the
    // misconfiguration in CI.
    if let Some(path) = opts.baseline.as_deref() {
        let baseline = Baseline::load(path)?;
        findings.retain(|f| !baseline.suppresses(f));
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

/// Relativize `path` against the scan root for display, falling back to the
/// full path. Context helper used by reporters.
// Week-1 API surface: consumed by reporters starting week 2.
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

    /// Binary DER files must reach the secrets engine, not die in the
    /// scanner's NUL-byte skip.
    #[test]
    fn binary_der_file_is_scanned_not_skipped() {
        let dir = std::env::temp_dir().join("snoot-scan-der");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let der = include_bytes!("../tests/fixtures/secrets/rsa_key.der");
        std::fs::write(dir.join("key.der"), der).unwrap();

        let opts = ScanOptions {
            root: dir.clone(),
            ..Default::default()
        };
        let report = scan(&opts).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "SNOOT003" && f.location.path.contains("key.der")),
            "expected SNOOT003 on key.der, got: {:?}",
            report
                .findings
                .iter()
                .map(|f| f.rule_id.clone())
                .collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A genuinely binary file no engine wants is still skipped.
    #[test]
    fn unwanted_binary_files_are_still_skipped() {
        let dir = std::env::temp_dir().join("snoot-scan-bin");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blob.bin"), [0x00, 0x01, 0x02, 0xFF, 0x00]).unwrap();

        let opts = ScanOptions {
            root: dir.clone(),
            ..Default::default()
        };
        let report = scan(&opts).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.stats.files_skipped, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--exclude` skips matching files; the fixture corpus holds real
    /// private keys by design, so self-scans exclude it.
    #[test]
    fn exclude_pattern_skips_matching_files() {
        let dir = std::env::temp_dir().join("snoot-scan-excl");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tests/fixtures")).unwrap();
        let pem = include_bytes!("../tests/fixtures/secrets/rsa_private.pem");
        std::fs::write(dir.join("tests/fixtures/key.pem"), pem).unwrap();
        std::fs::write(dir.join("src.rs"), "fn main() {}\n").unwrap();

        let without = scan(&ScanOptions {
            root: dir.clone(),
            ..Default::default()
        })
        .unwrap();
        assert!(
            without.findings.iter().any(|f| f.rule_id == "SNOOT003"),
            "fixture key should fire without --exclude"
        );

        let with = scan(&ScanOptions {
            root: dir.clone(),
            exclude: vec!["tests/fixtures/**".to_string()],
            ..Default::default()
        })
        .unwrap();
        assert!(
            with.findings.is_empty(),
            "excluded fixture should not fire: {:?}",
            with.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
        assert_eq!(with.stats.files_skipped, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bare file-name patterns work without a directory prefix, and a
    /// pattern matching a directory prunes the whole subtree.
    #[test]
    fn exclude_bare_filename_and_directory_prune() {
        let dir = std::env::temp_dir().join("snoot-scan-excl2");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        let pem = include_bytes!("../tests/fixtures/secrets/rsa_private.pem");
        std::fs::write(dir.join("keys/a.pem"), pem).unwrap();
        std::fs::write(dir.join("keys/b.pem"), pem).unwrap();

        let by_name = scan(&ScanOptions {
            root: dir.clone(),
            exclude: vec!["*.pem".to_string()],
            ..Default::default()
        })
        .unwrap();
        assert!(by_name.findings.is_empty());

        let by_dir = scan(&ScanOptions {
            root: dir.clone(),
            exclude: vec!["keys".to_string()],
            ..Default::default()
        })
        .unwrap();
        assert!(by_dir.findings.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An invalid glob fails the scan loudly instead of silently
    /// scanning everything.
    #[test]
    fn invalid_exclude_pattern_is_an_error() {
        let opts = ScanOptions {
            exclude: vec!["[unclosed".to_string()],
            ..Default::default()
        };
        let err = scan(&opts).unwrap_err();
        assert!(
            err.to_string().contains("invalid --exclude pattern"),
            "unexpected error: {err:#}"
        );
    }
}
