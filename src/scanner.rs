//! Scan orchestration: walk the tree, dispatch per-file engines, collect findings.
//!
//! The scanner itself owns no detection logic — it walks files with `walkdir`,
//! asks each engine whether a file is in scope (`Engine::file_matches`), and
//! aggregates the findings. Code (Rust/Python) and PKCS#1 RSA PEM detection
//! are live; manifest and TLS engines still stub (week 3).

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context;
use serde::{Deserialize, Serialize};

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
