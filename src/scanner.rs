//! Walk a source tree, dispatch engines, normalize paths, and apply a baseline.

use std::collections::HashSet;
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{ensure, Context};
use glob::{MatchOptions, Pattern};
use serde::{Deserialize, Serialize};

use crate::baseline::Baseline;
use crate::engines::{CodeEngine, Engine, ManifestEngine, SecretsEngine, TlsConfEngine};
use crate::ignore::{self, IgnoreList};
use crate::model::Finding;

#[derive(Debug)]
pub struct ScanOptions {
    pub root: PathBuf,
    pub baseline: Option<PathBuf>,
    /// Report and baseline outputs must not be scanned as source inputs.
    pub excluded_paths: Vec<PathBuf>,
    pub max_file_bytes: u64,
    pub exclude: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            baseline: None,
            excluded_paths: Vec::new(),
            max_file_bytes: 4 * 1024 * 1024,
            exclude: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub findings_suppressed: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    /// Absolute directory against which finding paths are relative.
    pub root: PathBuf,
}

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

pub fn scan(opts: &ScanOptions) -> anyhow::Result<ScanReport> {
    let started = Instant::now();
    let excludes = compile_excludes(&opts.exclude)?;
    let root = opts
        .root
        .canonicalize()
        .with_context(|| format!("opening scan path {}", opts.root.display()))?;
    ensure!(
        root.is_file() || root.is_dir(),
        "scan path must be a file or directory"
    );
    let source_root = if root.is_file() {
        root.parent().unwrap().to_path_buf()
    } else {
        root.clone()
    };
    let ignore = IgnoreList::load_from_root(&source_root)?;
    // Fail before scanning if suppression was requested but cannot be trusted.
    let baseline = opts.baseline.as_deref().map(Baseline::load).transpose()?;
    let excluded: Vec<_> = opts
        .excluded_paths
        .iter()
        .chain(opts.baseline.iter())
        .filter_map(|path| path.canonicalize().ok())
        .collect();

    let engines: Vec<Box<dyn Engine>> = vec![
        Box::new(CodeEngine),
        Box::new(SecretsEngine),
        Box::new(ManifestEngine),
        Box::new(TlsConfEngine),
    ];
    let mut findings = Vec::new();
    let mut stats = ScanStats::default();
    let walker = walkdir::WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 || !entry.file_type().is_dir() {
                return true;
            }
            let relative = ignore::rel_path(&source_root, entry.path());
            !entry
                .file_name()
                .to_str()
                .is_some_and(|name| SKIP_DIRS.contains(&name))
                && !ignore.ignores_dir(&relative.to_string_lossy())
                && !is_excluded(&source_root, entry.path(), &excludes)
        });

    for entry in walker {
        // An unreadable subtree must never turn into a successful clean scan.
        let entry = entry.context("walking scan path")?;
        if !entry.file_type().is_file() {
            if entry.file_type().is_symlink() {
                stats.files_skipped += 1;
            }
            continue;
        }
        let path = entry.path();
        let relative = path
            .strip_prefix(&source_root)
            .context("normalizing finding path")?;
        if is_excluded(&source_root, path, &excludes)
            || ignore.ignores(&relative.to_string_lossy())
            || excluded.iter().any(|excluded| path == excluded)
            || !engines.iter().any(|engine| engine.file_matches(relative))
        {
            stats.files_skipped += 1;
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        if metadata.len() > opts.max_file_bytes {
            stats.files_skipped += 1;
            continue;
        }
        let file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut content = Vec::new();
        // Cap the read in case a file grows after its metadata was checked.
        file.take(opts.max_file_bytes.saturating_add(1))
            .read_to_end(&mut content)
            .with_context(|| format!("reading {}", path.display()))?;
        let binary = content.contains(&0) || std::str::from_utf8(&content).is_err();
        let binary_candidate = content.first() == Some(&0x30)
            && engines
                .iter()
                .any(|e| e.tolerates_binary() && e.file_matches(relative));
        if content.len() as u64 > opts.max_file_bytes || (binary && !binary_candidate) {
            stats.files_skipped += 1;
            continue;
        }
        stats.files_scanned += 1;
        for engine in &engines {
            if engine.file_matches(relative) && (!binary || engine.tolerates_binary()) {
                engine.validate(relative, &content).with_context(|| {
                    format!("validating {} with {}", relative.display(), engine.name())
                })?;
                findings.extend(engine.scan(relative, &content));
            }
        }
    }

    // Queries may report the same call more than once; retain distinct locations.
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.fingerprint.clone(), f.location.line, f.location.column)));
    demote_test_path_severity(&mut findings);
    if let Some(baseline) = baseline {
        findings.retain(|finding| {
            if baseline.suppresses(finding) {
                stats.findings_suppressed += 1;
                false
            } else {
                true
            }
        });
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.location.path.cmp(&b.location.path))
            .then_with(|| a.location.line.cmp(&b.location.line))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    stats.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(ScanReport {
        findings,
        stats,
        root: source_root,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Severity};
    use crate::rules::RuleRegistry;

    #[test]
    fn skips_large_binary_and_non_utf8_files_and_prunes_build_output() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("large.py"), vec![b'a'; 101]).unwrap();
        std::fs::write(dir.path().join("binary.py"), b"rsa.newkeys(2048)\0").unwrap();
        std::fs::write(dir.path().join("invalid.py"), [0xff]).unwrap();
        std::fs::write(dir.path().join("good.py"), b"rsa.newkeys(2048)").unwrap();
        std::fs::create_dir(dir.path().join("target")).unwrap();
        std::fs::write(dir.path().join("target/ignored.py"), b"rsa.newkeys(2048)").unwrap();
        let report = scan(&ScanOptions {
            root: dir.path().to_owned(),
            max_file_bytes: 100,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].location.path, "good.py");
        assert_eq!(report.stats.files_skipped, 3);
        assert_eq!(report.stats.files_scanned, 1);
    }
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
