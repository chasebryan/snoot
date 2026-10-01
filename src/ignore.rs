//! `.snootignore` — gitignore-style path exclusions for scans.
//!
//! Loaded from `{scan_root}/.snootignore` when present. Patterns are matched
//! against paths relative to the scan root using `/` separators. Supports:
//! - `#` comments and blank lines
//! - directory patterns ending in `/` (prefix match on that directory)
//! - simple `*` wildcards (not `**`)
//! - exact relative paths

use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct IgnoreList {
    patterns: Vec<Pattern>,
}

#[derive(Debug, Clone)]
enum Pattern {
    /// Directory prefix, e.g. `tests/fixtures/` matches anything under it.
    DirPrefix(String),
    /// Exact relative path.
    Exact(String),
    /// Glob with a single `*` segment wildcard (substring style).
    Glob(String),
}

impl IgnoreList {
    /// Load from `{root}/.snootignore`. Missing file → empty list.
    pub fn load_from_root(root: &Path) -> anyhow::Result<Self> {
        use anyhow::Context;
        let path = root.join(".snootignore");
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Self::parse(&text)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err).with_context(|| format!("reading ignore file {}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Self {
        let mut patterns = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let normalized = line.replace('\\', "/").trim_start_matches("./").to_string();
            if normalized.ends_with('/') {
                patterns.push(Pattern::DirPrefix(normalized));
            } else if normalized.contains('*') {
                patterns.push(Pattern::Glob(normalized));
            } else {
                patterns.push(Pattern::Exact(normalized));
            }
        }
        Self { patterns }
    }

    /// True if a path relative to the scan root should be skipped.
    pub fn ignores(&self, rel: &str) -> bool {
        let rel = rel.replace('\\', "/");
        let rel = rel.trim_start_matches("./");
        for pat in &self.patterns {
            match pat {
                Pattern::DirPrefix(prefix) => {
                    if rel.starts_with(prefix) || rel == prefix.trim_end_matches('/') {
                        return true;
                    }
                    // Also skip the directory entry itself during walk pruning.
                    if prefix.trim_end_matches('/') == rel {
                        return true;
                    }
                }
                Pattern::Exact(exact) => {
                    if rel == exact {
                        return true;
                    }
                }
                Pattern::Glob(glob) => {
                    if glob_match(glob, rel) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// True if a directory (relative path) should not be descended into.
    pub fn ignores_dir(&self, rel_dir: &str) -> bool {
        let rel = rel_dir.replace('\\', "/");
        let rel = rel.trim_start_matches("./").trim_end_matches('/');
        for pat in &self.patterns {
            if let Pattern::DirPrefix(prefix) = pat {
                let p = prefix.trim_end_matches('/');
                if rel == p || rel.starts_with(&format!("{p}/")) {
                    return true;
                }
            }
        }
        false
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    // Minimal `*` matcher: split on `*` and require sequential contains.
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return path == pattern;
    }
    let mut rest = path;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
        } else if i == parts.len() - 1 {
            if !rest.ends_with(part) {
                return false;
            }
        } else if let Some(idx) = rest.find(part) {
            rest = &rest[idx + part.len()..];
        } else {
            return false;
        }
    }
    true
}

/// Relativize `path` against `root` for ignore matching.
pub fn rel_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_prefix_ignores_nested() {
        let ig = IgnoreList::parse("tests/fixtures/\n");
        assert!(ig.ignores("tests/fixtures/positive/rust/rsa_gen.rs"));
        assert!(ig.ignores_dir("tests/fixtures"));
        assert!(!ig.ignores("src/main.rs"));
    }

    #[test]
    fn exact_and_glob() {
        let ig = IgnoreList::parse("secrets/dev.key\n*.pem\n");
        assert!(ig.ignores("secrets/dev.key"));
        assert!(ig.ignores("certs/leaf.pem"));
        assert!(!ig.ignores("certs/leaf.crt"));
    }
}
