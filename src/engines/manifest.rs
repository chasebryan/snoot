//! Manifest engine: dependency-manifest scanning.
//!
//! **Job** (DESIGN.md §5): parse dependency manifests *properly* — TOML for
//! Cargo, JSON for npm, the go.mod DSL, requirements.txt / poetry / uv
//! formats, Maven POM XML, Gemfiles — and flag dependencies that pull in
//! classical crypto (e.g. old `ring`/`rust-crypto` versions, unmaintained
//! RSA-only libraries, vendored OpenSSL < 3.x without provider PQC support).
//!
//! Manifests are parsed, never regexed: a version requirement like
//! `rsa = ">=0.9"` needs real version-range reasoning, not substring matching.
//!
//! v1 covers direct dependencies only (DESIGN.md §3: transitive analysis is
//! explicitly out of scope — that's v2's lockfile graph walk).
//!
//! **Status**: week-3 milestone. File matching is real; per-ecosystem parsers
//! land in week 3.

use std::path::Path;

use crate::engines::Engine;
use crate::model::Finding;

pub struct ManifestEngine;

/// Manifest file names this engine understands, per ecosystem.
const MANIFEST_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "go.mod",
    "go.sum",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
];

impl Engine for ManifestEngine {
    fn name(&self) -> &'static str {
        "manifest"
    }

    fn file_matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| MANIFEST_FILES.contains(&n))
            .unwrap_or(false)
    }

    fn scan(&self, _path: &Path, _content: &[u8]) -> Vec<Finding> {
        // Week 3: parse per ecosystem, resolve each dependency's declared
        // version range, check against the known-classical-crypto table
        // (shipped in the binary — no network calls, DESIGN.md §5).
        // Emits medium-severity findings for classical crypto in deps.
        Vec::new()
    }
}
