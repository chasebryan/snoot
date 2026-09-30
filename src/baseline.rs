//! Baseline read/write and finding fingerprinting for suppression.
//!
//! **Job** (DESIGN.md §5): a baseline file records the fingerprints of
//! findings the team has already triaged, so `snoot scan --baseline
//! .snoot-baseline.json` only reports *new* findings — the standard CI
//! workflow for rolling a scanner out to a large existing codebase without
//! drowning in day-one noise.
//!
//! Fingerprints are `rule id + file + normalized snippet + evidence detail`
//! ([`Finding::fingerprint`](crate::model::Finding::fingerprint)), stable
//! across line shifts: moving code up or down doesn't unsuppress it, but
//! editing the matched snippet does (which is what you want — changed code
//! gets re-reported).
//!
//! `snoot init` writes a baseline from current findings.
//!
//! **Status**: week-3 milestone, implemented.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::model::Finding;

/// Baseline format version. Bumped if the fingerprint scheme ever changes.
const BASELINE_VERSION: u32 = 1;

/// On-disk baseline format (JSON).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    /// Fingerprints of suppressed findings. A `BTreeSet` so the on-disk
    /// file is always written in sorted (deterministic, diffable) order.
    pub fingerprints: BTreeSet<String>,
}

impl Baseline {
    /// Load a baseline file written by `snoot init`. Fails loudly on a
    /// missing file, bad JSON, or a version mismatch — silently skipping
    /// suppression would be worse than failing in CI.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline {}", path.display()))?;
        let baseline: Baseline = serde_json::from_str(&raw)
            .with_context(|| format!("parsing baseline {} as JSON", path.display()))?;
        if baseline.version != BASELINE_VERSION {
            anyhow::bail!(
                "baseline {} has version {}, this snoot writes version {BASELINE_VERSION} \
                 (re-run `snoot init`)",
                path.display(),
                baseline.version,
            );
        }
        Ok(baseline)
    }

    /// Write current findings as a new baseline file. Fingerprints are
    /// sorted so the file is deterministic across runs.
    pub fn write(path: &Path, findings: &[Finding]) -> anyhow::Result<()> {
        let mut fingerprints: Vec<String> =
            findings.iter().map(|f| f.fingerprint.clone()).collect();
        fingerprints.sort();
        fingerprints.dedup();
        let baseline = Baseline {
            version: BASELINE_VERSION,
            fingerprints: fingerprints.into_iter().collect(),
        };
        let raw = serde_json::to_string_pretty(&baseline)?;
        std::fs::write(path, raw)
            .with_context(|| format!("writing baseline {}", path.display()))?;
        Ok(())
    }

    /// True when this finding was already recorded in the baseline.
    pub fn suppresses(&self, finding: &Finding) -> bool {
        self.fingerprints.contains(&finding.fingerprint)
    }

    /// Parse a baseline from its JSON representation (used by tests).
    #[allow(dead_code)]
    fn from_json(s: &str) -> anyhow::Result<Self> {
        serde_json::from_str(s).with_context(|| "parsing baseline JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Location};
    use crate::rules::RuleRegistry;

    fn finding(rule_id: &str, path: &str, snippet: &str) -> Finding {
        let rule = RuleRegistry::by_id(rule_id).unwrap();
        Finding {
            rule_id: rule.id.clone(),
            severity: rule.severity,
            title: rule.title.clone(),
            location: Location {
                path: path.to_string(),
                line: Some(1),
                column: None,
                snippet: Some(snippet.to_string()),
            },
            evidence: Evidence {
                kind: "test".to_string(),
                detail: "test".to_string(),
            },
            remediation: rule.remediation.clone(),
            orange_note: None,
            fingerprint: Finding::fingerprint(&rule.id, path, snippet.trim(), "test"),
        }
    }

    #[test]
    fn round_trip_suppresses_recorded_findings() {
        let dir = std::env::temp_dir().join("snoot-baseline-rt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");

        let f1 = finding("SNOOT001", "a.rs", "Rsa::generate(2048)");
        let f2 = finding("SNOOT013", "b.py", "hashlib.md5()");
        Baseline::write(&path, &[f1.clone(), f2.clone()]).unwrap();

        let loaded = Baseline::load(&path).unwrap();
        assert_eq!(loaded.fingerprints.len(), 2);
        assert!(loaded.suppresses(&f1));
        assert!(loaded.suppresses(&f2));
        // A different snippet is a different finding — not suppressed.
        let f3 = finding("SNOOT001", "a.rs", "Rsa::generate(4096)");
        assert!(!loaded.suppresses(&f3));
        // Same snippet, moved file — not suppressed (path is in the hash).
        let f4 = finding("SNOOT001", "c.rs", "Rsa::generate(2048)");
        assert!(!loaded.suppresses(&f4));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_bad_version() {
        let bad = r#"{"version": 99, "fingerprints": []}"#;
        let loaded: Baseline = serde_json::from_str(bad).unwrap();
        assert_eq!(loaded.version, 99);
        // from_json parses; load() validates the version. Exercise via file.
        let dir = std::env::temp_dir().join("snoot-baseline-ver");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        std::fs::write(&path, bad).unwrap();
        assert!(Baseline::load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_missing_file() {
        let missing = std::env::temp_dir().join("snoot-baseline-nope/missing.json");
        assert!(Baseline::load(&missing).is_err());
    }

    #[test]
    fn write_is_deterministic() {
        let dir = std::env::temp_dir().join("snoot-baseline-det");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p1 = dir.join("a.json");
        let p2 = dir.join("b.json");
        let f1 = finding("SNOOT001", "a.rs", "Rsa::generate(2048)");
        let f2 = finding("SNOOT002", "a.rs", "SigningKey::random(&mut rng)");
        Baseline::write(&p1, &[f1.clone(), f2.clone()]).unwrap();
        Baseline::write(&p2, &[f2, f1]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&p1).unwrap(),
            std::fs::read_to_string(&p2).unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
