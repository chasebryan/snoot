//! Baseline read/write and finding fingerprinting for suppression.
//!
//! A baseline file records fingerprints of findings the team has already
//! triaged, so `snoot scan --baseline .snoot-baseline.json` only reports
//! *new* findings. Fingerprints are `rule id + file + normalized snippet
//! hash` ([`Finding::fingerprint`]), stable across line shifts.
//!
//! `snoot init` writes a baseline from current findings.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::model::Finding;

/// Current on-disk baseline schema version.
pub const BASELINE_VERSION: u32 = 1;

/// On-disk baseline format (JSON).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    /// Fingerprints of suppressed findings.
    pub fingerprints: HashSet<String>,
}

impl Baseline {
    /// Load a baseline file written by `snoot init`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline {}", path.display()))?;
        let baseline: Self =
            serde_json::from_str(&text).with_context(|| "parsing baseline JSON")?;
        if baseline.version == 0 || baseline.version > BASELINE_VERSION {
            bail!(
                "unsupported baseline version {} (this snoot speaks v{BASELINE_VERSION})",
                baseline.version
            );
        }
        Ok(baseline)
    }

    /// Write current findings as a new baseline file.
    pub fn write(path: &Path, findings: &[Finding]) -> anyhow::Result<()> {
        let baseline = Self {
            version: BASELINE_VERSION,
            fingerprints: findings.iter().map(|f| f.fingerprint.clone()).collect(),
        };
        let text = serde_json::to_string_pretty(&baseline).context("serializing baseline JSON")?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        std::fs::write(path, text + "\n")
            .with_context(|| format!("writing baseline {}", path.display()))?;
        Ok(())
    }

    /// True when this finding was already recorded in the baseline.
    pub fn suppresses(&self, finding: &Finding) -> bool {
        self.fingerprints.contains(&finding.fingerprint)
    }

    /// Parse a baseline from its JSON representation (used by tests).
    #[cfg(test)]
    fn from_json(s: &str) -> anyhow::Result<Self> {
        serde_json::from_str(s).with_context(|| "parsing baseline JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Severity};
    use crate::rules::RuleRegistry;
    use std::path::PathBuf;

    fn sample_finding(snippet: &str) -> Finding {
        let rule = RuleRegistry::by_id("SNOOT001").unwrap();
        Finding::new(
            &rule,
            "src/keys.rs",
            Some(1),
            Some(snippet.to_string()),
            Evidence {
                kind: "api_call".to_string(),
                detail: snippet.to_string(),
            },
        )
    }

    #[test]
    fn round_trip_suppresses_same_fingerprint() {
        let dir = std::env::temp_dir().join("snoot-baseline-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".snoot-baseline.json");

        let f1 = sample_finding("Rsa::generate(&mut rng, 2048)");
        Baseline::write(&path, std::slice::from_ref(&f1)).unwrap();
        let loaded = Baseline::load(&path).unwrap();
        assert!(loaded.suppresses(&f1));

        // Line number is not part of the fingerprint — shifting code stays suppressed.
        let mut shifted = f1.clone();
        shifted.location.line = Some(99);
        assert!(loaded.suppresses(&shifted));

        // Edited snippet is a new finding.
        let edited = sample_finding("Rsa::generate(&mut rng, 4096)");
        assert!(!loaded.suppresses(&edited));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_json_rejects_garbage() {
        assert!(Baseline::from_json("not-json").is_err());
    }

    #[test]
    fn severity_ord_still_compiles() {
        // Touch Severity so rearranging imports doesn't trip unused warnings
        // if Finding construction changes.
        assert!(Severity::Critical > Severity::High);
        let _ = PathBuf::from(".");
    }
}
