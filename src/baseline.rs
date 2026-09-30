//! Versioned, deterministic baselines containing fingerprints only.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};

use crate::model::Finding;

const VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub version: u32,
    pub fingerprints: BTreeSet<String>,
}

impl Baseline {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline {}", path.display()))?;
        Self::from_json(&json).with_context(|| format!("loading baseline {}", path.display()))
    }

    /// Publish a complete file atomically. Existing baselines require --force.
    pub fn write(path: &Path, findings: &[Finding], overwrite: bool) -> anyhow::Result<()> {
        let baseline = Self {
            version: VERSION,
            fingerprints: findings.iter().map(|f| f.fingerprint.clone()).collect(),
        };
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating baseline directory {}", parent.display()))?;
        let mut file = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("creating baseline in {}", parent.display()))?;
        serde_json::to_writer_pretty(&mut file, &baseline)?;
        writeln!(file)?;
        file.as_file().sync_all()?;
        if overwrite {
            file.persist(path)
                .with_context(|| format!("replacing baseline {}", path.display()))?;
        } else {
            file.persist_noclobber(path).with_context(|| {
                format!(
                    "writing baseline {} (use --force to replace an existing file)",
                    path.display()
                )
            })?;
        }
        Ok(())
    }

    pub fn suppresses(&self, finding: &Finding) -> bool {
        self.fingerprints.contains(&finding.fingerprint)
    }

    fn from_json(json: &str) -> anyhow::Result<Self> {
        let baseline: Self = serde_json::from_str(json).context("parsing baseline JSON")?;
        ensure!(
            baseline.version == VERSION,
            "unsupported baseline version {} (expected {VERSION})",
            baseline.version
        );
        ensure!(baseline.fingerprints.iter().all(|fp| {
            fp.len() == 16 && fp.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }), "baseline contains an invalid fingerprint (expected 16 lowercase hexadecimal characters)");
        Ok(baseline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_or_future_baselines() {
        for json in [
            "not json",
            r#"{"version":2,"fingerprints":[]}"#,
            r#"{"fingerprints":[]}"#,
            r#"{"version":1,"fingerprints":["typo"]}"#,
            r#"{"version":1,"fingerprints":[],"fingerprint":[]}"#,
        ] {
            assert!(Baseline::from_json(json).is_err(), "accepted {json}");
        }
    }
}
