//! Baseline read/write and finding fingerprinting for suppression.
//!
//! **Job** (DESIGN.md §5): a baseline file records the fingerprints of
//! findings the team has already triaged, so `snoot scan --baseline
//! .snoot-baseline.json` only reports *new* findings — the standard CI
//! workflow for rolling a scanner out to a large existing codebase without
//! drowning in day-one noise.
//!
//! Fingerprints are `rule id + file + normalized snippet hash`
//! ([`Finding::fingerprint`](crate::model::Finding::fingerprint)), stable
//! across line shifts: moving code up or down doesn't unsuppress it, but
//! editing the matched snippet does (which is what you want — changed code
//! gets re-reported).
//!
//! `snoot init` writes a baseline from current findings.
//!
//! **Status**: week-4 milestone. Types and doc comments are real; load/write/
//! suppression logic lands in week 4.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::model::Finding;

/// On-disk baseline format (JSON).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    /// Fingerprints of suppressed findings.
    pub fingerprints: HashSet<String>,
}

// Week-1 API surface: load/write/suppression logic lands in week 4.
#[allow(dead_code)]
impl Baseline {
    /// Load a baseline file written by `snoot init`.
    pub fn load(_path: &Path) -> anyhow::Result<Self> {
        // Week 4: read JSON, validate version.
        anyhow::bail!("baseline support lands in week 4 (see DESIGN.md §13)")
    }

    /// Write current findings as a new baseline file.
    pub fn write(_path: &Path, _findings: &[Finding]) -> anyhow::Result<()> {
        // Week 4: serialize fingerprints to JSON.
        anyhow::bail!("baseline support lands in week 4 (see DESIGN.md §13)")
    }

    /// True when this finding was already recorded in the baseline.
    pub fn suppresses(&self, finding: &Finding) -> bool {
        let _ = finding;
        // Week 4: `self.fingerprints.contains(&finding.fingerprint)`.
        false
    }

    /// Parse a baseline from its JSON representation (used by tests).
    #[allow(dead_code)]
    fn from_json(s: &str) -> anyhow::Result<Self> {
        serde_json::from_str(s).with_context(|| "parsing baseline JSON")
    }
}
