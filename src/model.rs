//! Core data model: findings, severities, rules, locations, evidence.
//!
//! Everything the scanner produces and every reporter consumes is built from
//! these types. They are serde-serializable so JSON output is free.

use std::fmt;
use std::str::FromStr;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Severity model (v1, deliberately simple — HNDL-aware but explainable).
/// See DESIGN.md §6.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum Severity {
    /// Inventory-only: crypto found, no action needed (feeds the CBOM).
    Info,
    /// Deprecated-but-not-quantum-relevant (MD5, SHA-1, DES) — hygiene flag.
    Low,
    /// Classical crypto in dependencies, test code, or TLS configs without PQC hybrid.
    Medium,
    /// Classical public-key usage (encrypt, sign, key exchange) in application code.
    High,
    /// Private key material for classical algorithms, or signing with
    /// RSA/ECDSA on long-lived artifacts.
    Critical,
}

impl Severity {
    fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// True when `self` is at least as severe as `min` (for `--fail-on`).
    pub fn at_least(self, min: Severity) -> bool {
        self.rank() >= min.rank()
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        f.write_str(s)
    }
}

impl FromStr for Severity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => {
                anyhow::bail!("unknown severity '{other}' (expected info|low|medium|high|critical)")
            }
        }
    }
}

/// Output formats for `snoot scan --format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum OutputFormat {
    Console,
    Sarif,
    Cbom,
    Json,
}

/// Where a finding lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Path relative to the scan root, using `/` separators.
    pub path: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
    /// The matched source snippet (truncated by the engine).
    pub snippet: Option<String>,
}

/// What the engine actually saw: the raw material behind a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// e.g. "api_call", "pem_block", "manifest_dep", "tls_config".
    pub kind: String,
    pub detail: String,
}

/// A single detected instance of classical crypto usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub location: Location,
    pub evidence: Evidence,
    pub remediation: String,
    /// Optional pointer at what orange can verify/replace (the front door).
    pub orange_note: Option<String>,
    /// Stable fingerprint (rule id + file + normalized snippet hash) so
    /// baselines survive line shifts. See DESIGN.md §5.
    pub fingerprint: String,
}

impl Finding {
    // Week-1 API surface: constructed by engines starting week 2.
    #[allow(dead_code)]
    pub fn new(
        rule: &Rule,
        path: impl Into<String>,
        line: Option<u32>,
        snippet: Option<String>,
        evidence: Evidence,
    ) -> Self {
        let path = path.into();
        let snippet_norm = snippet.as_deref().unwrap_or("").trim();
        let fingerprint = Self::fingerprint(&rule.id, &path, snippet_norm);
        Self {
            rule_id: rule.id.clone(),
            severity: rule.severity,
            title: rule.title.clone(),
            location: Location {
                path,
                line,
                column: None,
                snippet,
            },
            evidence,
            remediation: rule.remediation.clone(),
            orange_note: rule.orange_note.clone(),
            fingerprint,
        }
    }

    /// Deterministic 64-bit FNV-1a hex. No extra dependencies, stable across runs.
    // Week-1 API surface: used by baseline suppression starting week 4.
    #[allow(dead_code)]
    pub fn fingerprint(rule_id: &str, path: &str, snippet: &str) -> String {
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in format!("{rule_id}\0{path}\0{snippet}").bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("{hash:016x}")
    }
}

/// A detection rule: data, not code. See DESIGN.md §5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// e.g. "SNOOT001".
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    /// Classical → PQC migration mapping (DESIGN.md §6).
    pub remediation: String,
    /// Per-language tree-sitter queries used by the code engine.
    pub queries: Vec<LanguageQuery>,
    /// CWE reference where one exists, e.g. "CWE-327".
    pub cwe: Option<String>,
    /// Optional "verifiable with orange" pointer (the front door, DESIGN.md §9).
    pub orange_note: Option<String>,
}

/// One tree-sitter query for one language, attached to a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageQuery {
    /// "rust", "python", "go", "javascript", "typescript", "java", "c", "cpp".
    pub language: String,
    /// tree-sitter query source. Validated when the code engine lands (week 2).
    pub query: String,
}
