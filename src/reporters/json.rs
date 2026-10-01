//! JSON reporter: the full finding objects, for piping into other tools.

use crate::scanner::ScanReport;

/// Pretty-printed JSON: `{ "version", "findings": [...], "stats": {...} }`.
pub fn render(report: &ScanReport) -> anyhow::Result<String> {
    let doc = serde_json::json!({
        "tool": "snoot",
        "version": env!("CARGO_PKG_VERSION"),
        "findings": report.findings,
        "stats": report.stats,
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}
