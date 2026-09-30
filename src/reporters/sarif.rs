//! SARIF reporter: SARIF 2.1.0 for GitHub code scanning integration.
//!
//! This is the distribution hack (DESIGN.md §8): upload the SARIF to GitHub
//! code scanning and findings render as PR annotations where developers work.
//!
//! Emits a minimal but valid SARIF 2.1.0 document: tool driver metadata with
//! the rule table, plus one result per finding with rule id, level, message,
//! and physical location. Severity mapping: critical/high → error,
//! medium → warning, low/info → note.

use serde_json::{json, Value};

use crate::model::Severity;
use crate::rules::RuleRegistry;
use crate::scanner::ScanReport;

fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Render the report as a SARIF 2.1.0 JSON document (returned as a string).
pub fn render(report: &ScanReport) -> String {
    let rules: Vec<Value> = RuleRegistry::all()
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "name": rule.title,
                "shortDescription": { "text": rule.title },
                "fullDescription": { "text": rule.description },
                "help": { "text": rule.remediation },
            })
        })
        .collect();

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut location = json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": f.location.path },
                }
            });
            if let Some(line) = f.location.line {
                location["physicalLocation"]["region"] = json!({ "startLine": line });
            }
            json!({
                "ruleId": f.rule_id,
                "level": level(f.severity),
                "message": { "text": format!("{} — {}", f.title, f.remediation) },
                "locations": [location],
                "fingerprints": { "snoot/v1": f.fingerprint },
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "snoot",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/chasebryan/snoot",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}
