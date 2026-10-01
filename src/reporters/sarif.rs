//! SARIF reporter: SARIF 2.1.0 for GitHub code scanning integration.
//!
//! This is the distribution hack (DESIGN.md §8): upload the SARIF to GitHub
//! code scanning and findings render as PR annotations where developers work.
//!
//! Emits a SARIF 2.1.0 document validated against the schema's required
//! structure (see the `sarif_output_conforms` test): tool driver metadata
//! with the full rule table, one result per finding with `ruleId` +
//! `ruleIndex`, `level`, `message.text`, and a physical location, plus an
//! `invocations` block. Severity mapping: critical/high → error,
//! medium → warning, low/info → note.

use std::collections::HashMap;

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

fn uri_path(path: &str) -> String {
    let mut encoded = String::new();
    for byte in path.replace('\\', "/").bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(&mut encoded, "%{byte:02X}").expect("writing a string");
        }
    }
    encoded
}

/// Render the report as a SARIF 2.1.0 JSON document (returned as a string).
pub fn render(report: &ScanReport) -> anyhow::Result<String> {
    let registry = RuleRegistry::all();
    let rule_index: HashMap<&str, usize> = registry
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();

    let rules: Vec<Value> = registry
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
            let mut physical_location = json!({
                "artifactLocation": { "uri": uri_path(&f.location.path) },
            });
            // Always emit a region: whole-file findings (DER blobs, JWK)
            // have no line number, so they point at line 1.
            let mut region = json!({ "startLine": f.location.line.unwrap_or(1) });
            if let Some(column) = f.location.column {
                region["startColumn"] = json!(column);
            }
            if let Some(snippet) = &f.location.snippet {
                region["snippet"] = json!({ "text": snippet });
            }
            physical_location["region"] = region;
            let mut result = json!({
                "ruleId": f.rule_id,
                "level": level(f.severity),
                "message": { "text": format!("{} — {}", f.title, f.remediation) },
                "locations": [{ "physicalLocation": physical_location }],
                "partialFingerprints": { "snoot/v1": f.fingerprint },
            });
            if let Some(idx) = rule_index.get(f.rule_id.as_str()) {
                result["ruleIndex"] = json!(idx);
            }
            result
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "snoot",
                    "fullName": "snoot — PQC crypto inventory scanner",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/chasebryan/snoot",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
            }],
        }],
    });

    Ok(serde_json::to_string_pretty(&doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Finding, Location};
    use crate::scanner::{ScanReport, ScanStats};
    use std::path::PathBuf;

    fn finding(rule_id: &str, line: Option<u32>) -> Finding {
        let rule = RuleRegistry::by_id(rule_id).unwrap();
        Finding {
            rule_id: rule.id.clone(),
            severity: rule.severity,
            title: rule.title.clone(),
            location: Location {
                path: "src/auth.rs".to_string(),
                line,
                column: Some(5),
                snippet: Some("Rsa::generate(2048)".to_string()),
            },
            evidence: Evidence {
                kind: "api_call".to_string(),
                detail: "test".to_string(),
            },
            remediation: rule.remediation.clone(),
            orange_note: None,
            fingerprint: Finding::fingerprint(
                &rule.id,
                "src/auth.rs",
                "Rsa::generate(2048)",
                "test",
            ),
        }
    }

    fn report() -> ScanReport {
        ScanReport {
            findings: vec![
                finding("SNOOT001", Some(42)), // high → error
                finding("SNOOT013", Some(7)),  // low → note
                finding("SNOOT016", None),     // medium → warning, no line
            ],
            stats: ScanStats::default(),
            root: PathBuf::from("."),
        }
    }

    /// Schema-conformance gate: the SARIF we emit must carry every field
    /// GitHub code scanning and the SARIF 2.1.0 schema require. This is a
    /// structural validation (required fields, value domains, cross-refs),
    /// not a vendored copy of the full JSON schema.
    #[test]
    fn sarif_output_conforms() {
        let doc: Value = serde_json::from_str(&render(&report()).unwrap()).unwrap();

        assert_eq!(doc["version"], "2.1.0");
        assert!(
            doc["$schema"].as_str().unwrap().contains("sarif-2.1.0"),
            "missing/wrong $schema"
        );

        let runs = doc["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        let run = &runs[0];

        // Tool driver.
        let driver = &run["tool"]["driver"];
        assert_eq!(driver["name"], "snoot");
        assert!(!driver["version"].as_str().unwrap().is_empty());
        let rules = driver["rules"].as_array().unwrap();
        assert!(!rules.is_empty());
        let rule_ids: Vec<&str> = rules
            .iter()
            .map(|r| {
                assert!(!r["id"].as_str().unwrap().is_empty());
                assert!(!r["name"].as_str().unwrap().is_empty());
                assert!(!r["shortDescription"]["text"].as_str().unwrap().is_empty());
                r["id"].as_str().unwrap()
            })
            .collect();

        // Invocations block.
        assert_eq!(run["invocations"][0]["executionSuccessful"], true);

        // Results.
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        for result in results {
            let rule_id = result["ruleId"].as_str().unwrap();
            assert!(
                rule_ids.contains(&rule_id),
                "result references unknown rule {rule_id}"
            );
            let idx = result["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[idx]["id"].as_str().unwrap(), rule_id);

            let level = result["level"].as_str().unwrap();
            assert!(
                ["error", "warning", "note"].contains(&level),
                "bad level {level}"
            );
            assert!(!result["message"]["text"].as_str().unwrap().is_empty());

            let phys = &result["locations"][0]["physicalLocation"];
            assert!(!phys["artifactLocation"]["uri"].as_str().unwrap().is_empty());
            if let Some(region) = phys.get("region") {
                assert!(region["startLine"].as_u64().unwrap() >= 1);
            }
            assert!(!result["partialFingerprints"]["snoot/v1"]
                .as_str()
                .unwrap()
                .is_empty());
        }

        // Severity mapping spot-checks.
        let by_rule: HashMap<&str, &str> = results
            .iter()
            .map(|r| (r["ruleId"].as_str().unwrap(), r["level"].as_str().unwrap()))
            .collect();
        assert_eq!(by_rule["SNOOT001"], "error");
        assert_eq!(by_rule["SNOOT013"], "note");
        assert_eq!(by_rule["SNOOT016"], "warning");
    }

    #[test]
    fn sarif_empty_report_is_valid() {
        let empty = ScanReport {
            findings: vec![],
            stats: ScanStats::default(),
            root: PathBuf::from("."),
        };
        let doc: Value = serde_json::from_str(&render(&empty).unwrap()).unwrap();
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert!(!doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
