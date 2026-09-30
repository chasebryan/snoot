//! SARIF 2.1.0 reports with relative URI locations and baseline fingerprints.

use crate::model::Severity;
use crate::rules::RuleRegistry;
use crate::scanner::ScanReport;
use serde_json::{json, Value};

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn uri_path(path: &str) -> String {
    let mut uri = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            uri.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(uri, "%{byte:02X}").unwrap();
        }
    }
    uri
}

fn root_uri(report: &ScanReport) -> String {
    let path = report.root.to_string_lossy().replace('\\', "/");
    let path = path.strip_prefix("//?/").unwrap_or(&path);
    let uri = if let Some(unc) = path.strip_prefix("//") {
        format!("file://{}", uri_path(unc))
    } else if path.as_bytes().get(1) == Some(&b':') {
        format!("file:///{}:{}", &path[..1], uri_path(&path[2..]))
    } else {
        format!("file://{}", uri_path(path))
    };
    format!("{}/", uri.trim_end_matches('/'))
}

pub fn render(report: &ScanReport) -> anyhow::Result<String> {
    let rules: Vec<Value> = RuleRegistry::all()
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "shortDescription": { "text": rule.title },
                "fullDescription": { "text": rule.description },
                "help": { "text": rule.remediation },
                "defaultConfiguration": { "level": level(rule.severity) },
            })
        })
        .collect();
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|finding| {
            let mut location = json!({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri_path(&finding.location.path), "uriBaseId": "%SRCROOT%"
                    },
                }
            });
            if let Some(line) = finding.location.line {
                let mut region = json!({ "startLine": line });
                if let Some(column) = finding.location.column {
                    region["startColumn"] = json!(column);
                }
                location["physicalLocation"]["region"] = region;
            }
            json!({
                "ruleId": finding.rule_id,
                "level": level(finding.severity),
                "message": { "text": format!("{} — {}", finding.title, finding.remediation) },
                "locations": [location],
                "partialFingerprints": { "snoot/v1": finding.fingerprint },
            })
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "snoot", "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/chasebryan/snoot", "rules": rules,
            } },
            "originalUriBaseIds": { "%SRCROOT%": { "uri": root_uri(report) } },
            "invocations": [{ "executionSuccessful": true }],
            "results": results,
        }],
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_reserved_and_non_ascii_filename_bytes() {
        assert_eq!(uri_path("src/a b#%?.py"), "src/a%20b%23%25%3F.py");
        assert_eq!(uri_path("src/é.py"), "src/%C3%A9.py");
    }
}
