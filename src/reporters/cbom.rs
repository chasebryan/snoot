//! CBOM reporter: CycloneDX 1.6 Cryptography Bill of Materials.
//!
//! The compliance artifact (DESIGN.md §8): what OMB M-23-02's inventory
//! mandate and enterprise auditors actually want — a machine-readable list of
//! every cryptographic asset found, with algorithm properties per finding.
//!
//! Emits a minimal CycloneDX 1.6 document: `components` of type
//! `cryptographic-asset`, each carrying `cryptoProperties` with the algorithm
//! name and the snoot rule that found it. Week 4 hardens this: key sizes,
//! modes, protocol refs, and asset relations.

use serde_json::{json, Value};

use crate::scanner::ScanReport;

/// Render the report as a CycloneDX 1.6 CBOM JSON document (as a string).
pub fn render(report: &ScanReport) -> String {
    let components: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            json!({
                "type": "cryptographic-asset",
                "name": f.title,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        // Week 4: proper primitive names + parameterSetIdentifier
                        // (e.g. "RSA", "2048") extracted from evidence.
                        "primitive": f.title,
                    },
                },
                "evidence": {
                    "occurrences": [{
                        "location": f.location.path,
                        "line": f.location.line,
                    }],
                },
                "properties": [
                    { "name": "snoot:ruleId", "value": f.rule_id },
                    { "name": "snoot:severity", "value": f.severity.to_string() },
                    { "name": "snoot:fingerprint", "value": f.fingerprint },
                ],
            })
        })
        .collect();

    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": [{
                "name": "snoot",
                "version": env!("CARGO_PKG_VERSION"),
            }],
        },
        "components": components,
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}
