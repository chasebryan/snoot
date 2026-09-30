//! CBOM reporter: CycloneDX 1.6 Cryptography Bill of Materials.
//!
//! Emits `components` of type `cryptographic-asset` with `cryptoProperties`
//! derived from the snoot rule that fired. Key-size / mode extraction improves
//! as the secrets engine grows ASN.1 support.

use serde_json::{json, Value};

use crate::scanner::ScanReport;

fn key_size_from_detail(detail: &str) -> Option<u32> {
    // e.g. "RSA PRIVATE KEY (PKCS#1 PEM, 2048-bit)"
    let idx = detail.find("-bit")?;
    let start = detail[..idx].rfind(|c: char| !c.is_ascii_digit())? + 1;
    detail[start..idx].parse().ok()
}

fn primitive_for(rule_id: &str) -> (&'static str, &'static str) {
    match rule_id {
        "SNOOT001" | "SNOOT003" | "SNOOT011" => ("RSA", "key-agreement-or-signature"),
        "SNOOT002" | "SNOOT009" => ("ECDSA", "signature"),
        "SNOOT004" => ("DH", "key-agreement"),
        "SNOOT005" | "SNOOT018" => ("TLS", "protocol"),
        "SNOOT006" => ("ECDH", "key-agreement"),
        "SNOOT007" => ("DSA", "signature"),
        "SNOOT010" => ("private-key", "key"),
        "SNOOT008" => ("classical-signature", "signature"),
        "SNOOT012" => ("MD5", "hash"),
        "SNOOT013" => ("SHA-1", "hash"),
        "SNOOT014" => ("Ed25519", "signature"),
        "SNOOT015" => ("DES", "block-cipher"),
        "SNOOT016" => ("dependency", "library"),
        "SNOOT017" => ("JWK", "key"),
        "SNOOT019" => ("RC4", "stream-cipher"),
        "SNOOT020" => ("X.509", "certificate"),
        _ => ("unknown", "other"),
    }
}

/// Render the report as a CycloneDX 1.6 CBOM JSON document (as a string).
pub fn render(report: &ScanReport) -> String {
    let components: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let (primitive, purpose) = primitive_for(&f.rule_id);
            let param = key_size_from_detail(&f.evidence.detail);
            let mut alg = json!({
                "primitive": primitive,
                "executionEnvironment": "local",
                "purpose": purpose,
            });
            if let Some(bits) = param {
                alg["parameterSetIdentifier"] = json!(format!("{bits}"));
            }
            json!({
                "type": "cryptographic-asset",
                "name": f.title,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": alg,
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
                    { "name": "snoot:evidenceKind", "value": f.evidence.kind },
                    { "name": "snoot:evidenceDetail", "value": f.evidence.detail },
                ],
            })
        })
        .collect();

    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "snoot",
                    "version": env!("CARGO_PKG_VERSION"),
                }]
            },
        },
        "components": components,
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Finding};
    use crate::rules::RuleRegistry;
    use crate::scanner::{ScanReport, ScanStats};
    use std::path::PathBuf;

    #[test]
    fn cbom_maps_rsa_primitive() {
        let rule = RuleRegistry::by_id("SNOOT001").unwrap();
        let finding = Finding::new(
            &rule,
            "a.rs",
            Some(1),
            Some("Rsa::generate".into()),
            Evidence {
                kind: "api_call".into(),
                detail: "Rsa::generate".into(),
            },
        );
        let report = ScanReport {
            findings: vec![finding],
            stats: ScanStats::default(),
            root: PathBuf::from("."),
        };
        let out = render(&report);
        assert!(out.contains("\"primitive\": \"RSA\""), "{out}");
        assert!(out.contains("CycloneDX"));
    }
}
