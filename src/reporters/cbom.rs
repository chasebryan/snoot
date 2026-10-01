//! CycloneDX 1.6 inventory using schema-defined asset types and primitives.
use crate::model::Finding;
use crate::scanner::ScanReport;
use serde_json::{json, Value};

fn crypto_properties(f: &Finding) -> Option<Value> {
    let format = match f.evidence.kind.as_str() {
        "der_blob" => "DER",
        "jwk" => "JWK",
        _ => "PEM",
    };
    match f.rule_id.as_str() {
        "SNOOT003" | "SNOOT009" | "SNOOT015" => {
            let mut material = json!({"type": "private-key", "format": format});
            if let Some(bits) = f
                .evidence
                .detail
                .split_whitespace()
                .find_map(|w| w.strip_suffix("-bit")?.parse::<u32>().ok())
            {
                material["size"] = json!(bits);
            }
            return Some(
                json!({"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": material}),
            );
        }
        "SNOOT005" | "SNOOT018" | "SNOOT019" => {
            return Some(json!({"assetType": "protocol", "protocolProperties": {"type": "tls"}}))
        }
        "SNOOT020" | "SNOOT021" => {
            return Some(
                json!({"assetType": "certificate", "certificateProperties": {"certificateFormat": format}}),
            )
        }
        // A dependency establishes neither a particular algorithm nor active use.
        "SNOOT016" | "SNOOT017" => return None,
        "SNOOT022" => {
            if f.evidence.kind == "x509_cert" || f.evidence.detail.starts_with("X.509 certificate")
            {
                return Some(
                    json!({"assetType": "certificate", "certificateProperties": {"certificateFormat": format}}),
                );
            }
            let kind = if f.evidence.detail.contains("private") {
                "private-key"
            } else {
                "public-key"
            };
            return Some(
                json!({"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": kind, "format": format}}),
            );
        }
        _ => {}
    }
    let primitive = match f.rule_id.as_str() {
        "SNOOT002" | "SNOOT006" | "SNOOT011" | "SNOOT014" => "signature",
        "SNOOT004" | "SNOOT007" | "SNOOT012" => "key-agree",
        "SNOOT008" => "other",
        "SNOOT010" => "pke",
        "SNOOT013" => "hash",
        _ => "unknown",
    };
    let mut algo = json!({"primitive": primitive});
    if f.rule_id == "SNOOT001" {
        algo["cryptoFunctions"] = json!(["keygen"]);
    }
    Some(json!({"assetType": "algorithm", "algorithmProperties": algo}))
}

pub fn render(report: &ScanReport) -> anyhow::Result<String> {
    let components: Vec<Value> = report.findings.iter().enumerate().map(|(i, f)| {
        let mut occurrence = json!({"location": f.location.path});
        if let Some(line) = f.location.line { occurrence["line"] = json!(line); }
        let mut component = json!({
            "type": if matches!(f.rule_id.as_str(), "SNOOT016" | "SNOOT017") { "library" } else { "cryptographic-asset" },
            "bom-ref": format!("snoot:{}:{i}", f.fingerprint),
            "name": if f.rule_id == "SNOOT001" { "RSA" } else { &f.title }, "description": f.title,
            "evidence": {"occurrences": [occurrence]},
            "properties": [
                {"name": "snoot:ruleId", "value": f.rule_id}, {"name": "snoot:severity", "value": f.severity.to_string()},
                {"name": "snoot:fingerprint", "value": f.fingerprint}, {"name": "snoot:evidenceKind", "value": f.evidence.kind},
                {"name": "snoot:evidenceDetail", "value": f.evidence.detail}
            ]
        });
        if let Some(properties) = crypto_properties(f) { component["cryptoProperties"] = properties; }
        component
    }).collect();
    Ok(serde_json::to_string_pretty(&json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "snoot", "version": env!("CARGO_PKG_VERSION")}]}},
        "components": components
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Evidence;
    use crate::rules::RuleRegistry;
    use crate::scanner::ScanStats;
    #[test]
    fn key_inventory_preserves_format_size_and_distinct_occurrences() {
        let rule = RuleRegistry::by_id("SNOOT003").unwrap();
        let finding = Finding::new(
            &rule,
            "key.der",
            None,
            None,
            Evidence {
                kind: "der_blob".into(),
                detail: "RSA; 2048-bit RSA".into(),
            },
        );
        let report = ScanReport {
            findings: vec![finding.clone(), finding],
            stats: ScanStats::default(),
            root: ".".into(),
        };
        let doc: Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
        let first = &doc["components"][0];
        assert_ne!(first["bom-ref"], doc["components"][1]["bom-ref"]);
        assert_eq!(
            first["cryptoProperties"]["relatedCryptoMaterialProperties"]["format"],
            "DER"
        );
        assert_eq!(
            first["cryptoProperties"]["relatedCryptoMaterialProperties"]["size"],
            2048
        );
        assert!(first["cryptoProperties"]
            .get("algorithmProperties")
            .is_none());
    }
}
