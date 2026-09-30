//! CycloneDX 1.6 reports using schema-defined asset types and primitives.

use serde_json::{json, Value};

use crate::model::Finding;
use crate::scanner::ScanReport;

fn asset(finding: &Finding) -> (&str, &str, Option<Value>) {
    let material = |format| {
        json!({
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": { "type": "private-key", "format": format }
        })
    };
    let (name, primitive) = match finding.rule_id.as_str() {
        "SNOOT003" => {
            return (
                "RSA private key",
                "cryptographic-asset",
                Some(material("PEM")),
            )
        }
        "SNOOT009" => {
            return (
                "EC private key",
                "cryptographic-asset",
                Some(material("PEM")),
            )
        }
        "SNOOT010" => return ("Private key", "cryptographic-asset", Some(material("PEM"))),
        "SNOOT017" => {
            return (
                "JWK private key",
                "cryptographic-asset",
                Some(material("JWK")),
            )
        }
        "SNOOT005" | "SNOOT018" => {
            return (
                "TLS",
                "cryptographic-asset",
                Some(json!({
                    "assetType": "protocol", "protocolProperties": { "type": "tls" }
                })),
            )
        }
        "SNOOT020" => {
            return (
                "X.509 certificate",
                "cryptographic-asset",
                Some(json!({
                    "assetType": "certificate", "certificateProperties": { "certificateFormat": "PEM" }
                })),
            )
        }
        "SNOOT016" => return (finding.title.as_str(), "library", None),
        // A key-generation call does not establish encryption vs signing use.
        "SNOOT001" => ("RSA", "unknown"),
        "SNOOT002" => ("ECDSA", "signature"),
        "SNOOT004" => ("DH", "key-agree"),
        "SNOOT006" => ("ECDH", "key-agree"),
        "SNOOT007" => ("DSA", "signature"),
        "SNOOT008" => ("Classical signature", "signature"),
        "SNOOT011" => ("RSA", "pke"),
        "SNOOT012" => ("MD5", "hash"),
        "SNOOT013" => ("SHA-1", "hash"),
        "SNOOT014" => ("Ed25519", "signature"),
        "SNOOT015" => ("DES", "block-cipher"),
        "SNOOT019" => ("RC4", "stream-cipher"),
        _ => (finding.title.as_str(), "unknown"),
    };
    let mut properties = json!({
        "assetType": "algorithm",
        "algorithmProperties": { "primitive": primitive }
    });
    if finding.rule_id == "SNOOT001" {
        properties["algorithmProperties"]["cryptoFunctions"] = json!(["keygen"]);
    }
    (name, "cryptographic-asset", Some(properties))
}

fn key_size_from_detail(detail: &str) -> Option<u32> {
    detail
        .split_whitespace()
        .find_map(|word| word.strip_suffix("-bit")?.parse().ok())
}

pub fn render(report: &ScanReport) -> anyhow::Result<String> {
    let components: Vec<Value> = report
        .findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            let (name, component_type, properties) = asset(finding);
            let mut occurrence = json!({ "location": finding.location.path });
            if let Some(line) = finding.location.line {
                occurrence["line"] = json!(line);
            }
            let mut component = json!({
                "type": component_type,
                "bom-ref": format!("snoot:{}:{index}", finding.fingerprint),
                "name": name,
                "description": finding.title,
                "evidence": { "occurrences": [occurrence] },
                "properties": [
                    { "name": "snoot:ruleId", "value": finding.rule_id },
                    { "name": "snoot:severity", "value": finding.severity.to_string() },
                    { "name": "snoot:fingerprint", "value": finding.fingerprint },
                    { "name": "snoot:evidenceKind", "value": finding.evidence.kind },
                    { "name": "snoot:evidenceDetail", "value": finding.evidence.detail },
                ],
            });
            if let Some(mut properties) = properties {
                if properties["assetType"] == "related-crypto-material" {
                    if let Some(bits) = key_size_from_detail(&finding.evidence.detail) {
                        properties["relatedCryptoMaterialProperties"]["size"] = json!(bits);
                    }
                }
                component["cryptoProperties"] = properties;
            }
            component
        })
        .collect();
    let doc = json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "tools": { "components": [{
                "type": "application", "name": "snoot", "version": env!("CARGO_PKG_VERSION")
            }] },
        },
        "components": components,
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Evidence;
    use crate::rules::RuleRegistry;
    use crate::scanner::ScanStats;

    #[test]
    fn private_key_size_uses_material_properties_and_unknown_location_is_omitted() {
        let finding = Finding::new(
            &RuleRegistry::by_id("SNOOT003").unwrap(),
            "key.pem",
            None,
            None,
            Evidence {
                kind: "pem_block".into(),
                detail: "RSA PRIVATE KEY (PKCS#1 PEM), 2048-bit".into(),
            },
        );
        let report = ScanReport {
            findings: vec![finding.clone(), finding],
            stats: ScanStats::default(),
            root: ".".into(),
        };
        let document: Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
        let first = &document["components"][0];
        assert_eq!(
            first["cryptoProperties"]["relatedCryptoMaterialProperties"]["size"],
            2048
        );
        assert!(first["evidence"]["occurrences"][0].get("line").is_none());
        assert_ne!(first["bom-ref"], document["components"][1]["bom-ref"]);
    }
}
