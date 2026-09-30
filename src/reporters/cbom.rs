//! CBOM reporter: CycloneDX 1.6 Cryptography Bill of Materials.
//!
//! The compliance artifact (DESIGN.md §8): what OMB M-23-02's inventory
//! mandate and enterprise auditors actually want — a machine-readable list of
//! every cryptographic asset found, with algorithm properties per finding.
//!
//! Each finding becomes a `cryptographic-asset` component carrying
//! `cryptoProperties` per the CycloneDX 1.6 crypto extension:
//! `assetType` (algorithm vs key material vs protocol), `algorithmProperties`
//! with the spec's `primitive` enum and a `parameterSetIdentifier`
//! (e.g. "rsa", "ecdsa", "secp192r1" curve for weak-curve findings), and
//! `nistQuantumSecurityLevel: 0` — classical crypto offers no quantum
//! security, which is the entire point of the inventory. Provenance rides in
//! `evidence.occurrences` plus `snoot:*` properties.

use serde_json::{json, Value};

use crate::model::Finding;
use crate::scanner::ScanReport;

/// Per-rule crypto metadata: (assetType, primitive, parameterSetIdentifier).
/// Rules needing snippet/evidence-dependent refinement return None for the
/// parameter set and are resolved in `resolve_meta`.
fn static_meta(rule_id: &str) -> Option<(&'static str, &'static str, Option<&'static str>)> {
    Some(match rule_id {
        "SNOOT001" => ("algorithm", "other", Some("rsa")),
        "SNOOT002" => ("algorithm", "signature", Some("ecdsa")),
        "SNOOT003" => ("related-crypto-material", "other", Some("rsa")),
        "SNOOT004" => ("algorithm", "key-agreement", Some("dh")),
        "SNOOT005" => ("protocol", "key-agreement", Some("tls")),
        "SNOOT006" => ("algorithm", "signature", Some("dsa")),
        "SNOOT007" => ("algorithm", "key-agreement", Some("ecdh")),
        "SNOOT008" => ("algorithm", "elliptic-curve", Some("ec")),
        "SNOOT009" => ("related-crypto-material", "elliptic-curve", Some("ec")),
        "SNOOT010" => ("algorithm", "other", Some("rsa")),
        "SNOOT011" => ("algorithm", "signature", Some("dsa")),
        "SNOOT012" => ("algorithm", "key-agreement", Some("dh")),
        "SNOOT013" => ("algorithm", "hash-function", None), // md5|sha1 from snippet
        "SNOOT014" => ("algorithm", "signature", None),     // rsa|ecdsa from snippet
        "SNOOT015" => ("related-crypto-material", "other", Some("openpgp")),
        "SNOOT016" => ("algorithm", "other", None), // dep family from evidence
        "SNOOT017" => ("algorithm", "other", None), // dep family from evidence
        "SNOOT018" => ("protocol", "key-agreement", Some("tls")),
        "SNOOT019" => ("protocol", "key-agreement", Some("tls")),
        "SNOOT020" => ("certificate", "signature", Some("rsa")),
        "SNOOT021" => ("certificate", "signature", Some("ecdsa")),
        "SNOOT022" => ("certificate", "other", None), // refined from evidence below
        _ => return None,
    })
}

/// Dependency name → classical algorithm family, for manifest findings.
/// Evidence detail is formatted `dependency "name" (file): note`.
fn dep_family(detail: &str) -> &'static str {
    let name = detail.split('"').nth(1).unwrap_or("").to_ascii_lowercase();
    match name.as_str() {
        "rust-crypto" | "pycrypto" | "pycryptodome" | "pycryptodomex" | "cryptography"
        | "node-rsa" | "jsrsasign" | "jsonwebtoken" => "rsa",
        "crypto-js" => "aes",
        _ if name.starts_with("bcprov")
            || name.starts_with("bcmail")
            || name.starts_with("bcpkix")
            || name == "golang-jwt/jwt" =>
        {
            "rsa"
        }
        _ => "unknown",
    }
}

/// Resolve the full (assetType, primitive, parameterSetIdentifier, curve)
/// for a finding, refining static metadata from snippet/evidence.
fn resolve_meta(f: &Finding) -> (&'static str, &'static str, &'static str, Option<String>) {
    let (asset_type, primitive, param) =
        static_meta(&f.rule_id).unwrap_or(("algorithm", "unknown", Some("unknown")));
    // SNOOT022 covers both certificates and JWK public keys; the asset
    // type follows the evidence kind.
    let asset_type = if f.rule_id == "SNOOT022" && f.evidence.kind == "jwk" {
        "key"
    } else {
        asset_type
    };
    let snippet = f
        .location
        .snippet
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();

    let param = match (f.rule_id.as_str(), param) {
        ("SNOOT013", None) => {
            if snippet.contains("sha1") {
                "sha1"
            } else if snippet.contains("md5") {
                "md5"
            } else {
                "unknown"
            }
        }
        ("SNOOT014", None) => {
            if snippet.contains("es256") {
                "ecdsa"
            } else if snippet.contains("rs256") || snippet.contains("ps256") {
                "rsa"
            } else {
                "unknown"
            }
        }
        ("SNOOT016" | "SNOOT017", None) => dep_family(&f.evidence.detail),
        ("SNOOT022", None) => {
            // Inventory rule: recover the algorithm family from the evidence
            // detail ("JWK key #0: kty=EC, public key", "X.509 certificate:
            // ecdsa-with-SHA256, …", "DER public key: RSA (inventory)").
            let d = f.evidence.detail.to_ascii_lowercase();
            if d.contains("rsa") {
                "rsa"
            } else if d.contains("ecdsa") {
                "ecdsa"
            } else if d.contains("ed25519") {
                "ed25519"
            } else if d.contains("kty=ec") || d.contains(" ec ") {
                "ec"
            } else {
                "unknown"
            }
        }
        (_, Some(p)) => p,
        (_, None) => "unknown",
    };

    // Weak-curve findings carry the named curve for the inventory.
    let curve = if f.rule_id == "SNOOT008" {
        ["secp192r1", "secp224r1", "p-192", "p-224", "p192", "p224"]
            .into_iter()
            .find(|c| snippet.contains(c))
            .map(str::to_string)
    } else {
        None
    };

    (asset_type, primitive, param, curve)
}

fn component(f: &Finding) -> Value {
    let (asset_type, primitive, param, curve) = resolve_meta(f);

    let crypto_properties = if asset_type == "protocol" {
        json!({
            "assetType": "protocol",
            "protocolProperties": { "type": "tls" },
        })
    } else {
        let mut algo = json!({
            "primitive": primitive,
            "parameterSetIdentifier": param,
            // Classical crypto: zero quantum security. That is the inventory's point.
            "nistQuantumSecurityLevel": 0,
        });
        if let Some(curve) = curve {
            algo["curve"] = json!(curve);
        }
        json!({
            "assetType": asset_type,
            "algorithmProperties": algo,
        })
    };

    let mut occurrence = json!({ "location": f.location.path });
    if let Some(line) = f.location.line {
        occurrence["line"] = json!(line);
    }

    json!({
        "bom-ref": f.fingerprint,
        "type": "cryptographic-asset",
        "name": f.title,
        "cryptoProperties": crypto_properties,
        "evidence": { "occurrences": [occurrence] },
        "properties": [
            { "name": "snoot:ruleId", "value": f.rule_id },
            { "name": "snoot:severity", "value": f.severity.to_string() },
            { "name": "snoot:evidenceKind", "value": f.evidence.kind },
        ],
    })
}

/// Render the report as a CycloneDX 1.6 CBOM JSON document (as a string).
pub fn render(report: &ScanReport) -> String {
    let components: Vec<Value> = report.findings.iter().map(component).collect();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Location, Severity};
    use crate::rules::RuleRegistry;
    use crate::scanner::{ScanReport, ScanStats};
    use std::path::PathBuf;

    /// CycloneDX 1.6 `algorithmProperties.primitive` enum values.
    const PRIMITIVES: &[&str] = &[
        "block-cipher",
        "stream-cipher",
        "elliptic-curve",
        "hash-function",
        "key-agreement",
        "key-derivation",
        "mac",
        "authenticated-encryption",
        "signature",
        "other",
        "unknown",
    ];

    fn finding(
        rule_id: &str,
        path: &str,
        snippet: Option<&str>,
        evidence: (&str, &str),
    ) -> Finding {
        let rule = RuleRegistry::by_id(rule_id).unwrap();
        Finding {
            rule_id: rule.id.clone(),
            severity: rule.severity,
            title: rule.title.clone(),
            location: Location {
                path: path.to_string(),
                line: Some(3),
                column: None,
                snippet: snippet.map(str::to_string),
            },
            evidence: Evidence {
                kind: evidence.0.to_string(),
                detail: evidence.1.to_string(),
            },
            remediation: rule.remediation.clone(),
            orange_note: None,
            fingerprint: Finding::fingerprint(
                &rule.id,
                path,
                snippet.unwrap_or("").trim(),
                evidence.1,
            ),
        }
    }

    fn report() -> ScanReport {
        ScanReport {
            findings: vec![
                finding(
                    "SNOOT001",
                    "src/k.rs",
                    Some("Rsa::generate(2048)"),
                    ("api_call", "RSA keygen"),
                ),
                finding(
                    "SNOOT003",
                    "keys/id_rsa",
                    Some("-----BEGIN RSA PRIVATE KEY-----"),
                    ("pem_block", "PEM armor: RSA PRIVATE KEY"),
                ),
                finding("SNOOT005", "nginx.conf", None, ("tls_config", "no hybrid")),
                finding(
                    "SNOOT008",
                    "a.go",
                    Some("elliptic.P192()"),
                    ("api_call", "weak curve"),
                ),
                finding(
                    "SNOOT013",
                    "h.py",
                    Some("hashlib.md5()"),
                    ("api_call", "md5"),
                ),
                finding(
                    "SNOOT014",
                    "t.js",
                    Some("algorithm: 'RS256'"),
                    ("api_call", "jwt"),
                ),
                finding(
                    "SNOOT016",
                    "requirements.txt",
                    Some("pycrypto==2.6.1"),
                    (
                        "manifest_dep",
                        r#"dependency "pycrypto" (requirements.txt): abandoned"#,
                    ),
                ),
                finding(
                    "SNOOT020",
                    "certs/rsa.pem",
                    Some("-----BEGIN CERTIFICATE-----"),
                    (
                        "x509_cert",
                        "X.509 certificate: sha256WithRSAEncryption, RSA public key",
                    ),
                ),
                finding(
                    "SNOOT021",
                    "certs/ec.pem",
                    Some("-----BEGIN CERTIFICATE-----"),
                    (
                        "x509_cert",
                        "X.509 certificate: ecdsa-with-SHA256, EC public key",
                    ),
                ),
                finding(
                    "SNOOT022",
                    "keys/jwk.json",
                    None,
                    ("jwk", "JWK key #0: kty=EC, public key"),
                ),
                // Unknown rule id: must not break rendering.
                Finding {
                    rule_id: "SNOOT999".to_string(),
                    severity: Severity::Info,
                    title: "mystery".to_string(),
                    location: Location {
                        path: "x".to_string(),
                        line: None,
                        column: None,
                        snippet: None,
                    },
                    evidence: Evidence {
                        kind: "test".to_string(),
                        detail: "test".to_string(),
                    },
                    remediation: String::new(),
                    orange_note: None,
                    fingerprint: "abc".to_string(),
                },
            ],
            stats: ScanStats::default(),
            root: PathBuf::from("."),
        }
    }

    fn algo(comp: &Value) -> &Value {
        &comp["cryptoProperties"]["algorithmProperties"]
    }

    /// Structural validation of the CBOM: CycloneDX 1.6 envelope, valid
    /// cryptoProperties per component, and correct per-rule refinement.
    #[test]
    fn cbom_output_conforms() {
        let doc: Value = serde_json::from_str(&render(&report())).unwrap();

        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.6");
        assert_eq!(doc["version"], 1);
        assert_eq!(doc["metadata"]["tools"][0]["name"], "snoot");

        let comps = doc["components"].as_array().unwrap();
        assert_eq!(comps.len(), 11);
        let by_rule: std::collections::HashMap<&str, &Value> = comps
            .iter()
            .map(|c| {
                let rule = c["properties"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["name"] == "snoot:ruleId")
                    .unwrap()["value"]
                    .as_str()
                    .unwrap();
                // Required component fields.
                assert_eq!(c["type"], "cryptographic-asset");
                assert!(!c["name"].as_str().unwrap().is_empty());
                assert!(!c["bom-ref"].as_str().unwrap().is_empty());
                // cryptoProperties shape.
                let asset_type = c["cryptoProperties"]["assetType"].as_str().unwrap();
                assert!(
                    [
                        "algorithm",
                        "certificate",
                        "key",
                        "protocol",
                        "related-crypto-material"
                    ]
                    .contains(&asset_type),
                    "bad assetType {asset_type}"
                );
                if asset_type != "protocol" {
                    let primitive = algo(c)["primitive"].as_str().unwrap();
                    assert!(PRIMITIVES.contains(&primitive), "bad primitive {primitive}");
                    assert!(!algo(c)["parameterSetIdentifier"]
                        .as_str()
                        .unwrap()
                        .is_empty());
                }
                // Provenance.
                let occ = &c["evidence"]["occurrences"][0];
                assert!(!occ["location"].as_str().unwrap().is_empty());
                (rule, c)
            })
            .collect();

        // Per-rule refinement spot-checks.
        assert_eq!(algo(by_rule["SNOOT001"])["parameterSetIdentifier"], "rsa");
        assert_eq!(
            by_rule["SNOOT003"]["cryptoProperties"]["assetType"],
            "related-crypto-material"
        );
        assert_eq!(
            by_rule["SNOOT005"]["cryptoProperties"]["assetType"],
            "protocol"
        );
        assert_eq!(algo(by_rule["SNOOT008"])["curve"], "p192");
        assert_eq!(algo(by_rule["SNOOT013"])["parameterSetIdentifier"], "md5");
        assert_eq!(algo(by_rule["SNOOT014"])["parameterSetIdentifier"], "rsa");
        assert_eq!(algo(by_rule["SNOOT016"])["parameterSetIdentifier"], "rsa");
        // Certificate rules.
        assert_eq!(
            by_rule["SNOOT020"]["cryptoProperties"]["assetType"],
            "certificate"
        );
        assert_eq!(algo(by_rule["SNOOT020"])["primitive"], "signature");
        assert_eq!(algo(by_rule["SNOOT020"])["parameterSetIdentifier"], "rsa");
        assert_eq!(algo(by_rule["SNOOT021"])["parameterSetIdentifier"], "ecdsa");
        // Inventory rule: JWK public keys are `key` assets with refined params.
        assert_eq!(by_rule["SNOOT022"]["cryptoProperties"]["assetType"], "key");
        assert_eq!(algo(by_rule["SNOOT022"])["parameterSetIdentifier"], "ec");
        // Quantum security level is the inventory's point.
        assert_eq!(algo(by_rule["SNOOT001"])["nistQuantumSecurityLevel"], 0);
        // Unknown rule ids degrade gracefully.
        assert_eq!(algo(by_rule["SNOOT999"])["primitive"], "unknown");
    }
}
