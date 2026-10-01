//! Secrets engine: PEM / DER / JWK / key-material scanning.
//!
//! **Job** (DESIGN.md §5): find key material checked into the tree —
//! `-----BEGIN RSA PRIVATE KEY-----` blocks, PKCS#8 / PKCS#1 / SEC1 DER
//! blobs, X.509 certificates, JWK `{"kty":"RSA","n":"…","d":"…"}` objects.
//! Parse each one properly (don't regex the ASN.1): DER gets a minimal TLV
//! walker (enough to validate structure and tell certs from keys); algorithm
//! identification is an OID scan over the DER bytes, the same trick the PEM
//! path uses for PKCS#8.
//!
//! Finds private keys (critical: SNOOT003/SNOOT009/SNOOT015), certificates
//! (SNOOT020/SNOOT021, medium — the PQC migration inventory), and public
//! keys / non-classical certs (SNOOT022, info — CBOM feed).
//!
//! **Status**: week-4 milestone. PEM armor parsing, DER blob detection,
//! JWK parsing, and the certificate inventory feed are live.
//!
//! Known gaps (honest, not hidden): ENCRYPTED PRIVATE KEY (can't identify
//! the algorithm without the password), DSA private keys (no rule yet),
//! PKCS#12 bundles (password-encrypted), DER blobs using exotic signature
//! algorithms (inventoried as SNOOT022 without a name).

use std::path::Path;

use base64::Engine as _;

use crate::engines::Engine;
use crate::model::{Evidence, Finding};
use crate::rules::RuleRegistry;

pub struct SecretsEngine;

/// A parsed PEM armor block: label, 1-based start line, base64 body.
struct PemBlock {
    label: String,
    line: u32,
    body: String,
}

// ---------------------------------------------------------------------------
// DER OID table (each encoded as tag 0x06 + length + value bytes).
// ---------------------------------------------------------------------------

/// 1.2.840.113549.1.1.1
const OID_RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
/// 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// X.509 signature algorithms using RSA.
const OID_SIG_RSA: &[&[u8]] = &[
    &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04,
    ], // md5WithRSAEncryption
    &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
    ], // sha1WithRSAEncryption
    &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    ], // sha256WithRSAEncryption
    &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C,
    ], // sha384WithRSAEncryption
    &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D,
    ], // sha512WithRSAEncryption
];

/// X.509 signature algorithms using ECDSA.
const OID_SIG_ECDSA: &[&[u8]] = &[
    &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02], // ecdsa-with-SHA256
    &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03], // ecdsa-with-SHA384
    &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04], // ecdsa-with-SHA512
];

/// 1.2.840.10040.4.3.2 dsa-with-SHA256 (cert inventory only, no DSA key rule).
const OID_SIG_DSA_SHA256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03, 0x02];
/// 1.3.101.112 Ed25519 (doubles as signature and key OID).
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];

/// NIST named curves, carried by SEC1 EC private keys (which have no
/// ecPublicKey OID to scan for).
const OID_NAMED_CURVES: &[&[u8]] = &[
    &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], // secp256r1
    &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],                   // secp384r1
    &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],                   // secp521r1
    &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A],                   // secp256k1
];

/// Human-readable signature algorithm names, for evidence detail.
const SIG_NAMES: &[(&[u8], &str)] = &[
    (OID_SIG_RSA[0], "md5WithRSAEncryption"),
    (OID_SIG_RSA[1], "sha1WithRSAEncryption"),
    (OID_SIG_RSA[2], "sha256WithRSAEncryption"),
    (OID_SIG_RSA[3], "sha384WithRSAEncryption"),
    (OID_SIG_RSA[4], "sha512WithRSAEncryption"),
    (OID_SIG_ECDSA[0], "ecdsa-with-SHA256"),
    (OID_SIG_ECDSA[1], "ecdsa-with-SHA384"),
    (OID_SIG_ECDSA[2], "ecdsa-with-SHA512"),
    (OID_SIG_DSA_SHA256, "dsa-with-SHA256"),
    (OID_ED25519, "Ed25519"),
];

impl Engine for SecretsEngine {
    fn name(&self) -> &'static str {
        "secrets"
    }

    /// DER blobs are binary; the scanner must not skip them as "binary".
    fn tolerates_binary(&self) -> bool {
        true
    }

    fn file_matches(&self, path: &Path) -> bool {
        // Dedicated key/cert files, plus source files (PEM blocks get pasted
        // into code and config more often than anyone admits).
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_ascii_lowercase();
            // Well-known extensionless private-key filenames.
            if matches!(
                lower.as_str(),
                "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" | "id_ed25519_sk" | "id_rsa_sk"
            ) {
                return true;
            }
            if lower.ends_with(".pem")
                || lower.ends_with(".key")
                || lower.ends_with(".crt")
                || lower.ends_with(".cer")
                || lower.ends_with(".der")
                || lower.ends_with(".p12")
                || lower.ends_with(".pfx")
                || lower.ends_with(".pub")
                || lower.ends_with(".asc")
                || lower.ends_with(".jwk")
            {
                return true;
            }
        }
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(
                "rs" | "py"
                    | "go"
                    | "js"
                    | "ts"
                    | "java"
                    | "c"
                    | "h"
                    | "cpp"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "toml"
                    | "env"
                    | "txt"
                    | "md"
            )
        )
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_pem(path, content));
        findings.extend(scan_der(path, content));
        findings.extend(scan_jwk(path, content));
        findings
    }
}

// ---------------------------------------------------------------------------
// PEM armor
// ---------------------------------------------------------------------------

fn scan_pem(path: &Path, content: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(content);
    let mut findings = Vec::new();
    for block in pem_blocks(&text) {
        if let Some((rule_id, evidence_kind, detail)) = pem_block_finding(&block) {
            if let Some(rule) = RuleRegistry::by_id(rule_id) {
                let mut finding = Finding::new(
                    &rule,
                    path.to_string_lossy().replace('\\', "/"),
                    Some(block.line),
                    Some(format!("-----BEGIN {}-----", block.label)),
                    Evidence {
                        kind: evidence_kind.to_string(),
                        detail,
                    },
                );
                finding.fingerprint = Finding::material_fingerprint(
                    &rule.id,
                    &finding.location.path,
                    block.body.as_bytes(),
                );
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&block.body) {
                    if let Some(bits) = rsa_key_bits(&der) {
                        finding
                            .evidence
                            .detail
                            .push_str(&format!("; {bits}-bit RSA"));
                    }
                }
                findings.push(finding);
            }
        }
    }
    findings
}

/// Map one PEM block to (rule id, evidence kind, evidence detail).
fn pem_block_finding(block: &PemBlock) -> Option<(&'static str, &'static str, String)> {
    match block.label.as_str() {
        "RSA PRIVATE KEY" => Some((
            "SNOOT003",
            "pem_block",
            private_key_detail(block, "RSA PRIVATE KEY"),
        )),
        "EC PRIVATE KEY" => Some((
            "SNOOT009",
            "pem_block",
            private_key_detail(block, "EC PRIVATE KEY"),
        )),
        // PKCS#8 is algorithm-agnostic: sniff the DER OID.
        "PRIVATE KEY" => pkcs8_rule_id(&block.body).map(|rule_id| {
            (
                rule_id,
                "pem_block",
                format!(
                    "PEM armor: {} (PKCS#8, algorithm from DER OID)",
                    block.label
                ),
            )
        }),
        "OPENPGP PRIVATE KEY" | "PGP PRIVATE KEY BLOCK" => Some((
            "SNOOT015",
            "pem_block",
            format!("PEM armor: {}", block.label),
        )),
        "CERTIFICATE" => cert_block_finding(&block.body),
        "PUBLIC KEY" => public_key_block_finding(&block.body),
        // ENCRYPTED PRIVATE KEY (can't identify the algorithm),
        // DSA PRIVATE KEY (no rule yet): no finding.
        _ => None,
    }
}

/// Evidence detail for traditional-OpenSSL private-key armor. Notes
/// passphrase-based encryption (`Proc-Type: 4,ENCRYPTED`) when the block
/// carries those headers: the key is still an RSA/EC private key for
/// migration-inventory purposes, just encrypted at rest. ("Proc-Type:"
/// contains `-` and `:`, outside the base64 alphabet, so it can only come
/// from header lines, never the key body.)
fn private_key_detail(block: &PemBlock, label: &str) -> String {
    if block.body.contains("Proc-Type:") {
        format!("PEM armor: {label} (encrypted at rest: Proc-Type 4,ENCRYPTED)")
    } else {
        format!("PEM armor: {label}")
    }
}

/// Split `text` into PEM armor blocks. A block starts at a
/// `-----BEGIN <label>-----` line and runs to the matching
/// `-----END <label>-----` line; the body is the base64 between them.
fn pem_blocks(text: &str) -> Vec<PemBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, u32, String)> = None;
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        let trimmed = line.trim();
        if let Some(label) = armor_label(trimmed, "BEGIN") {
            current = Some((label, line_no, String::new()));
        } else if let Some(label) = armor_label(trimmed, "END") {
            if let Some((begin_label, begin_line, body)) = current.take() {
                if begin_label == label {
                    blocks.push(PemBlock {
                        label: begin_label,
                        line: begin_line,
                        body,
                    });
                }
                // Mismatched END: drop the dangling block, stay honest.
            }
        } else if let Some((_, _, body)) = current.as_mut() {
            body.push_str(trimmed);
        }
    }
    blocks
}

/// If `line` is a `-----BEGIN/END <label>-----` armor boundary, return the label.
fn armor_label(line: &str, which: &str) -> Option<String> {
    let prefix = format!("-----{which} ");
    let suffix = "-----";
    if line.starts_with(&prefix)
        && line.ends_with(suffix)
        && line.len() > prefix.len() + suffix.len()
    {
        Some(
            line[prefix.len()..line.len() - suffix.len()]
                .trim()
                .to_string(),
        )
    } else {
        None
    }
}

/// Identify the rule for a PKCS#8 `PRIVATE KEY` block by classifying the
/// decoded DER. Returns `None` when the body isn't valid base64/DER or the
/// algorithm has no rule (e.g. Ed25519).
fn pkcs8_rule_id(b64_body: &str) -> Option<&'static str> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64_body)
        .ok()?;
    match classify_der(&der) {
        DerKind::RsaPrivateKeyPkcs8 | DerKind::RsaPrivateKeyPkcs1 => Some("SNOOT003"),
        DerKind::EcPrivateKeyPkcs8 | DerKind::EcPrivateKeySec1 => Some("SNOOT009"),
        _ => None,
    }
}

/// Classify a `CERTIFICATE` armor block: RSA/ECDSA-signed certs get their
/// migration findings; anything else is inventory. The label is not trusted —
/// the DER structure decides (a mislabeled block holding a private key still
/// fires the private-key rule).
fn cert_block_finding(b64_body: &str) -> Option<(&'static str, &'static str, String)> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64_body)
        .ok()?;
    match classify_der(&der) {
        DerKind::RsaCert => Some((
            "SNOOT020",
            "x509_cert",
            format!("X.509 certificate signed with {}", sig_alg_name(&der)),
        )),
        DerKind::EcdsaCert => Some((
            "SNOOT021",
            "x509_cert",
            format!("X.509 certificate signed with {}", sig_alg_name(&der)),
        )),
        DerKind::OtherCert => Some((
            "SNOOT022",
            "x509_cert",
            format!("X.509 certificate: {} (inventory)", sig_alg_name(&der)),
        )),
        DerKind::RsaPrivateKeyPkcs8 | DerKind::RsaPrivateKeyPkcs1 => Some((
            "SNOOT003",
            "x509_cert",
            "mislabeled CERTIFICATE block holds an RSA private key".to_string(),
        )),
        DerKind::EcPrivateKeyPkcs8 | DerKind::EcPrivateKeySec1 => Some((
            "SNOOT009",
            "x509_cert",
            "mislabeled CERTIFICATE block holds an EC private key".to_string(),
        )),
        _ => None,
    }
}

/// Classify a `PUBLIC KEY` armor block: inventory for identifiable keys,
/// key-material rules for mislabeled blocks, silence otherwise.
fn public_key_block_finding(b64_body: &str) -> Option<(&'static str, &'static str, String)> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64_body)
        .ok()?;
    match classify_der(&der) {
        DerKind::RsaPublicKey => Some((
            "SNOOT022",
            "pem_block",
            "public key inventory: RSA".to_string(),
        )),
        DerKind::EcPublicKey => Some((
            "SNOOT022",
            "pem_block",
            "public key inventory: EC".to_string(),
        )),
        DerKind::RsaPrivateKeyPkcs8 | DerKind::RsaPrivateKeyPkcs1 => Some((
            "SNOOT003",
            "pem_block",
            "mislabeled PUBLIC KEY block holds an RSA private key".to_string(),
        )),
        DerKind::EcPrivateKeyPkcs8 | DerKind::EcPrivateKeySec1 => Some((
            "SNOOT009",
            "pem_block",
            "mislabeled PUBLIC KEY block holds an EC private key".to_string(),
        )),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DER blobs: minimal TLV walker + OID-scan classification.
// ---------------------------------------------------------------------------

/// What a DER blob structurally is. Structural heuristics (PKCS#1, SEC1)
/// are labeled as such in evidence; anything unrecognized is `Unknown`
/// and produces no finding — no guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DerKind {
    RsaPrivateKeyPkcs8,
    RsaPrivateKeyPkcs1,
    EcPrivateKeyPkcs8,
    EcPrivateKeySec1,
    RsaPublicKey,
    EcPublicKey,
    RsaCert,
    EcdsaCert,
    OtherCert,
    Unknown,
}

/// Parse one DER TLV at `off`. Returns (tag, content offset, content length).
/// Definite lengths only (DER never uses indefinite); absurd lengths rejected.
fn der_tlv(der: &[u8], off: usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(off)?;
    let len_byte = *der.get(off + 1)?;
    let (content_len, header_len) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | (*der.get(off + 2 + i)? as usize);
        }
        (len, 2 + n)
    };
    let content_off = off.checked_add(header_len)?;
    // Bounds-check the content without holding the slice.
    if der.len().checked_sub(content_off)? < content_len {
        return None;
    }
    Some((tag, content_off, content_len))
}

/// Top-level children of a DER SEQUENCE, or `None` unless `der` is exactly
/// one well-formed SEQUENCE (no trailing garbage, no truncation).
fn der_children(der: &[u8]) -> Option<Vec<(u8, usize, usize)>> {
    let (tag, content_off, content_len) = der_tlv(der, 0)?;
    if tag != 0x30 {
        return None;
    }
    let end = content_off.checked_add(content_len)?;
    if end != der.len() {
        return None;
    }
    let mut kids = Vec::new();
    let mut off = content_off;
    while off < end {
        let (t, co, cl) = der_tlv(der, off)?;
        kids.push((t, co, cl));
        off = co.checked_add(cl)?;
    }
    Some(kids)
}

/// Value of an INTEGER child when it fits in a single byte.
fn der_small_int(der: &[u8], kid: &(u8, usize, usize)) -> Option<u8> {
    let (tag, off, len) = *kid;
    if tag == 0x02 && len == 1 {
        Some(der[off])
    } else {
        None
    }
}

/// Classify a DER blob by structure + OID scan. Certificates are recognized
/// by their [SEQUENCE, SEQUENCE, BIT STRING] shape; public keys by
/// [SEQUENCE, BIT STRING] (SubjectPublicKeyInfo); anything else with key
/// OIDs is private-key material.
fn classify_der(der: &[u8]) -> DerKind {
    let kids = match der_children(der) {
        Some(k) => k,
        None => return DerKind::Unknown,
    };
    let tags: Vec<u8> = kids.iter().map(|(t, _, _)| *t).collect();
    let has_oid = |kid: &(u8, usize, usize), oid: &[u8]| {
        if kid.0 != 0x30 {
            return false;
        }
        // AlgorithmIdentifier's first child is its OID. Do not search key bytes or extensions.
        let Some((tag, off, len)) = der_tlv(der, kid.1) else {
            return false;
        };
        tag == 0x06 && off + len <= kid.1 + kid.2 && der[kid.1..off + len] == *oid
    };
    if tags == [0x30, 0x30, 0x03] {
        if OID_SIG_RSA.iter().any(|o| has_oid(&kids[1], o)) {
            return DerKind::RsaCert;
        }
        if OID_SIG_ECDSA.iter().any(|o| has_oid(&kids[1], o)) {
            return DerKind::EcdsaCert;
        }
        return DerKind::OtherCert;
    }
    if tags == [0x30, 0x03] {
        if has_oid(&kids[0], OID_RSA_ENCRYPTION) {
            return DerKind::RsaPublicKey;
        }
        if has_oid(&kids[0], OID_EC_PUBLIC_KEY) {
            return DerKind::EcPublicKey;
        }
        return DerKind::Unknown;
    }
    if tags.len() >= 3
        && tags[..3] == [0x02, 0x30, 0x04]
        && matches!(der_small_int(der, &kids[0]), Some(0 | 1))
    {
        if has_oid(&kids[1], OID_RSA_ENCRYPTION) {
            return DerKind::RsaPrivateKeyPkcs8;
        }
        if has_oid(&kids[1], OID_EC_PUBLIC_KEY) {
            return DerKind::EcPrivateKeyPkcs8;
        }
        return DerKind::Unknown;
    }
    if tags.len() >= 9
        && tags[..9].iter().all(|&t| t == 0x02)
        && der_small_int(der, &kids[0]) == Some(0)
        && kids[1].2 >= 64
    {
        return DerKind::RsaPrivateKeyPkcs1;
    }
    if tags.len() >= 2
        && tags[..2] == [0x02, 0x04]
        && der_small_int(der, &kids[0]) == Some(1)
        && kids.iter().filter(|k| k.0 == 0xa0).any(|k| {
            let value = &der[k.1..k.1 + k.2];
            OID_NAMED_CURVES.contains(&value)
        })
    {
        return DerKind::EcPrivateKeySec1;
    }
    DerKind::Unknown
}

/// Human-readable name of the first recognized signature-algorithm OID.
fn sig_alg_name(der: &[u8]) -> &'static str {
    let Some(kids) = der_children(der) else {
        return "unknown signature algorithm";
    };
    let Some(kid) = kids.get(1).filter(|k| k.0 == 0x30) else {
        return "unknown signature algorithm";
    };
    let Some((tag, off, len)) = der_tlv(der, kid.1) else {
        return "unknown signature algorithm";
    };
    if tag != 0x06 || off + len > kid.1 + kid.2 {
        return "unknown signature algorithm";
    }
    SIG_NAMES
        .iter()
        .find(|(oid, _)| der[kid.1..off + len] == **oid)
        .map_or("unknown signature algorithm", |(_, name)| *name)
}

fn integer_bits(value: &[u8]) -> Option<u32> {
    let start = value.iter().position(|b| *b != 0)?;
    let value = &value[start..];
    Some((value.len() as u32 * 8) - value[0].leading_zeros())
}

fn rsa_key_bits(der: &[u8]) -> Option<u32> {
    let kids = der_children(der)?;
    match classify_der(der) {
        DerKind::RsaPrivateKeyPkcs1 => integer_bits(&der[kids[1].1..kids[1].1 + kids[1].2]),
        DerKind::RsaPrivateKeyPkcs8 => {
            let key = kids.get(2)?;
            let inner = &der[key.1..key.1 + key.2];
            if classify_der(inner) != DerKind::RsaPrivateKeyPkcs1 {
                return None;
            }
            let inner_kids = der_children(inner)?;
            integer_bits(&inner[inner_kids[1].1..inner_kids[1].1 + inner_kids[1].2])
        }
        _ => None,
    }
}

/// Scan for a raw DER blob: the content must start with the SEQUENCE tag
/// (0x30) and parse as exactly one DER SEQUENCE. Binary content is fine —
/// this runs on the raw bytes, before any UTF-8 interpretation.
fn scan_der(path: &Path, content: &[u8]) -> Vec<Finding> {
    if content.first() != Some(&0x30) {
        return Vec::new();
    }
    let kind = classify_der(content);
    let (rule_id, detail) = match kind {
        DerKind::RsaPrivateKeyPkcs8 => ("SNOOT003", "DER private key: RSA (PKCS#8)".to_string()),
        DerKind::RsaPrivateKeyPkcs1 => (
            "SNOOT003",
            "DER private key: RSA (PKCS#1, structural heuristic)".to_string(),
        ),
        DerKind::EcPrivateKeyPkcs8 => ("SNOOT009", "DER private key: EC (PKCS#8)".to_string()),
        DerKind::EcPrivateKeySec1 => (
            "SNOOT009",
            "DER private key: EC (SEC1, structural heuristic)".to_string(),
        ),
        DerKind::RsaPublicKey => ("SNOOT022", "DER public key: RSA (inventory)".to_string()),
        DerKind::EcPublicKey => ("SNOOT022", "DER public key: EC (inventory)".to_string()),
        DerKind::RsaCert => (
            "SNOOT020",
            format!(
                "X.509 certificate (DER) signed with {}",
                sig_alg_name(content)
            ),
        ),
        DerKind::EcdsaCert => (
            "SNOOT021",
            format!(
                "X.509 certificate (DER) signed with {}",
                sig_alg_name(content)
            ),
        ),
        DerKind::OtherCert => (
            "SNOOT022",
            format!(
                "X.509 certificate (DER): {} (inventory)",
                sig_alg_name(content)
            ),
        ),
        DerKind::Unknown => return Vec::new(),
    };
    let rule = RuleRegistry::by_id(rule_id).expect("secrets rule ids are static");
    let mut finding = Finding::new(
        &rule,
        path.to_string_lossy().replace('\\', "/"),
        None,
        Some(format!("<DER blob, {} bytes>", content.len())),
        Evidence {
            kind: "der_blob".to_string(),
            detail,
        },
    );
    finding.fingerprint = Finding::material_fingerprint(&rule.id, &finding.location.path, content);
    if let Some(bits) = rsa_key_bits(content) {
        finding
            .evidence
            .detail
            .push_str(&format!("; {bits}-bit RSA"));
    }
    vec![finding]
}

// ---------------------------------------------------------------------------
// JWK objects
// ---------------------------------------------------------------------------

/// Scan for JWK key objects: top-level `{"kty": …}`, JWK Sets (`{"keys":
/// […]}`), or a bare array of keys. Private keys (with `"d"`) fire the
/// private-key rules; public keys and OKP (Ed25519-family) keys are
/// inventory. `"oct"` symmetric keys and unknown `kty` values are ignored.
fn scan_jwk(path: &Path, content: &[u8]) -> Vec<Finding> {
    let first = content.iter().find(|b| !b.is_ascii_whitespace()).copied();
    if !matches!(first, Some(b'{') | Some(b'[')) {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let mut objects: Vec<&serde_json::Map<String, serde_json::Value>> = Vec::new();
    match &value {
        serde_json::Value::Object(map) => {
            if map.contains_key("kty") {
                objects.push(map);
            }
            if let Some(keys) = map.get("keys").and_then(|k| k.as_array()) {
                objects.extend(keys.iter().filter_map(|k| k.as_object()));
            }
        }
        serde_json::Value::Array(keys) => {
            objects.extend(keys.iter().filter_map(|k| k.as_object()));
        }
        _ => {}
    }
    let mut findings = Vec::new();
    for (idx, obj) in objects.iter().enumerate() {
        if let Some((rule_id, detail)) = jwk_key_finding(obj, idx) {
            if let Some(rule) = RuleRegistry::by_id(rule_id) {
                let mut finding = Finding::new(
                    &rule,
                    path.to_string_lossy().replace('\\', "/"),
                    None,
                    None,
                    Evidence {
                        kind: "jwk".to_string(),
                        detail,
                    },
                );
                // Key order is stable in serde_json's map. Reordering a JWKS must not change key identity.
                let material = serde_json::to_vec(obj).expect("JSON objects serialize");
                finding.fingerprint =
                    Finding::material_fingerprint(&rule.id, &finding.location.path, &material);
                if obj.get("kty").and_then(|v| v.as_str()) == Some("RSA") {
                    if let Some(bits) = obj
                        .get("n")
                        .and_then(|v| v.as_str())
                        .and_then(|n| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(n)
                                .ok()
                        })
                        .and_then(|n| integer_bits(&n))
                    {
                        finding
                            .evidence
                            .detail
                            .push_str(&format!("; {bits}-bit RSA"));
                    }
                }
                findings.push(finding);
            }
        }
    }
    findings
}

fn jwk_key_finding(
    obj: &serde_json::Map<String, serde_json::Value>,
    idx: usize,
) -> Option<(&'static str, String)> {
    let kty = obj.get("kty")?.as_str()?;
    let has = |k: &str| obj.contains_key(k);
    let (rule_id, kind) = match kty {
        "RSA" if has("d") => ("SNOOT003", "private key material"),
        "RSA" if has("n") => ("SNOOT022", "public key"),
        "EC" if has("d") => ("SNOOT009", "private key material"),
        "EC" if has("x") => ("SNOOT022", "public key"),
        "OKP" if has("d") || has("x") => ("SNOOT022", "Ed25519-family key"),
        _ => return None,
    };
    Some((rule_id, format!("JWK key #{idx}: kty={kty}, {kind}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7b2Q3w==\n-----END RSA PRIVATE KEY-----\n";
    const EC_PEM: &str =
        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA==\n-----END EC PRIVATE KEY-----\n";
    const OPENPGP_ARMOR: &str =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nxsBNBF==\n-----END PGP PRIVATE KEY BLOCK-----\n";

    fn scan_text(name: &str, text: &str) -> Vec<Finding> {
        SecretsEngine.scan(Path::new(name), text.as_bytes())
    }

    /// Build a DER TLV in tests (short/long form for the sizes we use).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if content.len() < 128 {
            v.push(content.len() as u8);
        } else {
            v.push(0x81);
            v.push(content.len() as u8);
        }
        v.extend_from_slice(content);
        v
    }

    fn seq(children: &[u8]) -> Vec<u8> {
        tlv(0x30, children)
    }

    fn oid_tlv(oid: &[u8]) -> Vec<u8> {
        // oid already includes tag+len; wrap as-is.
        oid.to_vec()
    }

    fn scan_der_bytes(name: &str, der: &[u8]) -> Vec<Finding> {
        SecretsEngine.scan(Path::new(name), der)
    }

    #[test]
    fn rsa_private_key_pem_fires_snoot003() {
        let findings = scan_text("id_rsa", RSA_PEM);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT003");
        assert_eq!(findings[0].location.line, Some(1));
    }

    #[test]
    fn encrypted_rsa_pem_still_fires_with_encrypted_note() {
        // Traditional OpenSSL encryption (Proc-Type / DEK-Info headers):
        // still an RSA private key for inventory purposes, just noted.
        const ENCRYPTED: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
            Proc-Type: 4,ENCRYPTED\n\
            DEK-Info: AES-128-CBC,7CDEA083529E2DB403D7B23206005446\n\
            \n\
            MIIEpAIBAAKCAQEA7b...\n\
            -----END RSA PRIVATE KEY-----\n";
        let findings = scan_text("enc.key", ENCRYPTED);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT003");
        assert!(
            findings[0].evidence.detail.contains("encrypted at rest"),
            "detail: {}",
            findings[0].evidence.detail
        );
    }

    #[test]
    fn ec_private_key_pem_fires_snoot009() {
        let findings = scan_text("ec.key", EC_PEM);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT009");
    }

    #[test]
    fn openpgp_armor_fires_snoot015() {
        let findings = scan_text("key.asc", OPENPGP_ARMOR);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT015");
    }

    #[test]
    fn public_key_pem_is_inventory_snoot022() {
        // Minimal SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { rsaEncryption OID }, BIT STRING }.
        let mut inner = oid_tlv(OID_RSA_ENCRYPTION);
        inner.extend(tlv(0x05, &[])); // NULL parameters
        let mut outer = seq(&inner);
        outer.extend(tlv(0x03, &[0x00, 0xFF])); // BIT STRING
        let spki = seq(&outer);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        let findings = scan_text("key.pub", &pem);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT022");
    }

    #[test]
    fn plain_text_is_not_a_finding() {
        assert!(scan_text("notes.txt", "nothing to see here\n").is_empty());
    }

    #[test]
    fn pkcs8_sniff_distinguishes_rsa_and_ec() {
        let wrap = |oid: &[u8]| {
            let mut body = tlv(0x02, &[0]);
            body.extend(seq(oid));
            body.extend(tlv(0x04, &[1, 2, 3]));
            base64::engine::general_purpose::STANDARD.encode(seq(&body))
        };
        assert_eq!(pkcs8_rule_id(&wrap(OID_RSA_ENCRYPTION)), Some("SNOOT003"));
        assert_eq!(pkcs8_rule_id(&wrap(OID_EC_PUBLIC_KEY)), Some("SNOOT009"));
        assert_eq!(pkcs8_rule_id(&wrap(OID_ED25519)), None);
        assert_eq!(pkcs8_rule_id("!!! not base64 !!!"), None);
    }

    #[test]
    fn mismatched_armor_boundaries_are_ignored() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END EC PRIVATE KEY-----\n";
        assert!(scan_text("bad.pem", text).is_empty());
    }

    // -- DER blobs --------------------------------------------------------

    #[test]
    fn der_pkcs8_rsa_fires_snoot003() {
        // SEQUENCE { INTEGER 0, SEQUENCE { rsaEncryption OID }, OCTET STRING }.
        let mut body = tlv(0x02, &[0x00]);
        let mut alg = oid_tlv(OID_RSA_ENCRYPTION);
        alg.extend(tlv(0x05, &[]));
        body.extend(seq(&alg));
        body.extend(tlv(0x04, &[0xAA; 16]));
        let der = seq(&body);
        let findings = scan_der_bytes("key.der", &der);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT003");
        assert_eq!(findings[0].evidence.kind, "der_blob");
    }

    #[test]
    fn der_pkcs1_heuristic_fires_snoot003() {
        // PKCS#1 has no OID: SEQUENCE of INTEGERs, version 0, big modulus.
        let mut body = tlv(0x02, &[0x00]);
        body.extend(tlv(0x02, &[0x99; 65]));
        for _ in 0..7 {
            body.extend(tlv(0x02, &[1]));
        }
        let der = seq(&body);
        assert_eq!(classify_der(&der), DerKind::RsaPrivateKeyPkcs1);
        let findings = scan_der_bytes("key.der", &der);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT003");
        assert!(findings[0].evidence.detail.contains("heuristic"));
    }

    #[test]
    fn der_pkcs1_heuristic_rejects_tiny_integers() {
        // Same shape, toy-sized modulus: not a real key, no finding.
        let mut body = tlv(0x02, &[0x00]);
        body.extend(tlv(0x02, &[0x99; 8]));
        let der = seq(&body);
        assert_eq!(classify_der(&der), DerKind::Unknown);
        assert!(scan_der_bytes("key.der", &der).is_empty());
    }

    #[test]
    fn der_sec1_ec_heuristic_fires_snoot009() {
        // SEC1 ECPrivateKey: version 1 + named-curve OID, no ecPublicKey OID.
        let mut body = tlv(0x02, &[0x01]);
        body.extend(tlv(0x04, &[0xBB; 32]));
        let mut params = vec![0xA0];
        let oid = oid_tlv(OID_NAMED_CURVES[0]);
        params.push(oid.len() as u8);
        params.extend(oid);
        body.extend(params);
        let der = seq(&body);
        assert_eq!(classify_der(&der), DerKind::EcPrivateKeySec1);
        let findings = scan_der_bytes("key.der", &der);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT009");
    }

    #[test]
    fn der_rsa_cert_fires_snoot020() {
        // Minimal X.509 shape: SEQUENCE { SEQ, SEQ, BIT STRING } with an
        // RSA signature OID present.
        let tbs = oid_tlv(OID_SIG_RSA[2]);
        let mut sig_alg = oid_tlv(OID_SIG_RSA[2]);
        sig_alg.extend(tlv(0x05, &[]));
        let mut body = seq(&tbs);
        body.extend(seq(&sig_alg));
        body.extend(tlv(0x03, &[0x00, 0xFF]));
        let der = seq(&body);
        assert_eq!(classify_der(&der), DerKind::RsaCert);
        let findings = scan_der_bytes("cert.der", &der);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT020");
        assert!(findings[0]
            .evidence
            .detail
            .contains("sha256WithRSAEncryption"));
    }

    #[test]
    fn der_ecdsa_cert_fires_snoot021() {
        let mut sig_alg = oid_tlv(OID_SIG_ECDSA[0]);
        sig_alg.extend(tlv(0x05, &[]));
        let mut body = seq(&oid_tlv(OID_SIG_ECDSA[0]));
        body.extend(seq(&sig_alg));
        body.extend(tlv(0x03, &[0x00, 0xFF]));
        let der = seq(&body);
        assert_eq!(classify_der(&der), DerKind::EcdsaCert);
        let findings = scan_der_bytes("cert.der", &der);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT021");
    }

    #[test]
    fn der_ed25519_cert_is_inventory_snoot022() {
        let sig_alg = oid_tlv(OID_ED25519);
        let mut body = seq(&oid_tlv(OID_ED25519));
        body.extend(seq(&sig_alg));
        body.extend(tlv(0x03, &[0x00, 0xFF]));
        let der = seq(&body);
        assert_eq!(classify_der(&der), DerKind::OtherCert);
        let findings = scan_der_bytes("cert.der", &der);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT022");
        assert!(findings[0].evidence.detail.contains("Ed25519"));
    }

    #[test]
    fn der_spki_public_key_is_inventory() {
        let mut inner = oid_tlv(OID_RSA_ENCRYPTION);
        inner.extend(tlv(0x05, &[]));
        let mut outer = seq(&inner);
        outer.extend(tlv(0x03, &[0x00, 0xFF]));
        let der = seq(&outer);
        assert_eq!(classify_der(&der), DerKind::RsaPublicKey);
        let findings = scan_der_bytes("key.der", &der);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT022");
    }

    #[test]
    fn der_malformed_blobs_are_ignored() {
        // Truncated: declared length exceeds the buffer.
        assert!(scan_der_bytes("a.der", &[0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00]).is_empty());
        // Trailing garbage after the SEQUENCE.
        let mut der = seq(&tlv(0x02, &[0x00]));
        der.extend([0xFF, 0xFF]);
        assert!(scan_der_bytes("b.der", &der).is_empty());
        // Not a SEQUENCE at all.
        assert!(scan_der_bytes("c.der", &[0x02, 0x01, 0x00]).is_empty());
        // Valid DER, unrecognized content.
        let der = seq(&tlv(0x02, &[0x05]));
        assert_eq!(classify_der(&der), DerKind::Unknown);
        assert!(scan_der_bytes("d.der", &der).is_empty());
    }

    #[test]
    fn text_starting_with_zero_byte_value_is_not_der() {
        // 0x30 is also ASCII '0' — a text file starting with '0' must not
        // parse as DER unless the whole buffer is a valid SEQUENCE.
        assert!(scan_text("num.txt", "0123456789\n").is_empty());
    }

    // -- PEM certificates -------------------------------------------------

    fn pem_wrap(label: &str, der: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n")
    }

    #[test]
    fn pem_certificate_rsa_fires_snoot020() {
        let mut sig_alg = oid_tlv(OID_SIG_RSA[2]);
        sig_alg.extend(tlv(0x05, &[]));
        let mut body = seq(&oid_tlv(OID_SIG_RSA[2]));
        body.extend(seq(&sig_alg));
        body.extend(tlv(0x03, &[0x00, 0xFF]));
        let der = seq(&body);
        let findings = scan_text("cert.pem", &pem_wrap("CERTIFICATE", &der));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT020");
        assert_eq!(findings[0].evidence.kind, "x509_cert");
        assert_eq!(findings[0].location.line, Some(1));
    }

    // -- JWK ----------------------------------------------------------------

    #[test]
    fn jwk_rsa_private_fires_snoot003() {
        let jwk = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhRq82nP","e":"AQAB","d":"X4cTteJY_gn4qKrXYF_DkM"}"#;
        let findings = scan_text("key.jwk", jwk);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT003");
        assert_eq!(findings[0].evidence.kind, "jwk");
    }

    #[test]
    fn jwk_ec_public_is_inventory_snoot022() {
        let jwk = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHMLiMxiXyg_iwAJa2QuV-A"}"#;
        let findings = scan_text("key.json", jwk);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT022");
    }

    #[test]
    fn jwk_set_with_mixed_keys() {
        let jwks = r#"{"keys":[
            {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHMLiMxiXyg_iwAJa2QuV-A","d":"NhqU_h15mxYbjMwv6w6m4yU7DLEP6a6p3A8yk1e1pgk"},
            {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
        ]}"#;
        let findings = scan_text("jwks.json", jwks);
        let mut ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, ["SNOOT009", "SNOOT022"]);
    }

    #[test]
    fn jwk_symmetric_and_unknown_kty_ignored() {
        assert!(scan_text("a.json", r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#).is_empty());
        assert!(scan_text("b.json", r#"{"kty":"AKP","x":"abc"}"#).is_empty());
        assert!(scan_text("c.json", r#"{"name":"not-a-key"}"#).is_empty());
        assert!(scan_text("d.json", "not json at all").is_empty());
    }
}
