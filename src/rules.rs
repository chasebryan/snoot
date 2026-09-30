//! Rule registry: detection rules as data, not code.
//!
//! v1 target: 20+ rules. Week 2 ships 15 across all six languages plus PEM/TLS.

use crate::model::{LanguageQuery, Rule, Severity};

fn q(language: &str, query: &str) -> LanguageQuery {
    LanguageQuery {
        language: language.to_string(),
        query: query.to_string(),
    }
}

/// Shared Go selector-call query: `pkg.Func(...)`.
fn go_call(pkg: &str, func: &str) -> LanguageQuery {
    q(
        "go",
        &format!(
            "(call_expression\n  function: (selector_expression\n    operand: (identifier) @_mod\n    field: (field_identifier) @_fn)\n  (#eq? @_mod \"{pkg}\")\n  (#eq? @_fn \"{func}\"))"
        ),
    )
}

/// Shared JS/TS member-call query: `obj.method(...)`.
fn js_member(lang: &str, obj: &str, method: &str) -> LanguageQuery {
    q(
        lang,
        &format!(
            "(call_expression\n  function: (member_expression\n    object: (identifier) @_mod\n    property: (property_identifier) @_fn)\n  (#eq? @_mod \"{obj}\")\n  (#eq? @_fn \"{method}\"))"
        ),
    )
}

/// Shared C/C++ bare call: `Func(...)`.
fn c_call(lang: &str, func: &str) -> LanguageQuery {
    q(
        lang,
        &format!("(call_expression\n  function: (identifier) @_fn\n  (#eq? @_fn \"{func}\"))"),
    )
}

pub struct RuleRegistry;

impl RuleRegistry {
    pub fn all() -> Vec<Rule> {
        vec![
            Rule {
                id: "SNOOT001".to_string(),
                title: "RSA key generation".to_string(),
                severity: Severity::High,
                description: "Application code generates an RSA key pair. RSA is \
                    quantum-vulnerable (Shor's algorithm): anything this key \
                    protects is exposed to harvest-now-decrypt-later."
                    .to_string(),
                remediation: "Migrate encryption to ML-KEM-768 or ML-KEM-1024 \
                    (FIPS 203); use hybrid X25519+ML-KEM during transition. For \
                    signatures, migrate to ML-DSA (FIPS 204)."
                    .to_string(),
                queries: vec![
                        q(
                            "rust",
                            "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Rsa\")\n  (#eq? @_fn \"generate\"))",
                        ),
                        q(
                            "rust",
                            "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"RsaPrivateKey\")\n  (#eq? @_fn \"new\"))",
                        ),
                        q(
                            "python",
                            "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"RSA\")\n  (#eq? @_fn \"generate\"))",
                        ),
                        q(
                            "python",
                            "(call\n  function: (attribute\n    object: (attribute\n      object: (attribute\n        object: (identifier) @_a\n        attribute: (identifier) @_b)\n      attribute: (identifier) @_c)\n    attribute: (identifier) @_fn)\n  (#eq? @_a \"Crypto\")\n  (#eq? @_b \"PublicKey\")\n  (#eq? @_c \"RSA\")\n  (#eq? @_fn \"generate\"))",
                        ),
                        q(
                            "python",
                            "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"rsa\")\n  (#eq? @_fn \"newkeys\"))",
                        ),
                        q(
                            "python",
                            "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"rsa\")\n  (#eq? @_fn \"generate_private_key\"))",
                        ),
                        go_call("rsa", "GenerateKey"),
                        q(
                            "javascript",
                            "(call_expression\n  function: (identifier) @_fn\n  (#eq? @_fn \"generateKeyPairSync\"))",
                        ),
                        q(
                            "javascript",
                            "(call_expression\n  function: (identifier) @_fn\n  (#eq? @_fn \"generateKeyPair\"))",
                        ),
                        js_member("javascript", "crypto", "generateKeyPair"),
                        js_member("javascript", "crypto", "generateKeyPairSync"),
                        q(
                            "typescript",
                            "(call_expression\n  function: (identifier) @_fn\n  (#eq? @_fn \"generateKeyPairSync\"))",
                        ),
                        js_member("typescript", "crypto", "generateKeyPair"),
                        js_member("typescript", "crypto", "generateKeyPairSync"),
                        q(
                            "java",
                            "(method_invocation\n  object: (identifier) @_obj\n  name: (identifier) @_fn\n  arguments: (argument_list (string_literal (string_fragment) @_alg))\n  (#eq? @_obj \"KeyPairGenerator\")\n  (#eq? @_fn \"getInstance\")\n  (#eq? @_alg \"RSA\"))",
                        ),
                        c_call("c", "RSA_generate_key_ex"),
                        c_call("c", "RSA_generate_key"),
                        c_call("cpp", "RSA_generate_key_ex"),
                        c_call("cpp", "RSA_generate_key"),
                    ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "RSA key-generation sites are candidates for orange-verified \
                     ML-KEM migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT002".to_string(),
                title: "ECDSA signing / key generation".to_string(),
                severity: Severity::High,
                description: "Application code creates or uses ECDSA keys \
                    (P-256/P-384). ECDSA falls to Shor's algorithm; signatures \
                    on long-lived artifacts become forgeable once a \
                    cryptographically relevant quantum computer exists."
                    .to_string(),
                remediation: "Migrate signatures to ML-DSA-65 or ML-DSA-87 \
                    (FIPS 204). CNSA 2.0 requires PQC signatures for \
                    software/firmware signing by 2030."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"SigningKey\")\n  (#eq? @_fn \"random\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"SigningKey\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    go_call("ecdsa", "GenerateKey"),
                    go_call("ecdsa", "Sign"),
                    go_call("ecdsa", "SignASN1"),
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_obj\n  name: (identifier) @_fn\n  arguments: (argument_list (string_literal (string_fragment) @_alg))\n  (#eq? @_obj \"KeyPairGenerator\")\n  (#eq? @_fn \"getInstance\")\n  (#eq? @_alg \"EC\"))",
                    ),
                    c_call("c", "EC_KEY_generate_key"),
                    c_call("cpp", "EC_KEY_generate_key"),
                    c_call("c", "ECDSA_do_sign"),
                    c_call("cpp", "ECDSA_do_sign"),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "ECDSA signing sites are candidates for orange-verified \
                     ML-DSA migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT003".to_string(),
                title: "RSA private key material in PEM".to_string(),
                severity: Severity::Critical,
                description: "A PEM block containing an RSA private key was \
                    found in the source tree. Embedded private keys are \
                    compromised by definition — and quantum-vulnerable on top \
                    of it."
                    .to_string(),
                remediation: "Remove the key from source control immediately \
                    and rotate it. Store secrets in a KMS/HSM going forward. \
                    Issue PQC replacements (ML-KEM for encryption, ML-DSA for \
                    signatures) for the replacement keys."
                    .to_string(),
                queries: vec![],
                cwe: Some("CWE-798".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT004".to_string(),
                title: "Weak Diffie-Hellman parameters".to_string(),
                severity: Severity::High,
                description: "Diffie-Hellman key exchange with parameters below \
                    3072 bits, or a named weak group (e.g. Oakley Group 2 / \
                    modp1024). Weak to precomputation attacks today (Logjam \
                    class) and to Shor's algorithm."
                    .to_string(),
                remediation: "Retire DH below 3072 bits. Migrate key exchange \
                    to ML-KEM (FIPS 203); use hybrid X25519+ML-KEM for \
                    interoperability during transition."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Dh\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"DH\")\n  (#eq? @_fn \"generate_parameters\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"dh\")\n  (#eq? @_fn \"generate_parameters\"))",
                    ),
                    go_call("dh", "GenerateKey"),
                    c_call("c", "DH_generate_parameters_ex"),
                    c_call("c", "DH_generate_key"),
                    c_call("cpp", "DH_generate_parameters_ex"),
                    c_call("cpp", "DH_generate_key"),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT005".to_string(),
                title: "TLS configuration without PQC hybrid key exchange".to_string(),
                severity: Severity::Medium,
                description: "A TLS configuration enables classical-only key \
                    exchange (ECDHE / X25519) with no hybrid post-quantum \
                    group such as X25519+ML-KEM-768. Connections are exposed \
                    to harvest-now-decrypt-later."
                    .to_string(),
                remediation: "Enable hybrid PQC key exchange \
                    (X25519MLKEM768) in the TLS configuration. Chrome, \
                    Cloudflare, and the major clouds already negotiate it; \
                    plan full migration against CNSA 2.0 timelines."
                    .to_string(),
                queries: vec![],
                cwe: None,
                orange_note: None,
            },
            Rule {
                id: "SNOOT006".to_string(),
                title: "ECDH / X25519 key exchange".to_string(),
                severity: Severity::High,
                description: "Application code performs elliptic-curve Diffie-Hellman \
                    (including X25519/X448). ECDH is broken by Shor's algorithm; \
                    session keys derived today can be recovered from captured \
                    traffic once a CRQC exists (harvest-now-decrypt-later)."
                    .to_string(),
                remediation: "Migrate key exchange to ML-KEM (FIPS 203). Prefer \
                    hybrid X25519+ML-KEM-768 during the transition for \
                    interoperability."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"EphemeralSecret\")\n  (#eq? @_fn \"random\"))",
                    ),
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"StaticSecret\")\n  (#eq? @_fn \"random\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"ec\")\n  (#eq? @_fn \"generate_private_key\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"X25519PrivateKey\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    go_call("curve25519", "X25519"),
                    c_call("c", "ECDH_compute_key"),
                    c_call("cpp", "ECDH_compute_key"),
                    c_call("c", "X25519"),
                    c_call("cpp", "X25519"),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "ECDH sites are candidates for orange-verified ML-KEM \
                     migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT007".to_string(),
                title: "DSA key generation or signing".to_string(),
                severity: Severity::High,
                description: "Application code uses DSA for key generation or \
                    signatures. DSA is quantum-vulnerable and already deprecated \
                    by modern standards; retire it."
                    .to_string(),
                remediation: "Retire DSA. Migrate signatures to ML-DSA (FIPS 204)."
                    .to_string(),
                queries: vec![
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"DSA\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"dsa\")\n  (#eq? @_fn \"generate_private_key\"))",
                    ),
                    go_call("dsa", "GenerateKey"),
                    go_call("dsa", "Sign"),
                    c_call("c", "DSA_generate_parameters_ex"),
                    c_call("c", "DSA_generate_key"),
                    c_call("c", "DSA_do_sign"),
                    c_call("cpp", "DSA_generate_parameters_ex"),
                    c_call("cpp", "DSA_generate_key"),
                    c_call("cpp", "DSA_do_sign"),
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_obj\n  name: (identifier) @_fn\n  arguments: (argument_list (string_literal (string_fragment) @_alg))\n  (#eq? @_obj \"KeyPairGenerator\")\n  (#eq? @_fn \"getInstance\")\n  (#eq? @_alg \"DSA\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT008".to_string(),
                title: "Classical public-key signature API".to_string(),
                severity: Severity::High,
                description: "Application code invokes a classical public-key \
                    signature API (RSA/ECDSA createSign, SignPKCS1v15, \
                    Signature.getInstance with SHA*withRSA/ECDSA). Signatures \
                    become forgeable under Shor's algorithm."
                    .to_string(),
                remediation: "Migrate signatures to ML-DSA-65 or ML-DSA-87 \
                    (FIPS 204). Prefer hybrid classical+PQC during transition \
                    where protocol support exists."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Pkcs1v15Sign\")\n  (#eq? @_fn \"new\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"pkcs1_15\")\n  (#eq? @_fn \"new\"))",
                    ),
                    go_call("rsa", "SignPKCS1v15"),
                    go_call("rsa", "SignPSS"),
                    js_member("javascript", "crypto", "createSign"),
                    js_member("javascript", "crypto", "createVerify"),
                    js_member("typescript", "crypto", "createSign"),
                    js_member("typescript", "crypto", "createVerify"),
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_obj\n  name: (identifier) @_fn\n  (#eq? @_obj \"Signature\")\n  (#eq? @_fn \"getInstance\"))",
                    ),
                    c_call("c", "RSA_sign"),
                    c_call("cpp", "RSA_sign"),
                    c_call("c", "EVP_DigestSign"),
                    c_call("cpp", "EVP_DigestSign"),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "Classical signature sites are candidates for orange-verified \
                     ML-DSA migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT009".to_string(),
                title: "EC private key material in PEM".to_string(),
                severity: Severity::Critical,
                description: "A PEM block containing an elliptic-curve private \
                    key was found in the source tree. Embedded private keys are \
                    compromised by definition and quantum-vulnerable."
                    .to_string(),
                remediation: "Remove the key from source control immediately \
                    and rotate it. Prefer ML-DSA (signing) or ML-KEM (key \
                    exchange) replacements stored in a KMS/HSM."
                    .to_string(),
                queries: vec![],
                cwe: Some("CWE-798".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT010".to_string(),
                title: "Classical private key material in PEM".to_string(),
                severity: Severity::Critical,
                description: "A PKCS#8 or DSA private-key PEM block was found \
                    in the source tree. Until ASN.1 parsing proves a PQC \
                    algorithm, treat it as classical and quantum-vulnerable."
                    .to_string(),
                remediation: "Remove the key from source control, rotate it, \
                    and store replacements in a KMS/HSM. Prefer ML-KEM / ML-DSA."
                    .to_string(),
                queries: vec![],
                cwe: Some("CWE-798".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT011".to_string(),
                title: "RSA encryption / decryption API".to_string(),
                severity: Severity::High,
                description: "Application code encrypts or decrypts with RSA. \
                    Ciphertexts captured today can be decrypted by a future \
                    cryptographically relevant quantum computer."
                    .to_string(),
                remediation: "Migrate to ML-KEM-768 or ML-KEM-1024 (FIPS 203), \
                    with hybrid X25519+ML-KEM during transition."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Pkcs1v15Encrypt\")\n  (#eq? @_fn \"new\"))",
                    ),
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Oaep\")\n  (#eq? @_fn \"new\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"PKCS1_OAEP\")\n  (#eq? @_fn \"new\"))",
                    ),
                    go_call("rsa", "EncryptPKCS1v15"),
                    go_call("rsa", "EncryptOAEP"),
                    go_call("rsa", "DecryptPKCS1v15"),
                    go_call("rsa", "DecryptOAEP"),
                    c_call("c", "RSA_public_encrypt"),
                    c_call("c", "RSA_private_decrypt"),
                    c_call("cpp", "RSA_public_encrypt"),
                    c_call("cpp", "RSA_private_decrypt"),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "RSA encryption sites are candidates for orange-verified \
                     ML-KEM migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT012".to_string(),
                title: "MD5 usage".to_string(),
                severity: Severity::Low,
                description: "MD5 is cryptographically broken and not suitable \
                    for integrity or signatures. Not a quantum-primary finding, \
                    but flagged for hygiene during crypto inventory."
                    .to_string(),
                remediation: "Replace MD5 with SHA-256 or SHA-3 for integrity. \
                    For signatures, prefer ML-DSA (FIPS 204)."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Md5\")\n  (#eq? @_fn \"new\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"hashlib\")\n  (#eq? @_fn \"md5\"))",
                    ),
                    go_call("md5", "New"),
                    c_call("c", "MD5"),
                    c_call("c", "MD5_Init"),
                    c_call("cpp", "MD5"),
                    c_call("cpp", "MD5_Init"),
                ],
                cwe: Some("CWE-328".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT013".to_string(),
                title: "SHA-1 usage".to_string(),
                severity: Severity::Low,
                description: "SHA-1 is deprecated for collision resistance. \
                    Hygiene flag during crypto inventory; not the primary \
                    quantum-vulnerable surface."
                    .to_string(),
                remediation: "Replace SHA-1 with SHA-256 or SHA-3. For \
                    signatures, prefer ML-DSA (FIPS 204)."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Sha1\")\n  (#eq? @_fn \"new\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"hashlib\")\n  (#eq? @_fn \"sha1\"))",
                    ),
                    go_call("sha1", "New"),
                    c_call("c", "SHA1"),
                    c_call("c", "SHA1_Init"),
                    c_call("cpp", "SHA1"),
                    c_call("cpp", "SHA1_Init"),
                ],
                cwe: Some("CWE-328".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT014".to_string(),
                title: "Ed25519 signing (inventory)".to_string(),
                severity: Severity::Info,
                description: "Ed25519 is not broken by Shor the same way RSA/ECDSA \
                    are today, but CNSA 2.0 still plans a PQC signature migration. \
                    Inventory-only finding for CBOM completeness."
                    .to_string(),
                remediation: "Plan migration to ML-DSA (FIPS 204) per CNSA 2.0 \
                    timelines. No emergency action required for Ed25519 alone."
                    .to_string(),
                queries: vec![
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"SigningKey\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"Ed25519PrivateKey\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    go_call("ed25519", "GenerateKey"),
                    c_call("c", "ED25519_sign"),
                    c_call("cpp", "ED25519_sign"),
                ],
                cwe: None,
                orange_note: None,
            },
            Rule {
                id: "SNOOT015".to_string(),
                title: "DES / 3DES usage".to_string(),
                severity: Severity::Low,
                description: "DES/3DES are obsolete symmetric ciphers. Hygiene \
                    flag during crypto inventory."
                    .to_string(),
                remediation: "Replace DES/3DES with AES-256-GCM (or ChaCha20-Poly1305). \
                    Symmetric ciphers are not the primary quantum migration \
                    target; Grover's algorithm is addressed by AES-256."
                    .to_string(),
                queries: vec![
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"DES\")\n  (#eq? @_fn \"new\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"DES3\")\n  (#eq? @_fn \"new\"))",
                    ),
                    c_call("c", "DES_ecb_encrypt"),
                    c_call("c", "DES_ncbc_encrypt"),
                    c_call("c", "DES_ede3_cbc_encrypt"),
                    c_call("cpp", "DES_ecb_encrypt"),
                    c_call("cpp", "DES_ede3_cbc_encrypt"),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT016".to_string(),
                title: "Classical crypto dependency".to_string(),
                severity: Severity::Medium,
                description: "A direct dependency known to provide classical \
                    public-key cryptography was declared in a package manifest. \
                    Inventory the call sites and plan PQC migration; transitive \
                    analysis is out of scope for v1."
                    .to_string(),
                remediation: "Prefer libraries with ML-KEM/ML-DSA support (or \
                    hybrid TLS stacks). Track each dependency's PQC roadmap and \
                    pin versions that expose hybrid groups where available."
                    .to_string(),
                queries: vec![],
                cwe: None,
                orange_note: None,
            },
        ]
    }

    pub fn by_id(id: &str) -> Option<Rule> {
        Self::all().into_iter().find(|r| r.id == id)
    }

    #[allow(dead_code)]
    pub fn count() -> usize {
        Self::all().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_week2_rules() {
        let rules = RuleRegistry::all();
        assert_eq!(rules.len(), 16);
        assert_eq!(RuleRegistry::count(), 16);
        for i in 1..=16 {
            let id = format!("SNOOT{i:03}");
            assert!(RuleRegistry::by_id(&id).is_some(), "missing rule {id}");
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let rules = RuleRegistry::all();
        let mut ids: Vec<_> = rules.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len());
    }

    #[test]
    fn code_rules_carry_queries() {
        for id in [
            "SNOOT001", "SNOOT002", "SNOOT004", "SNOOT006", "SNOOT007", "SNOOT008", "SNOOT011",
            "SNOOT012", "SNOOT013", "SNOOT014", "SNOOT015",
        ] {
            let rule = RuleRegistry::by_id(id).unwrap();
            assert!(!rule.queries.is_empty(), "{id} has no tree-sitter queries");
        }
    }

    #[test]
    fn pem_and_tls_rules_have_no_queries() {
        for id in ["SNOOT003", "SNOOT005", "SNOOT009", "SNOOT010", "SNOOT016"] {
            let rule = RuleRegistry::by_id(id).unwrap();
            assert!(rule.queries.is_empty(), "{id} should be engine-driven");
        }
    }
}
