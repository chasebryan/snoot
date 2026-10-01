//! Rule registry: detection rules as data, not code.
//!
//! Each rule carries its id, severity, description, classical → PQC
//! remediation mapping, and per-language tree-sitter queries (consumed by the
//! code engine). Adding a rule or a language means adding data here — no new
//! control flow. Rules detected by other engines (secrets, tlsconf) carry an
//! empty query list; see the per-rule comments.
//!
//! Migration mappings follow DESIGN.md §6 (NIST FIPS 203/204/205).

use crate::model::{LanguageQuery, Rule, Severity};

fn q(language: &str, query: &str) -> LanguageQuery {
    LanguageQuery {
        language: language.to_string(),
        query: query.to_string(),
    }
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
                    // Crypto.PublicKey.RSA.generate(...) — three-level attribute chain.
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (attribute\n      object: (attribute\n        object: (identifier) @_a\n        attribute: (identifier) @_b)\n      attribute: (identifier) @_c)\n    attribute: (identifier) @_fn)\n  (#eq? @_a \"Crypto\")\n  (#eq? @_b \"PublicKey\")\n  (#eq? @_c \"RSA\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"rsa\")\n  (#eq? @_fn \"newkeys\"))",
                    ),
                    q("python", r#"(call function: (attribute object: (identifier) @_obj attribute: (identifier) @_fn) (#eq? @_obj "RSA") (#eq? @_fn "generate"))"#),
                    q("python", r#"(call function: (attribute object: (identifier) @_obj attribute: (identifier) @_fn) (#eq? @_obj "rsa") (#eq? @_fn "generate_private_key"))"#),
                    q("javascript", r#"(new_expression constructor: (identifier) @_cls (#eq? @_cls "NodeRSA"))"#),
                    // rsa.GenerateKey(rand.Reader, 2048)
                    q(
                        "go",
                        "(call_expression\n  function: (selector_expression\n    operand: (identifier) @_pkg\n    field: (field_identifier) @_fn)\n  (#eq? @_pkg \"rsa\")\n  (#eq? @_fn \"GenerateKey\"))",
                    ),
                    // crypto.generateKeyPairSync('rsa', {...})
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  arguments: (arguments . (string) @_alg)\n  (#eq? @_obj \"crypto\")\n  (#match? @_fn \"^generateKeyPair(Sync)?$\")\n  (#match? @_alg \"(?i)['\\\"]rsa['\\\"]\"))",
                    ),
                    // KeyPairGenerator.getInstance("RSA")
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#eq? @_cls \"KeyPairGenerator\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)rsa\"))",
                    ),
                    // RSA_generate_key(2048, RSA_F4, NULL, NULL)
                    q(
                        "c",
                        "(call_expression\n  function: (identifier) @_f\n  (#match? @_f \"^RSA_generate_key(_ex)?$\"))",
                    ),
                    // EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)
                    q(
                        "c",
                        "(call_expression\n  function: (identifier) @_f\n  arguments: (argument_list . (identifier) @_alg)\n  (#eq? @_f \"EVP_PKEY_CTX_new_id\")\n  (#eq? @_alg \"EVP_PKEY_RSA\"))",
                    ),
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
                title: "ECDSA signing".to_string(),
                severity: Severity::High,
                description: "Application code signs with ECDSA (P-256/P-384). \
                    ECDSA falls to Shor's algorithm; signatures on long-lived \
                    artifacts become forgeable once a cryptographically relevant \
                    quantum computer exists."
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
                    // ecdsa.SigningKey.generate(curve=...)
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (attribute\n      object: (identifier) @_a\n      attribute: (identifier) @_b)\n    attribute: (identifier) @_fn)\n  (#eq? @_a \"ecdsa\")\n  (#eq? @_b \"SigningKey\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    // ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
                    q(
                        "go",
                        "(call_expression\n  function: (selector_expression\n    operand: (identifier) @_pkg\n    field: (field_identifier) @_fn)\n  (#eq? @_pkg \"ecdsa\")\n  (#eq? @_fn \"GenerateKey\"))",
                    ),
                    // crypto.generateKeyPairSync('ec', {...})
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  arguments: (arguments . (string) @_alg)\n  (#eq? @_obj \"crypto\")\n  (#match? @_fn \"^generateKeyPair(Sync)?$\")\n  (#match? @_alg \"(?i)['\\\"]ec['\\\"]\"))",
                    ),
                    // KeyPairGenerator.getInstance("EC")
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#eq? @_cls \"KeyPairGenerator\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)['\\\"]ec['\\\"]\"))",
                    ),
                    // Signature.getInstance("SHA256withECDSA")
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#eq? @_cls \"Signature\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)ecdsa\"))",
                    ),
                    // ECDSA_sign(0, dgst, dgstlen, sig, &siglen, eckey)
                    q(
                        "c",
                        "(call_expression\n  function: (identifier) @_f\n  (#match? @_f \"^ECDSA_(do_)?sign$\"))",
                    ),
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
                title: "RSA private key material".to_string(),
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
                // Detected by the secrets engine (PEM parsing), not tree-sitter.
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
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#match? @_mod \"(?i)^dh$\")\n  (#eq? @_fn \"generate_parameters\"))",
                    ),
                    // crypto.getDiffieHellman('modp1' | 'modp2') — 768/1024-bit groups
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  arguments: (arguments . (string) @_grp)\n  (#eq? @_obj \"crypto\")\n  (#eq? @_fn \"getDiffieHellman\")\n  (#match? @_grp \"modp[12]\"))",
                    ),
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
                // Detected by the tlsconf engine (config-string matching).
                queries: vec![],
                cwe: None,
                orange_note: None,
            },
            Rule {
                id: "SNOOT006".to_string(),
                title: "DSA key generation".to_string(),
                severity: Severity::High,
                description: "Application code generates a DSA key pair. DSA \
                    is quantum-vulnerable (Shor's algorithm) and deprecated \
                    for new use; anything signed with these keys is exposed \
                    to harvest-now-forge-later."
                    .to_string(),
                remediation: "Migrate signatures to ML-DSA (FIPS 204). Do not \
                    generate new DSA keys."
                    .to_string(),
                queries: vec![
                    // KeyPairGenerator.getInstance("DSA")
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#eq? @_cls \"KeyPairGenerator\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)['\\\"]dsa['\\\"]\"))",
                    ),
                    // Crypto.PublicKey.DSA.generate(2048)
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (attribute\n      object: (attribute\n        object: (identifier) @_a\n        attribute: (identifier) @_b)\n      attribute: (identifier) @_c)\n    attribute: (identifier) @_fn)\n  (#eq? @_a \"Crypto\")\n  (#eq? @_b \"PublicKey\")\n  (#eq? @_c \"DSA\")\n  (#eq? @_fn \"generate\"))",
                    ),
                    // crypto.generateKeyPairSync('dsa', {...})
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  arguments: (arguments . (string) @_alg)\n  (#eq? @_obj \"crypto\")\n  (#match? @_fn \"^generateKeyPair(Sync)?$\")\n  (#match? @_alg \"(?i)['\\\"]dsa['\\\"]\"))",
                    ),
                    // openssl::dsa::Dsa::generate(2048)
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"Dsa\")\n  (#eq? @_fn \"generate\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "DSA key-generation sites are candidates for orange-verified \
                     ML-DSA migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT007".to_string(),
                title: "ECDH key exchange".to_string(),
                severity: Severity::High,
                description: "Application code performs elliptic-curve \
                    Diffie-Hellman key exchange. ECDH falls to Shor's \
                    algorithm: session keys agreed this way are exposed to \
                    harvest-now-decrypt-later."
                    .to_string(),
                remediation: "Migrate key exchange to ML-KEM-768 or \
                    ML-KEM-1024 (FIPS 203); use hybrid X25519+ML-KEM during \
                    transition."
                    .to_string(),
                queries: vec![
                    // ecdh.P256().GenerateKey(rand.Reader) etc.
                    q(
                        "go",
                        "(call_expression\n  function: (selector_expression\n    operand: (identifier) @_pkg)\n  (#eq? @_pkg \"ecdh\"))",
                    ),
                    // crypto.createECDH('secp256k1')
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  (#eq? @_obj \"crypto\")\n  (#eq? @_fn \"createECDH\"))",
                    ),
                    // KeyAgreement.getInstance("ECDH")
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#eq? @_cls \"KeyAgreement\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)ecdh\"))",
                    ),
                    // ec.ECDH()
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"ec\")\n  (#eq? @_fn \"ECDH\"))",
                    ),
                    // p256::ecdh::EphemeralSecret::random(&mut rng)
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"EphemeralSecret\")\n  (#eq? @_fn \"random\"))",
                    ),
                    // ECDH_compute_key(secret, secrelen, pub_point, ecdh, NULL)
                    q(
                        "c",
                        "(call_expression\n  function: (identifier) @_f\n  (#eq? @_f \"ECDH_compute_key\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "ECDH sites are candidates for orange-verified ML-KEM \
                     migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT008".to_string(),
                title: "Weak elliptic curves (P-192, P-224)".to_string(),
                severity: Severity::Medium,
                description: "Code references a sub-256-bit elliptic curve \
                    (P-192/secp192r1, P-224/secp224r1). Below 112 bits of \
                    classical security today — and Shor's algorithm erases \
                    what little margin remains."
                    .to_string(),
                remediation: "Move to P-256 minimum for any remaining \
                    classical use, and plan migration to ML-DSA/ML-KEM \
                    (FIPS 203/204)."
                    .to_string(),
                queries: vec![
                    // elliptic.P192() / elliptic.P224()
                    q(
                        "go",
                        "(call_expression\n  function: (selector_expression\n    operand: (identifier) @_pkg\n    field: (field_identifier) @_fn)\n  (#eq? @_pkg \"elliptic\")\n  (#match? @_fn \"^P(192|224)$\"))",
                    ),
                    // new ECGenParameterSpec("secp192r1")
                    q(
                        "java",
                        "(object_creation_expression\n  type: (type_identifier) @_cls\n  arguments: (argument_list . (string_literal) @_curve)\n  (#eq? @_cls \"ECGenParameterSpec\")\n  (#match? @_curve \"(?i)secp(192|224)r1\"))",
                    ),
                    // ec.SECP192R1()
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"ec\")\n  (#match? @_fn \"^SECP(192|224)R1$\"))",
                    ),
                    // crypto.createECDH('secp192r1')
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  arguments: (arguments . (string) @_curve)\n  (#eq? @_obj \"crypto\")\n  (#eq? @_fn \"createECDH\")\n  (#match? @_curve \"(?i)secp(192|224)r1\"))",
                    ),
                    // any use of a P192/P224 type or value
                    q(
                        "rust",
                        "([(identifier) (type_identifier)] @_i\n  (#match? @_i \"^P(192|224)$\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT009".to_string(),
                title: "EC private key material".to_string(),
                severity: Severity::Critical,
                description: "A PEM block containing an elliptic-curve private \
                    key was found in the source tree. Embedded private keys \
                    are compromised by definition — and quantum-vulnerable on \
                    top of it."
                    .to_string(),
                remediation: "Remove the key from source control immediately \
                    and rotate it. Store secrets in a KMS/HSM going forward. \
                    Issue ML-DSA (signing) or ML-KEM (exchange) replacements."
                    .to_string(),
                // Detected by the secrets engine (PEM parsing), not tree-sitter.
                queries: vec![],
                cwe: Some("CWE-798".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT010".to_string(),
                title: "RSA encryption/decryption API usage".to_string(),
                severity: Severity::High,
                description: "Application code encrypts or decrypts with RSA \
                    (including PKCS#1 v1.5 and OAEP). Ciphertexts produced \
                    here are the canonical harvest-now-decrypt-later target."
                    .to_string(),
                remediation: "Migrate encryption to ML-KEM-768 or ML-KEM-1024 \
                    (FIPS 203); use hybrid X25519+ML-KEM during transition. \
                    Treat existing RSA ciphertexts as already exposed if they \
                    protect long-lived data."
                    .to_string(),
                queries: vec![
                    // rsa.EncryptPKCS1v15 / rsa.DecryptOAEP(...)
                    q(
                        "go",
                        "(call_expression\n  function: (selector_expression\n    operand: (identifier) @_pkg\n    field: (field_identifier) @_fn)\n  (#eq? @_pkg \"rsa\")\n  (#match? @_fn \"^(Encrypt|Decrypt)\"))",
                    ),
                    // crypto.publicEncrypt(...) / crypto.privateDecrypt(...)
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  (#eq? @_obj \"crypto\")\n  (#match? @_fn \"^(publicEncrypt|privateDecrypt|publicDecrypt|privateEncrypt)$\"))",
                    ),
                    // Cipher.getInstance("RSA/ECB/PKCS1Padding")
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#eq? @_cls \"Cipher\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)rsa/\"))",
                    ),
                    // PKCS1_v1_5.new(key) / PKCS1_OAEP.new(key)
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#match? @_mod \"^PKCS1_(v1_5|OAEP)$\")\n  (#eq? @_fn \"new\"))",
                    ),
                    // use of the Pkcs1v15Encrypt padding marker
                    q(
                        "rust",
                        "((identifier) @_i\n  (#eq? @_i \"Pkcs1v15Encrypt\"))",
                    ),
                    // RSA_public_encrypt(flen, from, to, rsa, RSA_PKCS1_PADDING)
                    q(
                        "c",
                        "(call_expression\n  function: (identifier) @_f\n  (#match? @_f \"^RSA_(public_encrypt|private_decrypt)$\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "RSA encryption sites are candidates for orange-verified \
                     ML-KEM migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT011".to_string(),
                title: "DSA signing".to_string(),
                severity: Severity::High,
                description: "Application code signs with DSA. DSA signatures \
                    fall to Shor's algorithm; they should already have been \
                    retired classically, and are doubly urgent under PQC \
                    migration."
                    .to_string(),
                remediation: "Migrate signatures to ML-DSA (FIPS 204). Do not \
                    create new DSA signatures."
                    .to_string(),
                queries: vec![
                    // Signature.getInstance("SHA256withDSA") — the #not-match?
                    // keeps "SHA256withECDSA" (SNOOT002) out.
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#eq? @_cls \"Signature\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)dsa\")\n  (#not-match? @_alg \"(?i)ecdsa\"))",
                    ),
                    // DSS.new(key, 'fips-186-3')
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"DSS\")\n  (#eq? @_fn \"new\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "DSA signing sites are candidates for orange-verified \
                     ML-DSA migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT012".to_string(),
                title: "Finite-field Diffie-Hellman key exchange".to_string(),
                severity: Severity::High,
                description: "Application code performs finite-field \
                    Diffie-Hellman key exchange. Beyond weak-parameter risk \
                    (SNOOT004), all finite-field DH is quantum-vulnerable via \
                    Shor's algorithm."
                    .to_string(),
                remediation: "Migrate key exchange to ML-KEM (FIPS 203); use \
                    hybrid X25519+ML-KEM for interoperability during \
                    transition."
                    .to_string(),
                queries: vec![
                    // crypto.createDiffieHellman(...)
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  (#eq? @_obj \"crypto\")\n  (#eq? @_fn \"createDiffieHellman\"))",
                    ),
                    // KeyAgreement.getInstance("DH") / KeyPairGenerator.getInstance("DH")
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#match? @_cls \"^(KeyAgreement|KeyPairGenerator|KeyFactory)$\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)['\\\"]dh['\\\"]\"))",
                    ),
                    // dh.generate_parameters(generator=2, key_size=...)
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#match? @_mod \"(?i)^dh$\")\n  (#eq? @_fn \"generate_parameters\"))",
                    ),
                    // DH_compute_key(secret, pub_key, dh)
                    q(
                        "c",
                        "(call_expression\n  function: (identifier) @_f\n  (#eq? @_f \"DH_compute_key\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: Some(
                    "DH key-exchange sites are candidates for orange-verified \
                     ML-KEM migration — see https://github.com/chasebryan/orange"
                        .to_string(),
                ),
            },
            Rule {
                id: "SNOOT013".to_string(),
                title: "Legacy hash algorithms (MD5, SHA-1)".to_string(),
                severity: Severity::Low,
                description: "Code uses MD5 or SHA-1. Broken classically \
                    (collisions) and therefore unfit anywhere near a \
                    migration boundary — e.g. hashing data before PQC \
                    signing, or fingerprinting keys."
                    .to_string(),
                remediation: "Replace with SHA-256, SHA-384, or SHA-3. Not a \
                    quantum break per se, but legacy hashes have no place in \
                    a post-quantum migration."
                    .to_string(),
                queries: vec![
                    // md5.New() / sha1.New()
                    q(
                        "go",
                        "(call_expression\n  function: (selector_expression\n    operand: (identifier) @_pkg\n    field: (field_identifier) @_fn)\n  (#match? @_pkg \"^(md5|sha1)$\")\n  (#eq? @_fn \"New\"))",
                    ),
                    // crypto.createHash('md5' | 'sha1')
                    q(
                        "javascript",
                        "(call_expression\n  function: (member_expression\n    object: (identifier) @_obj\n    property: (property_identifier) @_fn)\n  arguments: (arguments . (string) @_alg)\n  (#eq? @_obj \"crypto\")\n  (#eq? @_fn \"createHash\")\n  (#match? @_alg \"(?i)['\\\"](md5|sha-?1)['\\\"]\"))",
                    ),
                    // MessageDigest.getInstance("MD5")
                    q(
                        "java",
                        "(method_invocation\n  object: (identifier) @_cls\n  name: (identifier) @_fn\n  arguments: (argument_list . (string_literal) @_alg)\n  (#eq? @_cls \"MessageDigest\")\n  (#eq? @_fn \"getInstance\")\n  (#match? @_alg \"(?i)['\\\"](md5|sha-?1)['\\\"]\"))",
                    ),
                    // hashlib.md5(...) / hashlib.sha1(...)
                    q(
                        "python",
                        "(call\n  function: (attribute\n    object: (identifier) @_mod\n    attribute: (identifier) @_fn)\n  (#eq? @_mod \"hashlib\")\n  (#match? @_fn \"^(md5|sha1)$\"))",
                    ),
                    // Md5::new() / Sha1::new()
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#match? @_mod \"^(Md5|Sha1)$\")\n  (#eq? @_fn \"new\"))",
                    ),
                    // md5::compute(...)
                    q(
                        "rust",
                        "(call_expression\n  function: (scoped_identifier\n    path: (identifier) @_mod\n    name: (identifier) @_fn)\n  (#eq? @_mod \"md5\")\n  (#eq? @_fn \"compute\"))",
                    ),
                    // MD5(d, n, md) / SHA1(d, n, md)
                    q(
                        "c",
                        "(call_expression\n  function: (identifier) @_f\n  (#match? @_f \"^(MD5|SHA1)$\"))",
                    ),
                ],
                cwe: Some("CWE-328".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT014".to_string(),
                title: "JWT signed with RSA/ECDSA (RS256/ES256/PS256)".to_string(),
                severity: Severity::High,
                description: "A JWT is signed with a classical algorithm \
                    (RS256, ES256, PS256). Tokens are long-lived bearer \
                    credentials — the textbook harvest-now-decrypt-later \
                    target — and every verifier must migrate with the signer."
                    .to_string(),
                remediation: "Plan migration to ML-DSA-based JWT profiles as \
                    they standardize (no registered JWA PQC algorithm yet — \
                    track NIST/JOSE). Until then, shorten token lifetimes and \
                    inventory every signer/verifier pair."
                    .to_string(),
                queries: vec![
                    // { ..., algorithm: 'RS256' }
                    q(
                        "javascript",
                        "(pair\n  key: (property_identifier) @_k\n  value: (string) @_v\n  (#eq? @_k \"algorithm\")\n  (#match? @_v \"(?i)(RS256|ES256|PS256)\"))",
                    ),
                    // jwt.encode(payload, key, algorithm='RS256')
                    q(
                        "python",
                        "(keyword_argument\n  name: (identifier) @_k\n  value: (string) @_v\n  (#eq? @_k \"algorithm\")\n  (#match? @_v \"(?i)(RS256|ES256|PS256)\"))",
                    ),
                    // SignatureAlgorithm.RS256
                    q(
                        "java",
                        "(field_access\n  field: (identifier) @_f\n  (#match? @_f \"^(RS256|ES256|PS256)$\"))",
                    ),
                    // jsonwebtoken::Algorithm::RS256
                    q(
                        "rust",
                        "((identifier) @_i\n  (#match? @_i \"^(RS256|ES256|PS256)$\"))",
                    ),
                    // jwt.SigningMethodRS256
                    q(
                        "go",
                        "(selector_expression\n  field: (field_identifier) @_f\n  (#match? @_f \"^SigningMethod(RS256|ES256|PS256)$\"))",
                    ),
                ],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT015".to_string(),
                title: "OpenPGP private key material".to_string(),
                severity: Severity::Critical,
                description: "An OpenPGP private key block was found in the \
                    source tree. Embedded private keys are compromised by \
                    definition — and the RSA/ECDSA keys PGP uses are \
                    quantum-vulnerable on top of it."
                    .to_string(),
                remediation: "Remove the key from source control immediately \
                    and rotate it. PGP has no PQC migration path yet; track \
                    the OpenPGP PQC draft and plan accordingly."
                    .to_string(),
                // Detected by the secrets engine (armor parsing), not tree-sitter.
                queries: vec![],
                cwe: Some("CWE-798".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT016".to_string(),
                title: "Classical-crypto library dependency".to_string(),
                severity: Severity::Medium,
                description: "A direct dependency exposes classical public-key cryptography \
                    or legacy cryptographic helpers. Presence is an inventory signal; it does \
                    not establish active use, algorithm selection, or absence of PQC support."
                    .to_string(),
                remediation: "Review the dependency's actual call sites and maintenance status. \
                    Plan PQC migration for classical public-key uses; symmetric primitives \
                    require separate algorithm and key-size review."
                    .to_string(),
                queries: vec![],
                cwe: None,
                orange_note: None,
            },
            Rule {
                id: "SNOOT017".to_string(),
                title: "Abandoned or known-vulnerable crypto dependency".to_string(),
                severity: Severity::High,
                description: "A dependency manifest declares a cryptography \
                    library that is abandoned or has known CVEs \
                    (e.g. rust-crypto, PyCrypto, golang-jwt v3). Unmaintained \
                    crypto is broken classically *and* quantum-vulnerable."
                    .to_string(),
                remediation: "Replace immediately: rust-crypto → maintained \
                    crates (RustCrypto, aws-lc-rs); PyCrypto → pycryptodome; \
                    golang-jwt/jwt v3 → golang-jwt/jwt/v5. Then plan PQC \
                    migration for the replacement."
                    .to_string(),
                // Detected by the manifest engine, not tree-sitter.
                queries: vec![],
                cwe: Some("CWE-1104".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT018".to_string(),
                title: "Weak TLS protocol versions (< 1.2)".to_string(),
                severity: Severity::High,
                description: "A TLS configuration enables SSLv2, SSLv3, \
                    TLS 1.0, or TLS 1.1. These are broken classically \
                    (POODLE, BEAST, Lucky 13 class) and forbidden by PCI DSS; \
                    every connection they negotiate is exposed."
                    .to_string(),
                remediation: "Disable SSLv2/SSLv3/TLS 1.0/TLS 1.1; minimum \
                    TLS 1.2, prefer TLS 1.3. Then enable hybrid PQC key \
                    exchange (SNOOT005)."
                    .to_string(),
                // Detected by the tlsconf engine, not tree-sitter.
                queries: vec![],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT019".to_string(),
                title: "Weak TLS cipher suites".to_string(),
                severity: Severity::High,
                description: "A TLS cipher string enables RC4, (3)DES, \
                    export-grade, NULL, anonymous, or MD5-based suites. \
                    Broken or deliberately weakened classically — and \
                    negotiated without any quantum resistance."
                    .to_string(),
                remediation: "Restrict to AEAD suites (TLS 1.3 suites, \
                    ECDHE+AESGCM / ECDHE+ChaCha20). Remove RC4, 3DES, \
                    export, NULL, and anonymous suites entirely."
                    .to_string(),
                // Detected by the tlsconf engine, not tree-sitter.
                queries: vec![],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT020".to_string(),
                title: "RSA-signed X.509 certificate".to_string(),
                severity: Severity::Medium,
                description: "An X.509 certificate signed with RSA (e.g. \
                    sha256WithRSAEncryption) was found in the tree. \
                    Certificates are long-lived trust artifacts: every \
                    RSA-signed certificate must be replaced with a PQC-signed \
                    one during migration, and the inventory starts here."
                    .to_string(),
                remediation: "Inventory this certificate for PQC migration. \
                    Replace with ML-DSA-signed certificates (FIPS 204) on \
                    CNSA 2.0 timelines; use hybrid classical+PQC chains \
                    during transition. Shorten certificate lifetimes in the \
                    meantime."
                    .to_string(),
                // Detected by the secrets engine (X.509 parsing), not tree-sitter.
                queries: vec![],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT021".to_string(),
                title: "ECDSA-signed X.509 certificate".to_string(),
                severity: Severity::Medium,
                description: "An X.509 certificate signed with ECDSA (e.g. \
                    ecdsa-with-SHA256) was found in the tree. ECDSA \
                    signatures fall to Shor's algorithm; every ECDSA-signed \
                    certificate must be replaced with a PQC-signed one \
                    during migration."
                    .to_string(),
                remediation: "Inventory this certificate for PQC migration. \
                    Replace with ML-DSA-signed certificates (FIPS 204) on \
                    CNSA 2.0 timelines; use hybrid classical+PQC chains \
                    during transition."
                    .to_string(),
                // Detected by the secrets engine (X.509 parsing), not tree-sitter.
                queries: vec![],
                cwe: Some("CWE-327".to_string()),
                orange_note: None,
            },
            Rule {
                id: "SNOOT022".to_string(),
                title: "Public key / certificate inventory".to_string(),
                severity: Severity::Info,
                description: "A public key or certificate was inventoried without a specific \
                    RSA/ECDSA certificate finding. Inventory severity does not establish quantum \
                    safety: RSA, EC, Ed25519, and other classical public-key algorithms require review."
                    .to_string(),
                remediation: "Review the algorithm and use of this asset. Include classical \
                    public keys and Ed25519 signatures in the post-quantum migration inventory."
                    .to_string(),
                // Detected by the secrets engine (DER/JWK parsing), not tree-sitter.
                queries: vec![],
                cwe: None,
                orange_note: None,
            },
        ]
    }

    // Used by unit tests now; by the code engine starting week 2.
    #[allow(dead_code)]
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
    fn registry_has_all_rules() {
        let rules = RuleRegistry::all();
        assert_eq!(rules.len(), 22);
        for n in 1..=22 {
            let id = format!("SNOOT{n:03}");
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

    /// Rules detected by non-code engines carry no tree-sitter queries;
    /// every other rule must ship at least one.
    #[test]
    fn code_rules_carry_queries() {
        const ENGINE_RULES: &[&str] = &[
            "SNOOT003", "SNOOT005", "SNOOT009", "SNOOT015", // secrets / tlsconf
            "SNOOT016", "SNOOT017", // manifest
            "SNOOT018", "SNOOT019", // tlsconf
            "SNOOT020", "SNOOT021", "SNOOT022", // secrets (certs, JWK, DER)
        ];
        for rule in RuleRegistry::all() {
            if ENGINE_RULES.contains(&rule.id.as_str()) {
                assert!(
                    rule.queries.is_empty(),
                    "{} should be engine-detected, but carries queries",
                    rule.id
                );
            } else {
                assert!(
                    !rule.queries.is_empty(),
                    "{} has no tree-sitter queries",
                    rule.id
                );
            }
        }
    }

    #[test]
    fn existing_rule_ids_and_titles_stable() {
        // SNOOT001–SNOOT005 must keep their week-1 identity, modulo the
        // week-5 rename of SNOOT003: it fires on DER and JWK as well as
        // PEM now, so "in PEM" was a lie.
        let expected = [
            ("SNOOT001", "RSA key generation"),
            ("SNOOT002", "ECDSA signing"),
            ("SNOOT003", "RSA private key material"),
            ("SNOOT004", "Weak Diffie-Hellman parameters"),
            (
                "SNOOT005",
                "TLS configuration without PQC hybrid key exchange",
            ),
        ];
        for (id, title) in expected {
            let rule = RuleRegistry::by_id(id).unwrap();
            assert_eq!(rule.title, title, "{id} title changed");
        }
        // Same rename rationale for SNOOT009.
        assert_eq!(
            RuleRegistry::by_id("SNOOT009").unwrap().title,
            "EC private key material"
        );
    }
}
