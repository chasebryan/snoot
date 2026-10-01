//! Manifest engine: dependency-manifest scanning.
//!
//! **Job** (DESIGN.md §5): parse dependency manifests *properly* — TOML for
//! Cargo, JSON for npm, the go.mod DSL, requirements.txt / pyproject formats,
//! Maven POM XML, Gradle — and flag dependencies that pull in classical
//! crypto from a curated table shipped in the binary (no network calls):
//! abandoned crypto libraries (SNOOT017: rust-crypto, PyCrypto,
//! golang-jwt v3) and maintained-but-classical-only crypto libraries
//! (SNOOT016: pycryptodome, node-rsa, Bouncy Castle, …).
//!
//! Manifests are parsed, never regexed: each ecosystem gets a real parser
//! for its format, and flagged dependencies resolve against declared version
//! ranges with semver-ish comparison where the table carries one.
//!
//! v1 covers direct dependencies only (DESIGN.md §3: transitive analysis is
//! explicitly out of scope). Lockfiles are skipped — they enumerate
//! transitive deps, which v1 doesn't inventory.
//!
//! **Status**: week-3 milestone, implemented.

use std::collections::HashSet;
use std::path::Path;

use crate::engines::Engine;
use crate::model::{Evidence, Finding};
use crate::rules::RuleRegistry;

pub struct ManifestEngine;

/// Manifest file names this engine understands, per ecosystem.
/// Lockfiles are deliberately absent (v1: direct deps only).
const MANIFEST_FILES: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "go.mod",
    "requirements.txt",
    "pyproject.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
];

/// One dependency found in a manifest.
struct Dep {
    name: String,
    req: String,
    line: Option<u32>,
}

/// Curated table of classical-crypto dependencies. Small on purpose —
/// every entry is a library whose *entire purpose* is classical public-key
/// crypto (or an abandoned crypto lib with known CVEs), so presence alone
/// is a meaningful inventory signal.
struct FlaggedDep {
    /// Dependency name (lowercase). Matched exactly, by `prefix`, or as a
    /// `/`-suffixed tail (Go module paths).
    name: &'static str,
    prefix: bool,
    rule: &'static str,
    note: &'static str,
    /// Flag only when the declared version is below this (semver-ish).
    max_version: Option<&'static str>,
}

const FLAGGED: &[FlaggedDep] = &[
    // Abandoned / known-vulnerable crypto libraries.
    FlaggedDep {
        name: "rust-crypto",
        prefix: false,
        rule: "SNOOT017",
        note: "abandoned since 2016; unmaintained RSA/DH",
        max_version: None,
    },
    FlaggedDep {
        name: "pycrypto",
        prefix: false,
        rule: "SNOOT017",
        note: "abandoned; known CVEs; superseded by pycryptodome",
        max_version: None,
    },
    FlaggedDep {
        name: "golang-jwt/jwt",
        prefix: false,
        rule: "SNOOT017",
        note: "v3 line unmaintained with known CVEs; use golang-jwt/jwt/v5",
        max_version: Some("v5.0.0"),
    },
    FlaggedDep { name: "rsa", prefix: false, rule: "SNOOT016", note: "RSA API surface; dependency presence does not establish active use", max_version: None },
    FlaggedDep { name: "ecdsa", prefix: false, rule: "SNOOT016", note: "ECDSA API surface; dependency presence does not establish active use", max_version: None },
    FlaggedDep { name: "p256", prefix: false, rule: "SNOOT016", note: "P-256 API surface; dependency presence does not establish active use", max_version: None },
    FlaggedDep { name: "p384", prefix: false, rule: "SNOOT016", note: "P-384 API surface; dependency presence does not establish active use", max_version: None },
    FlaggedDep { name: "x25519-dalek", prefix: false, rule: "SNOOT016", note: "X25519 API surface; dependency presence does not establish active use", max_version: None },
    FlaggedDep { name: "ed25519-dalek", prefix: false, rule: "SNOOT016", note: "Ed25519 API surface (quantum-vulnerable signature inventory); dependency presence does not establish active use", max_version: None },
    FlaggedDep { name: "node-forge", prefix: false, rule: "SNOOT016", note: "classical public-key API surface; dependency presence does not establish active use", max_version: None },
    // Maintained, but classical-only crypto.
    FlaggedDep {
        name: "pycryptodome",
        prefix: false,
        rule: "SNOOT016",
        note: "classical RSA/ECC",
        max_version: None,
    },
    FlaggedDep {
        name: "pycryptodomex",
        prefix: false,
        rule: "SNOOT016",
        note: "classical RSA/ECC",
        max_version: None,
    },
    FlaggedDep {
        name: "cryptography",
        prefix: false,
        rule: "SNOOT016",
        note: "classical RSA/ECC",
        max_version: None,
    },
    FlaggedDep {
        name: "node-rsa",
        prefix: false,
        rule: "SNOOT016",
        note: "RSA-only; no PQC path",
        max_version: None,
    },
    FlaggedDep {
        name: "crypto-js",
        prefix: false,
        rule: "SNOOT016",
        note: "classical ciphers/hashes only",
        max_version: None,
    },
    FlaggedDep {
        name: "jsrsasign",
        prefix: false,
        rule: "SNOOT016",
        note: "classical RSA/ECDSA",
        max_version: None,
    },
    FlaggedDep {
        name: "jsonwebtoken",
        prefix: false,
        rule: "SNOOT016",
        note: "JWT with classical algorithms by default",
        max_version: None,
    },
    FlaggedDep {
        name: "bcprov-",
        prefix: true,
        rule: "SNOOT016",
        note: "Bouncy Castle: classical RSA/ECC provider",
        max_version: None,
    },
    FlaggedDep {
        name: "bcmail-",
        prefix: true,
        rule: "SNOOT016",
        note: "Bouncy Castle: classical RSA/ECC provider",
        max_version: None,
    },
    FlaggedDep {
        name: "bcpkix-",
        prefix: true,
        rule: "SNOOT016",
        note: "Bouncy Castle: classical RSA/ECC provider",
        max_version: None,
    },
];

/// Match a dependency name against the flagged table.
fn flagged(name: &str, req: &str) -> Option<(&'static str, &'static str)> {
    let lower = name.to_ascii_lowercase();
    for f in FLAGGED {
        let hit = if f.prefix {
            lower.starts_with(f.name)
        } else {
            lower == f.name || lower.ends_with(&format!("/{}", f.name))
        };
        if !hit {
            continue;
        }
        if let Some(max) = f.max_version {
            if !version_lt(req, max) {
                continue;
            }
        }
        return Some((f.rule, f.note));
    }
    None
}

/// Leading numeric components of a version string, e.g. "v3.2.2" → `[3,2,2]`.
/// Strips common range prefixes (^, ~, >=, …); empty input → `[0]`.
fn norm_version(s: &str) -> Vec<u64> {
    let s = s
        .trim()
        .trim_start_matches(['v', '=', '^', '~', '>', '<', ' ', '!']);
    let numeric: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts: Vec<u64> = numeric.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.is_empty() {
        parts.push(0);
    }
    parts
}

/// True when `have` is an older version than `max`. Unknown/empty versions
/// count as older (fail closed for the abandoned-library list).
fn version_lt(have: &str, max: &str) -> bool {
    let (mut a, mut b) = (norm_version(have), norm_version(max));
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    a < b
}

/// First 1-based line containing `name` (for finding locations).
fn find_line(text: &str, name: &str) -> Option<u32> {
    text.lines()
        .enumerate()
        .find_map(|(i, l)| l.contains(name).then_some(i as u32 + 1))
}

fn dep(name: String, req: String, text: &str) -> Dep {
    let line = find_line(text, &name);
    Dep { name, req, line }
}

// --- per-ecosystem parsers -------------------------------------------------

fn parse_cargo_toml(text: &str) -> Vec<Dep> {
    let Ok(table) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let mut deps = Vec::new();
    let mut collect = |t: &toml::Table| {
        for (name, v) in t {
            let package = v
                .as_table()
                .and_then(|t| t.get("package"))
                .and_then(|v| v.as_str())
                .unwrap_or(name);
            let req = match v {
                toml::Value::String(s) => s.clone(),
                toml::Value::Table(t) => t
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            deps.push(dep(package.to_string(), req, text));
        }
    };
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = table.get(section).and_then(|v| v.as_table()) {
            collect(t);
        }
    }
    if let Some(target) = table.get("target").and_then(|v| v.as_table()) {
        for (_, cfg) in target {
            for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(d) = cfg.get(section).and_then(|v| v.as_table()) {
                    collect(d);
                }
            }
        }
    }
    deps
}

fn parse_package_json(text: &str) -> Vec<Dep> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut deps = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(map) = v.get(section).and_then(|v| v.as_object()) {
            for (name, ver) in map {
                deps.push(dep(
                    name.clone(),
                    ver.as_str().unwrap_or("").to_string(),
                    text,
                ));
            }
        }
    }
    deps
}

/// Split a PEP 508 / requirements-style `name[extras]>=1.0; marker` into
/// (name, version-spec).
fn split_req(s: &str) -> Option<(String, String)> {
    let s = s
        .split('#')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if s.is_empty() {
        return None;
    }
    let name: String = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    if name.is_empty() {
        return None;
    }
    let mut rest = &s[name.len()..];
    if let Some(after) = rest.strip_prefix('[') {
        rest = after.split(']').nth(1).unwrap_or("");
    }
    Some((name, rest.trim().to_string()))
}

fn parse_requirements_txt(text: &str) -> Vec<Dep> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                return None;
            }
            let (name, req) = split_req(line)?;
            Some(Dep {
                name,
                req,
                line: Some(i as u32 + 1),
            })
        })
        .collect()
}

fn parse_pyproject_toml(text: &str) -> Vec<Dep> {
    let Ok(table) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let mut deps = Vec::new();
    // [project] dependencies = ["name>=1.0", ...]
    if let Some(arr) = table
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for item in arr {
            if let Some(s) = item.as_str() {
                if let Some((name, req)) = split_req(s) {
                    deps.push(dep(name, req, text));
                }
            }
        }
    }
    // [tool.poetry.dependencies]
    if let Some(t) = table
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for (name, v) in t {
            if name == "python" {
                continue;
            }
            let req = match v {
                toml::Value::String(s) => s.clone(),
                toml::Value::Table(t) => t
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            deps.push(dep(name.clone(), req, text));
        }
    }
    deps
}

fn parse_go_mod(text: &str) -> Vec<Dep> {
    let mut deps = Vec::new();
    let mut in_require = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.split("//").next().unwrap_or("").trim();
        if t.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require && t == ")" {
            in_require = false;
            continue;
        }
        let req_line = if in_require {
            t
        } else if let Some(r) = t.strip_prefix("require ") {
            r
        } else {
            continue;
        };
        let mut parts = req_line.split_whitespace();
        let (Some(module), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        deps.push(Dep {
            name: module.to_string(),
            req: version.to_string(),
            line: Some(i as u32 + 1),
        });
    }
    deps
}

fn tag_content(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = line.find(&open)? + open.len();
    let e = line[s..].find(&close)?;
    Some(line[s..s + e].trim().to_string())
}

fn parse_pom_xml(text: &str) -> Vec<Dep> {
    // Preserve line offsets while ignoring XML comments. The dependency fields may share a line.
    let mut cleaned = text.to_string();
    while let Some(start) = cleaned.find("<!--") {
        let Some(end) = cleaned[start + 4..].find("-->").map(|i| start + 4 + i + 3) else {
            break;
        };
        let blank: String = cleaned[start..end]
            .chars()
            .map(|c| if c == '\n' { '\n' } else { ' ' })
            .collect();
        cleaned.replace_range(start..end, &blank);
    }
    let mut deps = Vec::new();
    let mut offset = 0;
    while let Some(start) = cleaned[offset..].find("<dependency>").map(|i| offset + i) {
        let Some(end) = cleaned[start..].find("</dependency>").map(|i| start + i) else {
            break;
        };
        let block = &cleaned[start..end];
        if let Some(name) = tag_content(block, "artifactId") {
            deps.push(Dep {
                name,
                req: tag_content(block, "version").unwrap_or_default(),
                line: Some(cleaned[..start].bytes().filter(|b| *b == b'\n').count() as u32 + 1),
            });
        }
        offset = end + "</dependency>".len();
    }
    deps
}

fn parse_build_gradle(text: &str) -> Vec<Dep> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let t = line.trim();
            if t.starts_with("//")
                || t.starts_with('#')
                || t.starts_with("/*")
                || t.starts_with('*')
            {
                return None;
            }
            let declaration = t.split(|c: char| c.is_whitespace() || c == '(').next()?;
            if ![
                "implementation",
                "api",
                "compile",
                "compileOnly",
                "runtimeOnly",
                "testImplementation",
                "testCompile",
                "testRuntimeOnly",
                "annotationProcessor",
                "classpath",
            ]
            .contains(&declaration)
            {
                return None;
            }
            let q = t.find(['\'', '"'])?;
            let quote = t.as_bytes()[q] as char;
            let rest = &t[q + 1..];
            let end = rest.find(quote)?;
            let mut parts = rest[..end].split(':');
            let (_group, name, version) = (parts.next()?, parts.next()?, parts.next()?);
            Some(Dep {
                name: name.to_string(),
                req: version.to_string(),
                line: Some(i as u32 + 1),
            })
        })
        .collect()
}

fn deps_for_file(file_name: &str, text: &str) -> Vec<Dep> {
    match file_name {
        "Cargo.toml" => parse_cargo_toml(text),
        "package.json" => parse_package_json(text),
        "requirements.txt" => parse_requirements_txt(text),
        "pyproject.toml" => parse_pyproject_toml(text),
        "go.mod" => parse_go_mod(text),
        "pom.xml" => parse_pom_xml(text),
        "build.gradle" | "build.gradle.kts" => parse_build_gradle(text),
        _ => Vec::new(),
    }
}

impl Engine for ManifestEngine {
    fn name(&self) -> &'static str {
        "manifest"
    }

    fn file_matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| MANIFEST_FILES.contains(&n))
            .unwrap_or(false)
    }

    fn validate(&self, path: &Path, content: &[u8]) -> anyhow::Result<()> {
        let text = std::str::from_utf8(content)?;
        match path.file_name().and_then(|n| n.to_str()) {
            Some("Cargo.toml" | "pyproject.toml") => {
                text.parse::<toml::Table>()?;
            }
            Some("package.json") => {
                serde_json::from_str::<serde_json::Value>(text)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Vec<Finding> {
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let text = String::from_utf8_lossy(content);
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for dep in deps_for_file(file_name, &text) {
            let Some((rule_id, note)) = flagged(&dep.name, &dep.req) else {
                continue;
            };
            let Some(rule) = RuleRegistry::by_id(rule_id) else {
                continue;
            };
            let snippet = format!("{} {}", dep.name, dep.req).trim().to_string();
            let displayed = snippet.chars().take(160).collect();
            let mut finding = Finding::new(
                &rule,
                path.to_string_lossy().replace('\\', "/"),
                dep.line,
                Some(snippet),
                Evidence {
                    kind: "manifest_dep".to_string(),
                    detail: format!(
                        "dependency \"{}\" ({file_name}): {note}",
                        dep.name.to_ascii_lowercase()
                    ),
                },
            );
            finding.location.snippet = Some(displayed);
            if seen.insert(finding.fingerprint.clone()) {
                findings.push(finding);
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_toml_parses_sections() {
        let text = r#"
[package]
name = "demo"

[dependencies]
serde = "1"
rust-crypto = { version = "0.2", optional = true }

[dev-dependencies]
tempfile = "3"
"#;
        let deps = parse_cargo_toml(text);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"rust-crypto"));
        assert!(names.contains(&"tempfile"));
        let rc = deps.iter().find(|d| d.name == "rust-crypto").unwrap();
        assert_eq!(rc.req, "0.2");
    }

    #[test]
    fn package_json_parses_dep_sections() {
        let text =
            r#"{"dependencies": {"node-rsa": "^1.1.5"}, "devDependencies": {"jest": "^29"}}"#;
        let deps = parse_package_json(text);
        assert_eq!(deps.len(), 2);
        let rsa = deps.iter().find(|d| d.name == "node-rsa").unwrap();
        assert_eq!(rsa.req, "^1.1.5");
    }

    #[test]
    fn requirements_txt_skips_noise() {
        let text = "# comment\n-r other.txt\nrequests==2.31.0\npycrypto[full]>=2.6.1 ; python_version > '2.7'\n";
        let deps = parse_requirements_txt(text);
        assert_eq!(deps.len(), 2);
        let pc = deps.iter().find(|d| d.name == "pycrypto").unwrap();
        assert!(pc.req.contains("2.6.1"));
    }

    #[test]
    fn go_mod_parses_blocks_and_singles() {
        let text = "module demo\n\ngo 1.21\n\nrequire (\n\tgithub.com/a/b v1.2.3\n)\n\nrequire github.com/golang-jwt/jwt v3.2.2\n";
        let deps = parse_go_mod(text);
        assert_eq!(deps.len(), 2);
        let jwt = deps.iter().find(|d| d.name.contains("golang-jwt")).unwrap();
        assert_eq!(jwt.req, "v3.2.2");
    }

    #[test]
    fn pom_xml_parses_dependencies() {
        let text = "<project>\n<dependencies>\n<dependency>\n<groupId>org.bouncycastle</groupId>\n<artifactId>bcprov-jdk18on</artifactId>\n<version>1.78.1</version>\n</dependency>\n</dependencies>\n</project>";
        let deps = parse_pom_xml(text);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "bcprov-jdk18on");
        assert_eq!(deps[0].req, "1.78.1");
    }

    #[test]
    fn build_gradle_parses_coordinates() {
        let text = "dependencies {\n    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'\n    testImplementation(\"junit:junit:4.13.2\")\n}\n";
        let deps = parse_build_gradle(text);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "bcprov-jdk18on"));
    }

    #[test]
    fn flagged_table_matches() {
        assert_eq!(flagged("pycrypto", "2.6.1").unwrap().0, "SNOOT017");
        assert_eq!(flagged("PyCrypto", "").unwrap().0, "SNOOT017");
        assert_eq!(flagged("node-rsa", "^1.1.5").unwrap().0, "SNOOT016");
        assert_eq!(
            flagged("github.com/golang-jwt/jwt", "v3.2.2").unwrap().0,
            "SNOOT017"
        );
        // v5 is the fixed line: not flagged.
        assert!(flagged("github.com/golang-jwt/jwt/v5", "v5.0.0").is_none());
        assert!(flagged("github.com/golang-jwt/jwt", "v5.0.0").is_none());
        assert_eq!(flagged("bcprov-jdk18on", "1.78").unwrap().0, "SNOOT016");
        assert!(flagged("requests", "2.31").is_none());
        assert!(flagged("serde", "1").is_none());
    }

    #[test]
    fn version_lt_behaves() {
        assert!(version_lt("v3.2.2", "v5.0.0"));
        assert!(!version_lt("v5.0.0", "v5.0.0"));
        assert!(!version_lt("v5.1.0", "v5.0.0"));
        assert!(version_lt("", "v5.0.0")); // unknown → fail closed
        assert!(version_lt("^3.2", "5"));
    }

    #[test]
    fn scan_flags_cargo_toml() {
        let engine = ManifestEngine;
        let path = Path::new("Cargo.toml");
        let content = b"[dependencies]\nserde = \"1\"\nrust-crypto = \"0.2\"\n";
        assert!(engine.file_matches(path));
        let findings = engine.scan(path, content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SNOOT017");
        assert_eq!(findings[0].location.line, Some(3));
        assert_eq!(findings[0].evidence.kind, "manifest_dep");
    }

    #[test]
    fn scan_ignores_clean_manifest() {
        let engine = ManifestEngine;
        let findings = engine.scan(
            Path::new("package.json"),
            br#"{"dependencies": {"express": "^4.18.2"}}"#,
        );
        assert!(findings.is_empty());
    }
}
