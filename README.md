# snoot

[![CI](https://github.com/chasebryan/snoot/actions/workflows/ci.yml/badge.svg)](https://github.com/chasebryan/snoot/actions/workflows/ci.yml)

*Snoot out the crypto hiding in your codebase.*

snoot scans a source tree for classical public-key cryptography — RSA,
ECDSA/ECDH, DSA, DH — in API calls, key material, dependency manifests, and
TLS configs. It reports what's quantum-vulnerable, maps each finding to its
NIST post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA), and emits
machine-readable inventory evidence: SARIF (GitHub code scanning), CycloneDX 1.6
CBOM, and JSON.

**First public release: v0.1.0, experimental cryptography inventory.** Four detection
engines cover source code, key material, dependency manifests, and TLS
configuration, with 22 rules and eight source languages. Reports and baselines
have automated regression checks. Detection remains heuristic: a clean scan
is not proof that a repository is quantum-safe or that every cryptographic use
has been found. Validation and remaining detection work are recorded in
[docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

## GitHub Action

Add `.github/workflows/snoot.yml` to the repository you want to scan:

```yaml
name: Cryptography inventory
on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  snoot:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
      - uses: chasebryan/snoot@v0.1.0
        id: scan
        with:
          path: .
          fail-on: high
          # Fork PR tokens cannot upload SARIF; scanning and gating still run.
          upload-sarif: ${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}
```

SARIF upload is available for public GitHub.com repositories and eligible
organization repositories with GitHub Code Security enabled. If you only need
a local report and severity gate, set `upload-sarif: 'false'` and use just
`contents: read`. Upload errors fail the action. Do not use `pull_request_target`
to give untrusted fork code a privileged token.

The action builds the selected source revision using Rust 1.90 and `Cargo.lock`;
the first build can take several minutes. GitHub-hosted Ubuntu, macOS, and
Windows runners are supported. Self-hosted runners need Bash, Python 3.9+,
rustup, a native C/C++ compiler/linker, and access to Rust/Cargo distribution
servers. Container jobs and other runner configurations are not validated.
Scanning runs offline; optional SARIF upload sends filenames and evidence
snippets to GitHub. No additional secrets or external services are required.

Use the exact release tag above for a fixed version, or a full release commit
SHA for stronger source pinning. Development `main` is not a release reference.
The action builds from source rather than trusting downloadable release binaries.

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | File/directory to scan, relative to the repository workspace |
| `fail-on` | `high` | `info`, `low`, `medium`, `high`, `critical`; `''` disables gating |
| `exclude` | `''` | Comma-separated globs relative to the scan root |
| `baseline` | `''` | Version-2 baseline file, relative to the repository workspace |
| `sarif` | `snoot.sarif` | Output file, relative to the repository workspace |
| `upload-sarif` | `'true'` | Exact `'true'` or `'false'`; uploading needs permissions above |
| `category` | `snoot` | Unique code-scanning category for each scan of the same commit |

Paths must stay inside the checked-out workspace. Spaces are supported; newline
characters in path inputs are rejected. Findings in a subdirectory scan are
linked to their repository-relative locations. Baseline identities remain
relative to the scan root, so create a baseline using the same `path` and exclusions.

| Output | Meaning |
| --- | --- |
| `sarif` | Absolute path to a completed report; empty on scan/input failure |
| `finding-count` | Unsuppressed finding count, including findings below the gate |
| `exit-code` | `0` completed below threshold, `2` severity gate, `3` scan error |

The action writes and optionally uploads the report before failing the severity
gate. Build/input errors fail the action and can leave outputs empty. An upload
failure fails the action even if the scanner's `exit-code` is `0`.

For existing repositories, review accepted findings into a baseline and commit it:

```sh
snoot init . --output .snoot-baseline.json
```

Then configure `baseline: .snoot-baseline.json`. Review baseline and exclusion
changes: suppressed findings do not trigger the severity gate. For monorepos,
set distinct `category` and `sarif` values for each scan, such as
`category: snoot-api` and `sarif: snoot-api.sarif`.

To retain the report as a workflow artifact even when findings fail the gate:

```yaml
- uses: actions/upload-artifact@v7
  if: ${{ always() && steps.scan.outputs.sarif != '' }}
  with:
    name: snoot-sarif
    path: ${{ steps.scan.outputs.sarif }}
```

See [release notes](docs/releases/v0.1.0.md),
[security reporting](SECURITY.md), and [contribution guide](CONTRIBUTING.md).

## CLI installation

Download a native archive and its `.sha256` file from
[GitHub Releases](https://github.com/chasebryan/snoot/releases).
Verify the SHA-256 checksum before extracting, then add the extracted `snoot`
(or `snoot.exe`) to your `PATH`.

| Platform | Archive target | Minimum runtime |
| --- | --- | --- |
| Linux x64 | `x86_64-unknown-linux-gnu.tar.gz` | glibc 2.35 |
| Linux ARM64 | `aarch64-unknown-linux-gnu.tar.gz` | glibc 2.35 |
| macOS Intel | `x86_64-apple-darwin.tar.gz` | macOS 11 |
| macOS Apple Silicon | `aarch64-apple-darwin.tar.gz` | macOS 11 |
| Windows x64 | `x86_64-pc-windows-msvc.zip` | Windows with the MSVC runtime |

Names start with `snoot-v0.1.0-`. For example, on Linux x64:

```sh
sha256sum -c snoot-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
# macOS: shasum -a 256 -c <archive>.sha256
# Windows PowerShell: Get-FileHash <archive>.zip -Algorithm SHA256
```

macOS binaries are unsigned and not notarized; environments requiring signed
software should build from reviewed source. Snoot is not published on crates.io.
A source installation requires Rust 1.90 and a native C/C++ build toolchain:

```sh
git clone https://github.com/chasebryan/snoot.git
cd snoot
git checkout v0.1.0
cargo install --path . --locked
snoot scan ./myapp
snoot scan ./myapp --format sarif --output results.sarif --fail-on high
snoot scan ./myapp --exclude 'tests/fixtures/**'
snoot rules
```

## Why now: harvest now, decrypt later

Encrypted traffic can be recorded now and decrypted after a cryptographically
relevant quantum computer becomes available. Classical RSA encryption and
ECDH/DH key exchange are vulnerable to that future threat. RSA, ECDSA, DSA,
and Ed25519 signatures face future forgery risk as well. Inventorying the
cryptography in a repository helps teams plan their migration.

NIST's post-quantum standards define ML-KEM for key establishment, ML-DSA for
signatures, and SLH-DSA for signatures. Migration choices depend on the use
of a key and the protocols that consume it; a scanner finding starts that review.

## Baselines, outputs, and CI

```sh
snoot init ./myapp --output .snoot-baseline.json
snoot scan ./myapp --baseline .snoot-baseline.json --fail-on high
snoot init ./myapp --output .snoot-baseline.json --force
snoot scan ./myapp --format json --format sarif --format cbom --output reports
```

One format writes to stdout or the named output file. Multiple formats require
an output directory and produce separate `snoot.json`, `snoot.sarif`,
`snoot.cdx.json`, or `snoot.txt` files. Existing scan source files and symlink
outputs are protected from report overwrites; generated reports can be replaced.

Baselines use version 2 fingerprints relative to the scan root. Regenerate
older baselines after reviewing the findings. Moving code down a file or moving
a checkout preserves suppression. Changing a call's arguments, key material,
or relative filename reports it again. Identical calls in one file share a
baseline identity: suppression does not track their number of copies.

Exit codes are **0** for a completed scan below the requested threshold,
**2** for findings at or above `--fail-on` (also used for invalid CLI arguments),
and **3** for scan, baseline, validation, or output errors. Reports are written
before returning a findings exit code. Suppressed findings do not fail CI.

`--exclude` accepts root-relative globs (`*`, `**`, and character classes),
including bare filename patterns. `.snootignore` additionally accepts exact
paths, directory prefixes ending in `/`, and simple `*` patterns; it does not
implement gitignore negation or the full gitignore grammar. The repository
excludes deliberate key fixtures from self-scans and tests them separately.

## Development checks

Requires Rust 1.90; the tested toolchain is pinned in the checkout.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- scan . --fail-on high
python -m pip install jsonschema==4.23.0
python scripts/validate_reports.py target/debug/snoot
```

Only the development schema validator downloads schemas. Snoot scans offline.

## Pipeline

**snoot discovers → [orange](https://github.com/chasebryan/orange) verifies →
[orange-school](https://github.com/chasebryan/orange-school) teaches.**
Findings for primitives orange supports carry an `orange_note` pointing at
what orange can verify or replace.

## Detection limits

- Heuristic detection; no data-flow analysis — a flagged call site means
  "look here", not "this is exploitable". snoot doesn't know whether a key
  protects long-lived data. Findings under test/example directories are
  demoted to medium by path convention; the path does not establish deployability.
- Can't see obfuscated code, dynamically loaded crypto libraries, or crypto
  behind FFI boundaries it has no queries for.
- Deliberate blind spots: PKCS#12 bundles, DSA private keys, and
  `ENCRYPTED PRIVATE KEY` blocks (algorithm unknowable without the
  passphrase) produce no findings rather than guesses.
- Source only: binary / container / firmware analysis is not supported.
- Direct dependencies only; transitive analysis is out of scope for this release.
- Symmetric crypto and hashes get hygiene flags at most; this release is about the
  quantum-vulnerable public-key surface.
- Read/traversal errors and malformed JSON/TOML dependency manifests fail the
  scan. Build/dependency directories are pruned. Unsupported, oversized (over
  4 MiB), non-UTF-8, and binary source files are skipped; supported DER key and
  certificate files are still inspected. Child symlinks are not followed.
- Secret reports redact PEM bodies and private JWK fields. Embedded escaped
  PEM strings and arbitrary nested JSON keys remain outside detection coverage.
- TLS checks are file-level heuristics. They do not resolve includes, inheritance,
  or individual virtual hosts. A configured hybrid group is not proof of negotiation.
- CBOM records known asset types and extracted private RSA sizes, and omits
  algorithm use, runtime environments, and parameters not established by evidence.
- Some source rules match names without resolving imports or types. Aliases,
  indirect calls, and generic names can create misses or false positives.
- Recall is unmeasured — see [docs/accuracy.md](docs/accuracy.md) for what
  validation does and doesn't prove.

## License

GNU AGPLv3 — see LICENSE (in the [snoot repo](https://github.com/chasebryan/snoot)).
