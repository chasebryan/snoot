# Contributing to snoot

Thanks for helping sniff out classical crypto.

## Dev loop

```sh
# toolchain is pinned in rust-toolchain.toml (1.90+)
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all --check
cargo run -- scan tests/fixtures
cargo run -- scan .   # must be clean (.snootignore excludes fixtures)
```

Schema validation (development only):

```sh
python -m pip install jsonschema==4.23.0
python scripts/validate_reports.py target/debug/snoot
```

Preserve main's 22 rule IDs. Every query must compile and match a minimal
positive example in `src/engines/code.rs`; exact fixture rule sets and public CLI
contracts are also regression gates. Baselines use version 2; incompatible
fingerprint changes need a version bump and regeneration instructions.

## Adding a detection rule

1. Add a `Rule` to `src/rules.rs` with id `SNOOT0xx`, remediation, and
   per-language tree-sitter queries (or leave `queries` empty for
   secrets/manifest/tls engines).
2. Add known-positive and known-negative samples under `tests/fixtures/`.
3. Extend `src/fixture_corpus.rs` if the rule should be gated there.
4. Run `cargo test --locked` and a manual scan of the positive corpus.

Rules are data. Prefer new query strings over new control flow.

## Engines

| Engine | Owns |
|--------|------|
| `engines/code.rs` | AST API-call detection |
| `engines/secrets.rs` | PEM / DER / JWK / cert material |
| `engines/manifest.rs` | Direct dependency manifests |
| `engines/tlsconf.rs` | TLS config without PQC hybrid |

## PR expectations

- Tests green, clippy clean, `cargo fmt`
- Self-scan of the repo stays clean
- Document new FP/FN classes in `docs/accuracy.md` when you learn them

License: AGPLv3.

## Action and release changes

Run `python scripts/action/test_run.py target/debug/snoot` after `cargo test`
(use `snoot.exe` on Windows). These tests invoke the real CLI and verify adapter
outputs, gate behavior, literal inputs, protected outputs, and SARIF locations.
CI also tests the composite action and native release archive installation.

Update README and `action.yml` together when changing the action contract.
Review `docs/RELEASE_CHECKLIST.md` before publishing. Release notes live in
`docs/releases/vVERSION.md`; Cargo version and the exact tag must agree.
All dependency and release changes pass the same CI. Report vulnerabilities
privately using SECURITY.md rather than a public reproduction issue.

Dependency updates must refresh THIRD_PARTY_NOTICES.txt from upstream notices.
The collection script documents regeneration, and release packaging verifies
that the notice entries match Cargo.lock.
