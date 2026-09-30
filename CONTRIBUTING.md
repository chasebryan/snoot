# Contributing to snoot

Thanks for helping sniff out classical crypto.

## Dev loop

```sh
# toolchain is pinned in rust-toolchain.toml (1.90+)
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo run -- scan tests/fixtures/positive
cargo run -- scan .   # must be clean (.snootignore excludes fixtures)
```

## Adding a detection rule

1. Add a `Rule` to `src/rules.rs` with id `SNOOT0xx`, remediation, and
   per-language tree-sitter queries (or leave `queries` empty for
   secrets/manifest/tls engines).
2. Add known-positive and known-negative samples under `tests/fixtures/`.
3. Extend `tests/fixture_corpus.rs` if the rule should be gated there.
4. Run `cargo test` and a manual scan of the positive corpus.

Rules are data. Prefer new query strings over new control flow.

## Engines

| Engine | Owns |
|--------|------|
| `engines/code.rs` | AST API-call detection |
| `engines/secrets.rs` | PEM / JWK / cert material |
| `engines/manifest.rs` | Direct dependency manifests |
| `engines/tlsconf.rs` | TLS config without PQC hybrid |

## PR expectations

- Tests green, clippy clean, `cargo fmt`
- Self-scan of the repo stays clean
- Document new FP/FN classes in `docs/accuracy.md` when you learn them

License: AGPLv3.
