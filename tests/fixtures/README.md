# Fixture corpus

Known-positive and known-negative samples for each live detection rule.
Accuracy tests in `tests/fixture_corpus.rs` rewrite these shapes into a temp
tree and assert the CLI reports the expected rule IDs.

| Path | Expected |
|------|----------|
| `positive/rust/rsa_gen.rs` | SNOOT001 |
| `positive/rust/ecdsa.rs` | SNOOT002 |
| `positive/rust/dh.rs` | SNOOT004 |
| `positive/python/*.py` | SNOOT001 / SNOOT002 / SNOOT004 |
| `positive/secrets/dev.key` | SNOOT003 |
| `negative/**` | no findings |
