# Fixture corpus

Known-positive and known-negative samples for live detection rules.
Accuracy tests in `tests/fixture_corpus.rs` scan these trees directly.

| Path | Expected |
|------|----------|
| `positive/rust/*` | SNOOT001 / 002 / 004 |
| `positive/python/*` | SNOOT001 / 002 / 004 / 006 / 007 |
| `positive/go/*` | SNOOT001 / 002 |
| `positive/javascript/*` | SNOOT001 / 008 |
| `positive/typescript/*` | SNOOT008 |
| `positive/java/*` | SNOOT001 |
| `positive/c/*`, `positive/cpp/*` | SNOOT001 |
| `positive/secrets/*` | SNOOT003 / 009 / 010 |
| `positive/tls/*` | SNOOT005 |
| `negative/**` | no findings |
