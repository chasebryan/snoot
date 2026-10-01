# Snoot recall benchmark

This benchmark measures whether Snoot detects the labeled cryptographic evidence
in its regression corpus.

## What is measured

The benchmark unit is a **(file, rule ID) pair**.

For each labeled file, the harness runs the real Snoot CLI and compares the
observed rule IDs with the expected rule IDs in `labels.json`.

It reports:

- true positives (expected file-rule pairs that Snoot detected)
- false negatives (expected pairs Snoot missed)
- false positives (unexpected pairs Snoot emitted)
- overall precision and recall
- per-rule precision and recall

CI currently requires precision and recall of 1.0 for this synthetic corpus.

## Run it

Build Snoot first:

```sh
cargo build --locked
python3 scripts/benchmark_recall.py target/debug/snoot
```

On Windows, pass `target/debug/snoot.exe`.

Write a machine-readable result with:

```sh
python3 scripts/benchmark_recall.py target/debug/snoot \
  --json-output target/recall-benchmark.json
```

## Interpretation

This is a **regression benchmark**, not a production accuracy claim.

The current corpus consists of synthetic or generated fixtures chosen to exercise
known detection rules. A score of 1.0 means the implementation still finds the
labeled cases and does not introduce unexpected rule matches in those cases.

It does **not** establish recall on arbitrary production repositories. Production
recall requires an independently labeled corpus containing both detected and
missed cryptographic usages across supported languages, libraries, coding styles,
configuration patterns, and key formats.

That distinction is deliberate: fixture recall protects the detector from
regression; a future production benchmark estimates real-world coverage.

## Adding cases

1. Add the smallest useful fixture under `tests/fixtures/`.
2. Add its exact expected rule IDs to `src/fixture_corpus.rs`.
3. Add the same file and rule IDs to `benchmarks/recall/labels.json`.
4. Run `cargo test --locked` and the recall benchmark.
5. If the case represents a known miss, land the label and detector fix together
   so the benchmark records the new coverage contract.

Do not lower the benchmark thresholds merely to make a detector regression pass.
If an expected label is wrong, fix the label and explain the change in review.
