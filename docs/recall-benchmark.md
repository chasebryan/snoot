# Recall benchmark

Snoot's regression fixtures answer: **does a known rule still fire on a known
example?** The recall benchmark answers a different question: **of the
cryptographic sites a reviewer labeled as present, how many did Snoot find?**

That distinction matters. Precision-only triage can show that reported findings
are usually real while still saying nothing about cryptography the scanner
missed.

## Run it

Build Snoot, then run:

```sh
cargo build --locked
python3 scripts/recall_benchmark.py target/debug/snoot
```

The harness scans `benchmarks/recall/corpus/`, matches findings to labels in
`benchmarks/recall/manifest.json`, and reports:

- labeled crypto sites detected / total labeled sites;
- recall as a fraction and percentage;
- missed labels (false negatives);
- findings that matched no label, as a precision-review queue.

CI requires 100% recall on the committed seed corpus and no unlabeled findings.

## Label format

Each label has a stable ID, a corpus-relative path, one or more acceptable Snoot
rule IDs, and optionally an exact line (plus an optional `line_tolerance`).

```json
{
  "id": "python-pyca-rsa-keygen",
  "path": "python_rsa.py",
  "line": 4,
  "rule_ids": ["SNOOT001"]
}
```

A finding can satisfy only one label. This prevents one broad finding from
artificially earning credit for multiple labeled sites.

Any finding left unmatched is surfaced as an unlabeled finding. That is not
automatically a false positive; it means the corpus needs review. CI fails on it
by default so new scanner behavior cannot silently change the benchmark.

## What the seed corpus proves

The committed corpus is deliberately small and synthetic. It checks the
**measurement machinery** across code, manifests, TLS configuration, and a clean
negative file. It does **not** establish Snoot's production recall, completeness,
or quantum-safety coverage.

A defensible recall claim requires a separately labeled corpus whose ground
truth was created independently of Snoot's current rules. The next useful corpus
should include production-like examples across every supported language and
engine, including aliases, indirect calls, negative lookalikes, and currently
documented blind spots.

## Growing the benchmark

For each new reviewed sample:

1. add the source/config/manifest under `benchmarks/recall/corpus/`;
2. label every cryptographic site independently of Snoot output;
3. add one manifest label per site;
4. run the benchmark and investigate both missed labels and unlabeled findings;
5. only change a label after reviewer agreement that the ground truth was wrong.

Do not weaken `--fail-under` to make a scanner change pass. A missed label is
evidence to investigate, not a test nuisance.
