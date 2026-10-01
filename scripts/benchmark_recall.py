#!/usr/bin/env python3
"""Measure Snoot detection precision/recall over an explicitly labeled corpus.

Benchmark units are (relative file path, rule id) pairs. This intentionally
measures detection coverage, not exploitability or production prevalence.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"recall benchmark: {message}")


def load_labels(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")

    if document.get("schema_version") != 1:
        fail("labels schema_version must be 1")
    if not isinstance(document.get("root"), str) or not document["root"]:
        fail("labels root must be a non-empty string")
    if not isinstance(document.get("cases"), list) or not document["cases"]:
        fail("labels cases must be a non-empty array")

    seen_paths: set[str] = set()
    for index, case in enumerate(document["cases"]):
        if not isinstance(case, dict):
            fail(f"case {index} must be an object")
        relative = case.get("path")
        rules = case.get("expected_rules")
        if not isinstance(relative, str) or not relative:
            fail(f"case {index} path must be a non-empty string")
        if relative in seen_paths:
            fail(f"duplicate case path: {relative}")
        seen_paths.add(relative)
        if (
            not isinstance(rules, list)
            or any(not isinstance(rule, str) or not rule for rule in rules)
            or len(rules) != len(set(rules))
        ):
            fail(f"case {relative} expected_rules must contain unique rule ids")

    minimums = document.get("minimums", {})
    for name in ("precision", "recall"):
        value = minimums.get(name, 1.0)
        if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
            fail(f"minimums.{name} must be between 0 and 1")
    return document


def run_scan(binary: Path, path: Path) -> dict[str, Any]:
    command = [
        str(binary),
        "scan",
        str(path),
        "--format",
        "json",
        "--no-color",
        "--quiet",
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no scanner output"
        fail(f"scanner failed for {path} with exit {result.returncode}: {detail}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"scanner returned invalid JSON for {path}: {error}")


def metric(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else numerator / denominator


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure Snoot precision/recall on a labeled benchmark corpus."
    )
    parser.add_argument(
        "binary",
        nargs="?",
        default="target/debug/snoot",
        type=Path,
        help="Snoot executable to benchmark (default: target/debug/snoot)",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=Path("benchmarks/recall/labels.json"),
        help="benchmark labels document",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="optional path for the complete machine-readable benchmark result",
    )
    args = parser.parse_args()

    labels = load_labels(args.labels)
    corpus_root = Path(labels["root"])
    if not corpus_root.is_dir():
        fail(f"corpus root does not exist: {corpus_root}")
    if not args.binary.is_file():
        fail(f"Snoot binary does not exist: {args.binary}")

    expected: set[tuple[str, str]] = set()
    observed: set[tuple[str, str]] = set()
    raw_findings = 0

    for case in labels["cases"]:
        relative = case["path"].replace("\\", "/")
        source = corpus_root / relative
        if not source.is_file():
            fail(f"labeled case does not exist: {source}")

        for rule in case["expected_rules"]:
            expected.add((relative, rule))

        report = run_scan(args.binary, source)
        findings = report.get("findings")
        if not isinstance(findings, list):
            fail(f"scanner JSON for {source} has no findings array")
        raw_findings += len(findings)

        # A single-file scan reports the input file by basename because paths
        # are relative to the file's parent. Reattach the benchmark case path.
        for finding in findings:
            rule = finding.get("rule_id")
            if not isinstance(rule, str) or not rule:
                fail(f"scanner finding for {source} has no rule_id")
            observed.add((relative, rule))

    true_positive = expected & observed
    false_negative = expected - observed
    false_positive = observed - expected
    precision = metric(len(true_positive), len(true_positive) + len(false_positive))
    recall = metric(len(true_positive), len(expected))

    per_rule: dict[str, dict[str, Any]] = {}
    by_rule_expected: dict[str, set[str]] = defaultdict(set)
    by_rule_observed: dict[str, set[str]] = defaultdict(set)
    for path, rule in expected:
        by_rule_expected[rule].add(path)
    for path, rule in observed:
        by_rule_observed[rule].add(path)
    for rule in sorted(set(by_rule_expected) | set(by_rule_observed)):
        rule_tp = by_rule_expected[rule] & by_rule_observed[rule]
        rule_fn = by_rule_expected[rule] - by_rule_observed[rule]
        rule_fp = by_rule_observed[rule] - by_rule_expected[rule]
        per_rule[rule] = {
            "expected": len(by_rule_expected[rule]),
            "observed": len(by_rule_observed[rule]),
            "true_positive": len(rule_tp),
            "false_positive": len(rule_fp),
            "false_negative": len(rule_fn),
            "precision": metric(len(rule_tp), len(rule_tp) + len(rule_fp)),
            "recall": metric(len(rule_tp), len(by_rule_expected[rule])),
        }

    result = {
        "schema_version": 1,
        "benchmark": labels.get("name", "snoot-recall"),
        "unit": "file-rule pair",
        "cases": len(labels["cases"]),
        "expected_pairs": len(expected),
        "observed_pairs": len(observed),
        "raw_findings": raw_findings,
        "true_positive": len(true_positive),
        "false_positive": len(false_positive),
        "false_negative": len(false_negative),
        "precision": precision,
        "recall": recall,
        "false_positives": [
            {"path": path, "rule_id": rule} for path, rule in sorted(false_positive)
        ],
        "false_negatives": [
            {"path": path, "rule_id": rule} for path, rule in sorted(false_negative)
        ],
        "per_rule": per_rule,
    }

    print(
        f"Recall benchmark: {len(labels['cases'])} cases, "
        f"{len(expected)} labeled file-rule pairs"
    )
    print(
        f"TP={len(true_positive)} FP={len(false_positive)} FN={len(false_negative)} "
        f"precision={precision:.3f} recall={recall:.3f}"
    )
    for rule, metrics in per_rule.items():
        print(
            f"{rule}: TP={metrics['true_positive']} FP={metrics['false_positive']} "
            f"FN={metrics['false_negative']} recall={metrics['recall']:.3f}"
        )

    if false_negative:
        print("False negatives:", file=sys.stderr)
        for path, rule in sorted(false_negative):
            print(f"  {rule}  {path}", file=sys.stderr)
    if false_positive:
        print("False positives:", file=sys.stderr)
        for path, rule in sorted(false_positive):
            print(f"  {rule}  {path}", file=sys.stderr)

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    minimums = labels.get("minimums", {})
    minimum_precision = float(minimums.get("precision", 1.0))
    minimum_recall = float(minimums.get("recall", 1.0))
    if precision < minimum_precision or recall < minimum_recall:
        print(
            "Benchmark regression: "
            f"precision {precision:.3f} < {minimum_precision:.3f} or "
            f"recall {recall:.3f} < {minimum_recall:.3f}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
