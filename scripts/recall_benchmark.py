#!/usr/bin/env python3
"""Measure Snoot against a labeled recall corpus.

This harness intentionally separates scanner regression fixtures from recall
measurement. A label represents one cryptographic site that a reviewer says
exists. Snoot gets credit only when a finding with an accepted rule ID appears
at the labeled path (and line, when provided).

Unmatched labels are false negatives. Findings that match no label are emitted
as an unlabeled-findings review queue; in strict mode they also fail the run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path, help="path to the snoot executable")
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=Path("benchmarks/recall/manifest.json"),
        help="benchmark manifest (default: benchmarks/recall/manifest.json)",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=1.0,
        help="minimum labeled-site recall required, from 0.0 to 1.0 (default: 1.0)",
    )
    parser.add_argument(
        "--allow-unlabeled",
        action="store_true",
        help="do not fail when Snoot reports findings that have no benchmark label",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="optional path for a machine-readable benchmark summary",
    )
    return parser.parse_args()


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./")


def load_manifest(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("version") != 1:
        raise ValueError("recall manifest version must be 1")
    if not isinstance(doc.get("labels"), list):
        raise ValueError("recall manifest must contain a labels array")

    seen = set()
    for label in doc["labels"]:
        for key in ("id", "path", "rule_ids"):
            if key not in label:
                raise ValueError(f"label is missing {key}: {label!r}")
        if label["id"] in seen:
            raise ValueError(f"duplicate label id: {label['id']}")
        seen.add(label["id"])
        if not label["rule_ids"] or not all(isinstance(x, str) for x in label["rule_ids"]):
            raise ValueError(f"label {label['id']} must list at least one rule ID")
        if "line" in label and (not isinstance(label["line"], int) or label["line"] < 1):
            raise ValueError(f"label {label['id']} line must be a positive integer")
        if label.get("line_tolerance", 0) < 0:
            raise ValueError(f"label {label['id']} line_tolerance must be non-negative")
    return doc


def run_scan(binary: Path, corpus: Path) -> dict:
    result = subprocess.run(
        [str(binary), "scan", str(corpus), "--format", "json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Snoot scan failed with exit {result.returncode}: {detail}")
    report = json.loads(result.stdout)
    if report.get("tool") != "snoot" or not isinstance(report.get("findings"), list):
        raise ValueError("Snoot returned an unexpected JSON report")
    return report


def matches(label: dict, finding: dict) -> bool:
    location = finding.get("location", {})
    if normalize_path(location.get("path", "")) != normalize_path(label["path"]):
        return False
    if finding.get("rule_id") not in label["rule_ids"]:
        return False

    expected_line = label.get("line")
    if expected_line is None:
        return True
    actual_line = location.get("line")
    if not isinstance(actual_line, int):
        return False
    tolerance = int(label.get("line_tolerance", 0))
    return abs(actual_line - expected_line) <= tolerance


def evaluate(manifest: dict, report: dict) -> dict:
    labels = manifest["labels"]
    findings = report["findings"]
    unmatched_finding_indexes = set(range(len(findings)))
    detected = []
    missed = []

    for label in labels:
        candidates = [
            index
            for index in unmatched_finding_indexes
            if matches(label, findings[index])
        ]
        if not candidates:
            missed.append(label)
            continue

        expected_line = label.get("line")
        if expected_line is not None:
            candidates.sort(
                key=lambda index: abs(
                    findings[index].get("location", {}).get("line", expected_line)
                    - expected_line
                )
            )
        chosen = candidates[0]
        unmatched_finding_indexes.remove(chosen)
        detected.append({"label": label, "finding": findings[chosen]})

    unlabeled = [findings[index] for index in sorted(unmatched_finding_indexes)]
    total = len(labels)
    recall = len(detected) / total if total else 1.0
    return {
        "labels_total": total,
        "labels_detected": len(detected),
        "recall": recall,
        "missed_labels": missed,
        "unlabeled_findings": unlabeled,
        "scanner_stats": report.get("stats", {}),
    }


def print_summary(summary: dict) -> None:
    total = summary["labels_total"]
    detected = summary["labels_detected"]
    recall = summary["recall"]
    print(
        f"Recall benchmark: {detected}/{total} labeled crypto sites detected "
        f"({recall:.1%})"
    )
    print(f"Unlabeled findings: {len(summary['unlabeled_findings'])}")

    if summary["missed_labels"]:
        print("\nMissed labels:")
        for label in summary["missed_labels"]:
            where = label["path"]
            if "line" in label:
                where += f":{label['line']}"
            accepted = ", ".join(label["rule_ids"])
            print(f"  - {label['id']}: {where} (accepted: {accepted})")

    if summary["unlabeled_findings"]:
        print("\nUnlabeled findings:")
        for finding in summary["unlabeled_findings"]:
            location = finding.get("location", {})
            where = location.get("path", "?")
            if location.get("line") is not None:
                where += f":{location['line']}"
            print(f"  - {finding.get('rule_id', '?')}: {where}")


def main() -> int:
    args = parse_args()
    if not 0.0 <= args.fail_under <= 1.0:
        raise ValueError("--fail-under must be between 0.0 and 1.0")

    manifest_path = args.manifest.resolve()
    manifest = load_manifest(manifest_path)
    corpus = (manifest_path.parent / manifest.get("corpus", "corpus")).resolve()
    if not corpus.is_dir():
        raise ValueError(f"recall corpus directory does not exist: {corpus}")

    report = run_scan(args.binary.resolve(), corpus)
    summary = evaluate(manifest, report)
    print_summary(summary)

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(summary, indent=2) + "\n",
            encoding="utf-8",
        )

    failed = summary["recall"] < args.fail_under
    if summary["unlabeled_findings"] and not args.allow_unlabeled:
        failed = True
    if failed:
        print("\nFAIL: benchmark contract not met", file=sys.stderr)
        return 1

    print("\nPASS: benchmark contract met")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"recall-benchmark: {exc}", file=sys.stderr)
        raise SystemExit(2)
