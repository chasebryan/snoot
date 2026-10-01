"""Regenerate notices from locked Cargo sources and the pinned Rust distribution.

Metadata: cargo metadata --locked --format-version 1 > metadata.json
For a crate omitting notices from its archive, put the exact upstream-commit
notice in --overrides/NAME-VERSION.txt. Its source commit is recorded below.
"""

import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("metadata", type=Path)
parser.add_argument("rust_docs", type=Path)
parser.add_argument("--overrides", type=Path, required=True)
args = parser.parse_args()
metadata = json.loads(args.metadata.read_text())
sections = ["""Snoot — third-party notices

Snoot's own license is provided in LICENSE. This file reproduces notices from
locked Cargo dependency sources and the Rust 1.90.0 runtime distribution.
Declared dependency license alternatives are retained as supplied by upstream.
The dependency list includes target-specific packages used by the release matrix.

To update: generate locked cargo metadata, supply Rust 1.90.0's share/doc/rust,
and retrieve omitted crate notices from the exact .cargo_vcs_info.json commit.
Run scripts/collect_notices.py with those paths and --overrides. Release CI
checks that every locked registry dependency has a matching notice entry.
"""]
for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
    if package["source"] is None:
        continue
    root = Path(package["manifest_path"]).parent
    marker = f"DEPENDENCY: {package['name']} {package['version']}"
    sections.append(f"\n{'=' * 72}\n{marker}\nDeclared license: {package.get('license')}\nUpstream: {package.get('repository')}\n")
    included = []
    for file in sorted(root.rglob("*")):
        if file.is_file() and file.name.lower().startswith(
            ("license", "licence", "copyright", "copying", "notice", "authors")
        ):
            included.append(file)
    override = args.overrides / f"{package['name']}-{package['version']}.txt"
    if override.is_file():
        vcs = json.loads((root / ".cargo_vcs_info.json").read_text())
        commit = vcs["git"]["sha1"]
        sections.append(f"\nUpstream notice source: {package['repository']}/tree/{commit}\n" + override.read_text(encoding="utf-8"))
    elif not included:
        raise ValueError(f"Missing upstream notice: {marker}")
    for file in included:
        sections.append(f"\n--- {file.relative_to(root)} ---\n" + file.read_text(encoding="utf-8"))
sections.append("\n" + "=" * 72 + "\nRUST RUNTIME: 1.90.0\nSource: https://github.com/rust-lang/rust/tree/1.90.0\n")
for file in [args.rust_docs / "COPYRIGHT-library.html", *sorted((args.rust_docs / "licenses").glob("*.txt"))]:
    sections.append(f"\n--- Rust distribution {file.relative_to(args.rust_docs)} (verbatim) ---\n" + file.read_text(encoding="utf-8"))
Path("THIRD_PARTY_NOTICES.txt").write_text("\n".join(sections), encoding="utf-8", newline="\n")
