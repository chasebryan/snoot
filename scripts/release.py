"""Package, verify, and execute each native release archive before publication."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

TARGETS = {
    "x86_64-unknown-linux-gnu": "tar.gz",
    "aarch64-unknown-linux-gnu": "tar.gz",
    "x86_64-apple-darwin": "tar.gz",
    "aarch64-apple-darwin": "tar.gz",
    "x86_64-pc-windows-msvc": "zip",
}


def version():
    return re.search(r'^version = "([^"]+)"', Path("Cargo.toml").read_text(), re.M)[1]


def asset_name(target):
    return f"snoot-v{version()}-{target}.{TARGETS[target]}"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package(target, binary):
    directory = Path("dist")
    directory.mkdir(exist_ok=True)
    stem = f"snoot-v{version()}-{target}"
    stage = directory / stem
    stage.mkdir(exist_ok=True)
    executable = "snoot.exe" if target.endswith("msvc") else "snoot"
    shutil.copy2(binary, stage / executable)
    for file in ("README.md", "LICENSE"):
        shutil.copy2(file, stage / file)
    archive = directory / asset_name(target)
    if TARGETS[target] == "zip":
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            for file in sorted(stage.iterdir()):
                output.write(file, f"{stem}/{file.name}")
    else:
        with tarfile.open(archive, "w:gz") as output:
            output.add(stage, arcname=stem)
    archive.with_name(archive.name + ".sha256").write_text(
        f"{digest(archive)}  {archive.name}\n", encoding="utf-8", newline="\n"
    )
    print(archive)


def verify(directory, target=None):
    targets = [target] if target else TARGETS
    lines = []
    for item in targets:
        archive = directory / asset_name(item)
        actual = f"{digest(archive)}  {archive.name}\n"
        expected = archive.with_name(archive.name + ".sha256").read_bytes()
        if expected != actual.encode("utf-8"):
            raise ValueError(f"checksum mismatch: {archive}")
        lines.append(actual)
    if target is None:
        directory.joinpath("SHA256SUMS").write_text("".join(sorted(lines)), encoding="utf-8")
    print(f"Verified {len(lines)} archive checksum(s)")


def smoke(directory, target):
    verify(directory, target)
    archive = directory / asset_name(target)
    stem = f"snoot-v{version()}-{target}"
    executable = "snoot.exe" if target.endswith("msvc") else "snoot"
    expected = {f"{stem}/{name}" for name in (executable, "README.md", "LICENSE")}
    with tempfile.TemporaryDirectory(prefix="snoot-release-") as temporary:
        destination = Path(temporary)
        if TARGETS[target] == "zip":
            with zipfile.ZipFile(archive) as source:
                if set(source.namelist()) != expected:
                    raise ValueError("unexpected ZIP contents")
                source.extractall(destination)
        else:
            with tarfile.open(archive) as source:
                if {entry.name for entry in source if entry.isfile()} != expected:
                    raise ValueError("unexpected tar contents")
                if any(not (entry.isfile() or entry.isdir()) or
                       entry.name not in expected | {stem} for entry in source):
                    raise ValueError("unexpected tar entry")
                source.extractall(destination, filter="data")
        binary = destination / stem / executable

        def run(*args, status=0):
            result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True)
            if result.returncode != status:
                raise ValueError(f"archive CLI failed: {args}: {result.stderr}")
            return result.stdout

        if run("--version").strip() != f"snoot {version()}":
            raise ValueError("binary version differs from the release")
        run("rules")
        fixture = destination / "app"
        fixture.mkdir()
        (fixture / "main.py").write_text("rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
        report = json.loads(run("scan", fixture, "--format=json", "--fail-on=high", status=2))
        if {finding["rule_id"] for finding in report["findings"]} != {"SNOOT001"}:
            raise ValueError("positive detection smoke test failed")
        baseline = destination / "baseline.json"
        run("init", fixture, "--output", baseline)
        report = json.loads(run("scan", fixture, "--format=json", "--fail-on=high", "--baseline", baseline))
        if report["findings"] or report["stats"]["findings_suppressed"] != 1:
            raise ValueError("baseline smoke test failed")
        run("scan", destination / "missing", status=3)
        print(f"Installed archive smoke test passed: {target}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("package", "verify", "smoke", "check-version"))
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--tag")
    args = parser.parse_args()
    if args.command == "package":
        package(args.target, args.binary)
    elif args.command == "verify":
        verify(args.directory, args.target)
    elif args.command == "smoke":
        smoke(args.directory, args.target)
    elif args.tag != f"v{version()}" or not re.fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        raise ValueError("release tag must match the Cargo package version exactly")
    elif not Path(f"docs/releases/{args.tag}.md").is_file():
        raise ValueError("reviewed release notes are missing")


if __name__ == "__main__":
    main()
