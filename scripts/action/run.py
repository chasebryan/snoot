"""Action contract: literal inputs, workspace paths, complete reports before gating."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import quote, unquote


def emit_output(name, value):
    # Validated paths contain no newlines, so one command-file line is sufficient.
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"{name}={value}\n")


def inputs():
    if sys.version_info < (3, 9):
        raise ValueError("Python 3.9 or newer is required")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    severity = os.environ.get("SNOOT_FAIL_ON", "high")
    if severity not in ("", "info", "low", "medium", "high", "critical"):
        raise ValueError("fail-on must be empty, info, low, medium, high, or critical")
    if os.environ.get("SNOOT_UPLOAD", "true") not in ("true", "false"):
        raise ValueError("upload-sarif must be 'true' or 'false'")
    category = os.environ.get("SNOOT_CATEGORY", "snoot")
    if not category or "\n" in category or "\r" in category:
        raise ValueError("category must be nonempty and contain no newlines")
    paths = {}
    for key, variable, default in (
        ("root", "SNOOT_SCAN_PATH", "."),
        ("sarif", "SNOOT_SARIF", "snoot.sarif"),
        ("baseline", "SNOOT_BASELINE", ""),
    ):
        value = os.environ.get(variable, default)
        if "\n" in value or "\r" in value or (not value and key != "baseline"):
            raise ValueError(f"{key} must be nonempty and contain no newlines")
        if not value:
            paths[key] = None
            continue
        candidate = workspace / value
        resolved = candidate.resolve()
        if not resolved.is_relative_to(workspace):
            raise ValueError(f"{key} must be inside GITHUB_WORKSPACE")
        # Keep the lexical path so the scanner can reject symlink report outputs.
        paths[key] = candidate
    if not paths["root"].exists():
        raise ValueError("scan path does not exist")
    if paths["baseline"] is not None and not paths["baseline"].is_file():
        raise ValueError("baseline file does not exist")
    return workspace, paths, severity


def prepare_report(workspace, paths):
    report_path = paths["sarif"]
    document = json.loads(report_path.read_text(encoding="utf-8"))
    if document["version"] != "2.1.0" or len(document["runs"]) != 1:
        raise ValueError("scanner did not produce one SARIF 2.1.0 run")
    run = document["runs"][0]
    if run["tool"]["driver"]["name"] != "snoot":
        raise ValueError("unexpected SARIF tool")
    root = paths["root"].resolve()
    scan_base = root if root.is_dir() else root.parent
    prefix = scan_base.relative_to(workspace).as_posix()
    for result in run["results"]:
        for location in result.get("locations", []):
            artifact = location["physicalLocation"]["artifactLocation"]
            relative = unquote(artifact["uri"])
            source = (scan_base / relative).resolve()
            if not source.is_relative_to(workspace):
                raise ValueError("SARIF location is outside the repository workspace")
            repository_path = relative if prefix == "." else f"{prefix}/{relative}"
            artifact["uri"] = quote(repository_path, safe="-._~/")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=report_path.parent, delete=False
        ) as output:
            temporary = Path(output.name)
            json.dump(document, output, indent=2)
            output.write("\n")
        os.replace(temporary, report_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return len(run["results"])


def main():
    try:
        workspace, paths, severity = inputs()
        if sys.argv[1:] == ["--validate"]:
            return 0
        command = [os.environ["SNOOT_BINARY"], "scan", "--format=sarif", f"--output={paths['sarif']}"]
        if severity:
            command.append(f"--fail-on={severity}")
        if paths["baseline"] is not None:
            command.append(f"--baseline={paths['baseline']}")
        exclude = os.environ.get("SNOOT_EXCLUDE", "")
        if exclude:
            command.append(f"--exclude={exclude}")
        command.extend(["--", str(paths["root"])])
        status = subprocess.run(command, cwd=workspace, check=False).returncode
        if status not in (0, 2):
            raise ValueError(f"scanner failed with exit code {status}")
        count = prepare_report(workspace, paths)
        emit_output("sarif", paths["sarif"].absolute())
        emit_output("finding-count", count)
        emit_output("exit-code", status)
        # The final composite step enforces the gate after report upload.
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"snoot action: {error}", file=sys.stderr)
        if "GITHUB_OUTPUT" in os.environ and sys.argv[1:] != ["--validate"]:
            emit_output("exit-code", 3)
        return 3


if __name__ == "__main__":
    sys.exit(main())
