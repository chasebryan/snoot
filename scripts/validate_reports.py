#!/usr/bin/env python3
"""Validate generated reports against pinned upstream schemas (development only).

Requires jsonschema==4.23.0. Schema downloads happen here, never in snoot.
Run from the repository root: python scripts/validate_reports.py target/debug/snoot
"""

import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from referencing import Registry, Resource

CDX = "https://raw.githubusercontent.com/CycloneDX/specification/55343ba19dee1785acf1ce9191540d5fd7b590db/schema/"
SARIF = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/a560296ca8c921f3bdb8d4a8db57ab83dae968a7/sarif-2.1/schema/sarif-schema-2.1.0.json"


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/snoot").resolve())
    schemas = {name: fetch(CDX + name) for name in
               ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")}
    registry = Registry()
    for name, schema in schemas.items():
        resource = Resource.from_contents(schema)
        for uri in (CDX + name, "http://cyclonedx.org/schema/" + name,
                    "https://cyclonedx.org/schema/" + name, schema.get("$id", "")):
            if uri:
                registry = registry.with_resource(uri, resource)
    sarif_schema = fetch(SARIF)
    validators = {
        "sarif": validator_for(sarif_schema)(sarif_schema, format_checker=FormatChecker()),
        "cbom": validator_for(schemas["bom-1.6.schema.json"])(
            schemas["bom-1.6.schema.json"], registry=registry, format_checker=FormatChecker()),
    }
    with tempfile.TemporaryDirectory() as empty:
        for corpus in ("tests/fixtures", empty):
            for format_name, validator in validators.items():
                output = subprocess.check_output([binary, "scan", corpus, "--format", format_name], text=True)
                document = json.loads(output)
                validator.validate(document)
                print(f"{format_name}: {'positive fixtures' if corpus == 'tests/fixtures' else 'empty scan'} matches the official schema")


if __name__ == "__main__":
    main()
