#!/usr/bin/env bash
# Validate bundled JSON schemas parse and optional draft validation when available.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - <<PY
import json, pathlib, sys
root = pathlib.Path("${ROOT}")
schemas = sorted((root / "schemas").glob("*.schema.json"))
if not schemas:
    print("no schemas found", file=sys.stderr)
    sys.exit(1)
for path in schemas:
    json.loads(path.read_text(encoding="utf-8"))
    print(f"ok parse {path.relative_to(root)}")

# Best-effort Draft validation if jsonschema is installed.
try:
    import jsonschema
    from jsonschema import Draft202012Validator
except Exception as exc:  # noqa: BLE001
    print(f"skip draft validation: jsonschema unavailable ({exc})")
    sys.exit(0)

for path in schemas:
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    print(f"ok draft {path.relative_to(root)}")
PY
