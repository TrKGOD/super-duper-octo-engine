#!/usr/bin/env python3
"""Validate JSON schemas and checked-in examples."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[1]
checks=[
("templates/finding.schema.json",[]),
("templates/handoff.schema.json",["templates/examples/handoff.completed.example.json"]),
("templates/plan.schema.json",["templates/examples/plan.passive.example.json"]),
("templates/evidence-manifest.schema.json",["templates/examples/evidence-manifest.example.json"]),
("templates/knowledge-document.schema.json",[]),
("templates/knowledge-pattern.schema.json",["templates/examples/knowledge-pattern.example.json"]),
("templates/prediction.schema.json",["benchmarks/predictions.example.json"])
]
for schema_name,examples in checks:
 schema=json.loads((ROOT/schema_name).read_text(encoding="utf-8")); Draft202012Validator.check_schema(schema)
 validator=Draft202012Validator(schema,format_checker=FormatChecker())
 for example in examples: validator.validate(json.loads((ROOT/example).read_text(encoding="utf-8")))
print("JSON schemas and checked-in examples are valid.")
