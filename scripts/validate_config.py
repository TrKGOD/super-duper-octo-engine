#!/usr/bin/env python3
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
errors = []

def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path.relative_to(ROOT)}: {exc}")
        return None

engagement = load_json(ROOT / "config" / "engagement.example.json")
models = load_json(ROOT / "config" / "models.json")
tools = load_json(ROOT / "config" / "tools.json")

if engagement:
    rules = engagement.get("rules_of_engagement", {})
    if rules.get("execution_enabled") is not False:
        errors.append("Example engagement must keep execution_enabled=false.")
    scope = engagement.get("scope", {})
    if any(scope.get(k) for k in ("allowed_domains","allowed_ips","allowed_cidrs","allowed_applications")):
        errors.append("Example engagement must not contain real targets.")

if models and models.get("default") != "inherit":
    errors.append("Bootstrap model default must be inherit.")
if tools and tools.get("bash_enabled_for_agents") is not False:
    errors.append("Bash must be disabled for agents in bootstrap.")

schema = ROOT / "database" / "schema.sql"
if not schema.exists():
    errors.append("Missing database/schema.sql")

if errors:
    print("Configuration validation FAILED:")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print("Configuration validation passed. Execution remains disabled by default.")
