#!/usr/bin/env python3
"""Default-deny tripwire for Claude Code Bash tool calls.

This is NOT a sandbox. Shell parsing is inherently difficult to secure. Use an
isolated VM/container and network egress policy for active testing.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "engagement.local.json"

def deny(message: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": message}}))
    raise SystemExit(0)

def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        deny("Unable to parse tool input; default deny.")

    command = str(payload.get("tool_input", {}).get("command", "")).strip()
    if not command:
        deny("Empty or unavailable command; default deny.")

    if not CONFIG.exists():
        deny("No local engagement config. Bash execution is disabled by default.")

    try:
        engagement = json.loads(CONFIG.read_text(encoding="utf-8"))
    except Exception:
        deny("Invalid local engagement config; default deny.")

    rules = engagement.get("rules_of_engagement", {})
    if rules.get("execution_enabled") is not True:
        deny("Active execution is disabled in the engagement configuration.")

    # Bootstrap deliberately does not authorize arbitrary shell execution.
    # This guard remains deny-by-default until a reviewed execution broker is added.
    deny("No reviewed command broker is configured. Use passive analysis or an isolated lab workflow.")

if __name__ == "__main__":
    main()
