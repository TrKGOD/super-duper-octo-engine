#!/usr/bin/env python3
"""Narrow command broker for local workflow bookkeeping; never a sandbox."""
import json
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "engagement.local.json"
DB = ".local/state.sqlite3"

def deny(message):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": message}}))
    raise SystemExit(0)

def safe_local_json(path):
    p = Path(path)
    return not p.is_absolute() and ".." not in p.parts and p.parts[:1] == (".local",) and p.suffix == ".json"

def allowed_argv(argv):
    if len(argv) < 2 or argv[0] not in {"python", "python3"}:
        return False
    script = argv[1]
    if script == "scripts/migrate.py":
        return argv == [argv[0], script, "--db", DB]
    if script != "scripts/workflow.py":
        return False
    args = argv[2:]
    if len(args) < 3 or args[:2] != ["--db", DB]:
        return False
    cmd = args[2:]
    if len(cmd) == 3 and cmd[0] == "status" and cmd[1] == "--engagement-id" and bool(cmd[2]):
        return True
    if len(cmd) == 3 and cmd[0] == "init" and cmd[1] == "--engagement" and cmd[2] == "config/engagement.local.json":
        return True
    if len(cmd) == 5 and cmd[0] == "plan" and cmd[1] == "--engagement-id" and bool(cmd[2]) and cmd[3] == "--file" and safe_local_json(cmd[4]):
        return True
    if len(cmd) == 3 and cmd[0] == "start" and cmd[1] == "--task-id" and bool(cmd[2]):
        return True
    if len(cmd) == 5 and cmd[0] == "handoff" and cmd[1] == "--task-id" and bool(cmd[2]) and cmd[3] == "--file" and safe_local_json(cmd[4]):
        return True
    if len(cmd) == 5 and cmd[0] == "finding" and cmd[1] == "--file" and safe_local_json(cmd[2]) and cmd[3] == "--engagement-id" and bool(cmd[4]):
        return True
    return False

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        deny("Unable to parse tool input; default deny.")
    command = str(payload.get("tool_input", {}).get("command", "")).strip()
    if not command or any(x in command for x in (";", "|", "&", ">", "<", "\n", "\r", "$", "`")):
        deny("Only one allowlisted local workflow command is permitted.")
    try:
        argv = shlex.split(command)
    except ValueError:
        deny("Unable to parse command; default deny.")
    if not allowed_argv(argv):
        deny("Command is not in the local workflow allowlist.")
    if not CONFIG.exists():
        deny("No local engagement config; workflow commands are disabled.")
    try:
        engagement = json.loads(CONFIG.read_text(encoding="utf-8"))
    except Exception:
        deny("Invalid local engagement config.")
    if engagement.get("rules_of_engagement", {}).get("execution_enabled") is not False:
        deny("Workflow bookkeeping is allowed only while execution_enabled=false.")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}))

if __name__ == "__main__":
    main()
