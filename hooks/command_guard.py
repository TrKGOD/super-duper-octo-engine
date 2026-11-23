#!/usr/bin/env python3
"""Default-deny command guard; the only network path is the approved HTTP broker."""
import hashlib
import json
import re
import shlex
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/engagement.local.json"
DB = ".local/state.sqlite3"
KB_DB = ".local/knowledge-base.sqlite3"
KB_ALLOWED_SUBCOMMANDS = {"search", "search-patterns", "show"}


def deny(message):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": message,
    }}))
    raise SystemExit(0)


def safe_local_json(path):
    candidate = Path(path)
    return (
        not candidate.is_absolute()
        and ".." not in candidate.parts
        and candidate.parts[:1] == (".local",)
        and candidate.suffix.lower() == ".json"
    )


def safe_request_manifest(path):
    candidate = Path(path)
    return (
        not candidate.is_absolute()
        and ".." not in candidate.parts
        and candidate.parts[:2] == (".local", "requests")
        and candidate.suffix.lower() == ".json"
        and len(candidate.parts) == 3
        and re.fullmatch(r"[A-Za-z0-9._-]+\.json", candidate.name) is not None
    )


def active_http_args(argv):
    if len(argv) != 10 or argv[1] != "scripts/active_http.py":
        return None
    if argv[2] != "--db" or argv[3] != DB:
        return None
    if argv[4] != "--engagement-id" or not argv[5]:
        return None
    if argv[6] != "--task-id" or not argv[7]:
        return None
    if argv[8] != "--request-file" or not safe_request_manifest(argv[9]):
        return None
    return {"engagement_id": argv[5], "task_id": argv[7], "request_file": argv[9]}


def allowed_argv(argv):
    if len(argv) < 2 or argv[0] not in {"python", "python3"}:
        return False
    script = argv[1]
    if script == "scripts/active_http.py":
        return active_http_args(argv) is not None
    if script == "scripts/migrate.py":
        return argv == [argv[0], script, "--db", DB]
    if script == "scripts/knowledge_base.py":
        args = argv[2:]
        if len(args) < 3 or args[:2] != ["--db", KB_DB] or args[2] not in KB_ALLOWED_SUBCOMMANDS:
            return False
        if len(args) == 7 and args[:3] == ["--db", KB_DB, "search"] and args[3] == "--query" and re.fullmatch(r"[A-Za-z0-9 _.-]{1,160}", args[4]) and args[5] == "--limit" and args[6].isdigit():
            return 1 <= int(args[6]) <= 10
        if len(args) == 7 and args[:3] == ["--db", KB_DB, "search-patterns"] and args[3] == "--query" and re.fullmatch(r"[A-Za-z0-9 _.-]{1,160}", args[4]) and args[5] == "--limit" and args[6].isdigit():
            return 1 <= int(args[6]) <= 10
        if len(args) == 5 and args[:3] == ["--db", KB_DB, "show"] and args[3] == "--document-id" and re.fullmatch(r"KB-[A-F0-9]{16}", args[4]):
            return True
        return False
    if script != "scripts/workflow.py":
        return False
    args = argv[2:]
    if len(args) < 3 or args[:2] != ["--db", DB]:
        return False
    command = args[2:]
    if len(command) == 3 and command[0] == "status" and command[1] == "--engagement-id" and bool(command[2]):
        return True
    if len(command) == 3 and command[0] == "init" and command[1] == "--engagement" and command[2] == "config/engagement.local.json":
        return True
    if len(command) == 5 and command[0] == "plan" and command[1] == "--engagement-id" and bool(command[2]) and command[3] == "--file" and safe_local_json(command[4]):
        return True
    if len(command) == 3 and command[0] == "start" and command[1] == "--task-id" and bool(command[2]):
        return True
    if len(command) == 5 and command[0] == "handoff" and command[1] == "--task-id" and bool(command[2]) and command[3] == "--file" and safe_local_json(command[4]):
        return True
    if len(command) == 5 and command[0] == "finding" and command[1] == "--file" and safe_local_json(command[2]) and command[3] == "--engagement-id" and bool(command[4]):
        return True
    return False


def _active_request_is_approved(args, config):
    if not CONFIG.is_file() or config.get("engagement_id") != args["engagement_id"]:
        return False
    manifest_path = ROOT / args["request_file"]
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return False
    try:
        manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        with sqlite3.connect(ROOT / DB) as connection:
            connection.row_factory = sqlite3.Row
            engagement = connection.execute(
                "SELECT status,rules_json FROM engagements WHERE engagement_id=?",
                (args["engagement_id"],),
            ).fetchone()
            task = connection.execute(
                "SELECT agent,status,input_json FROM tasks WHERE task_id=? AND engagement_id=?",
                (args["task_id"], args["engagement_id"]),
            ).fetchone()
        if not engagement or not task:
            return False
        rules = json.loads(engagement["rules_json"])
        task_input = json.loads(task["input_json"])
        pinned = next(
            (item for item in task_input.get("request_files", []) if item.get("path") == args["request_file"]),
            None,
        )
        return bool(
            engagement["status"] == "active"
            and rules.get("execution_enabled") is True
            and rules.get("authorization_verified") is True
            and task["agent"] == "active-testing-agent"
            and task["status"] == "running"
            and task_input.get("active_testing") is True
            and pinned and pinned.get("sha256") == manifest_hash
        )
    except (OSError, sqlite3.Error, ValueError, TypeError, json.JSONDecodeError):
        return False


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        deny("Unable to parse tool input; default deny.")
    command = str(payload.get("tool_input", {}).get("command", "")).strip()
    if not command or any(char in command for char in (";", "|", "&", ">", "<", "\n", "\r", "$", chr(96))):
        deny("Only one allowlisted local workflow/KB command or the active HTTP broker is permitted.")
    try:
        argv = shlex.split(command)
    except ValueError:
        deny("Unable to parse command; default deny.")
    if not allowed_argv(argv):
        deny("Command is not in the workflow/KB allowlist or approved active HTTP broker.")
    if not CONFIG.is_file():
        deny("Local engagement config is required for agent runtime commands.")
    try:
        engagement = json.loads(CONFIG.read_text(encoding="utf-8"))
    except Exception:
        deny("Invalid local engagement config.")
    active_args = active_http_args(argv)
    if active_args:
        if not _active_request_is_approved(active_args, engagement):
            deny("Active HTTP request is not authorized by the approved engagement, running task, and pinned manifest.")
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "allow",
        }}))
        return
    if engagement.get("rules_of_engagement", {}).get("execution_enabled") is not False:
        deny("Non-broker agent commands are disabled while active execution is enabled.")
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "allow",
    }}))


if __name__ == "__main__":
    main()
