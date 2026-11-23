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


def engagement_paths(db_arg):
    """Resolve only the default engagement paths or a strict per-engagement pair."""
    if db_arg == DB:
        return CONFIG, ROOT / DB
    match = re.fullmatch(r"\.local/engagements/([A-Za-z0-9][A-Za-z0-9._-]{0,63})/state\.sqlite3", db_arg)
    if not match:
        return None
    slug = match.group(1)
    return ROOT / "config" / ("engagement." + slug + ".local.json"), ROOT / db_arg


def safe_db_argument(value):
    paths = engagement_paths(value)
    if paths is None:
        return False
    config_path, db_path = paths
    local = ROOT / ".local"
    engagements = local / "engagements"
    engagement_dir = db_path.parent
    config_dir = ROOT / "config"
    if local.is_symlink() or config_dir.is_symlink() or (value != DB and (engagements.is_symlink() or engagement_dir.is_symlink())):
        return False
    if config_path.is_symlink() or db_path.is_symlink():
        return False
    return True


def active_http_args(argv):
    if len(argv) != 10 or argv[1] != "scripts/active_http.py":
        return None
    if argv[2] != "--db" or not safe_db_argument(argv[3]):
        return None
    if argv[4] != "--engagement-id" or not argv[5]:
        return None
    if argv[6] != "--task-id" or not argv[7]:
        return None
    if argv[8] != "--request-file" or not safe_request_manifest(argv[9]):
        return None
    return {"db": argv[3], "engagement_id": argv[5], "task_id": argv[7], "request_file": argv[9]}


def active_surface_args(argv):
    if len(argv) != 14 or argv[1] != "scripts/active_surface.py":
        return None
    if argv[2] != "--db" or not safe_db_argument(argv[3]):
        return None
    if argv[4] != "--engagement-id" or not argv[5]:
        return None
    if argv[6] != "--task-id" or not argv[7]:
        return None
    if argv[8] != "--target-url" or not argv[9].startswith(("http://", "https://")):
        return None
    if argv[10] != "--max-pages" or not argv[11].isdigit() or not 1 <= int(argv[11]) <= 25:
        return None
    if argv[12] != "--max-depth" or not argv[13].isdigit() or not 0 <= int(argv[13]) <= 3:
        return None
    return {"db": argv[3], "engagement_id": argv[5], "task_id": argv[7], "target_url": argv[9]}


def orchestrator_args(argv):
    if len(argv) != 8 or argv[1] != "scripts/run_orchestrator.py":
        return None
    if argv[2] != "--db" or not safe_db_argument(argv[3]):
        return None
    if argv[4] != "--engagement-id" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,79}", argv[5]):
        return None
    if argv[6] != "--model" or not re.fullmatch(r"[A-Za-z0-9._:-]{2,120}", argv[7]):
        return None
    return {"db": argv[3], "engagement_id": argv[5]}


def passive_framing_args(argv):
    if argv[0] not in {"python", "python3"}:
        return None
    if len(argv) == 4 and argv[1] in {"scripts/analyze_http_framing.py", "scripts/analyze_race_capture.py"}:
        if argv[2] != "--input" or not safe_local_json(argv[3]):
            return None
        return {"input": argv[3]}
    if len(argv) == 5 and argv[1] == "scripts/analyze_protocol_artifacts.py":
        if argv[2] not in {"oidc-discovery", "oauth-flow", "jwt", "sqli-pair"}:
            return None
        if argv[3] != "--input" or not safe_local_json(argv[4]):
            return None
        return {"input": argv[4], "kind": argv[2]}
    return None


def active_security_args(argv):
    """Strict argument parser for specialist read-only broker workflows."""
    if len(argv) < 2 or argv[0] not in {"python", "python3"}:
        return None
    script = argv[1]
    if script == "scripts/active_ssrf_probe.py":
        if len(argv) not in {14, 16}:
            return None
        if argv[2] != "--db" or not safe_db_argument(argv[3]):
            return None
        if argv[4] != "--engagement-id" or not argv[5] or argv[6] != "--task-id" or not argv[7]:
            return None
        if argv[8] != "--request-file" or not safe_request_manifest(argv[9]):
            return None
        if argv[10] != "--callback-url" or not argv[11].startswith("https://"):
            return None
        if argv[12] != "--marker" or not re.fullmatch(r"[A-Za-z0-9._-]{8,96}", argv[13]):
            return None
        if len(argv) == 16 and (argv[14] != "--callback-events" or not safe_local_json(argv[15])):
            return None
        return {"db": argv[3], "engagement_id": argv[5], "task_id": argv[7],
                "request_files": [argv[9]]}
    if script == "scripts/active_authentication_check.py":
        if len(argv) != 14:
            return None
        if argv[2] != "--db" or not safe_db_argument(argv[3]):
            return None
        if argv[4] != "--engagement-id" or not argv[5] or argv[6] != "--task-id" or not argv[7]:
            return None
        if argv[8] != "--authenticated-request-file" or not safe_request_manifest(argv[9]):
            return None
        if argv[10] != "--anonymous-request-file" or not safe_request_manifest(argv[11]):
            return None
        if argv[12] != "--protected-resource" or not argv[13]:
            return None
        return {"db": argv[3], "engagement_id": argv[5], "task_id": argv[7],
                "request_files": [argv[9], argv[11]]}
    if script == "scripts/active_cache_check.py":
        if len(argv) != 16:
            return None
        if argv[2] != "--db" or not safe_db_argument(argv[3]):
            return None
        if argv[4] != "--engagement-id" or not argv[5] or argv[6] != "--task-id" or not argv[7]:
            return None
        if argv[8] != "--first-request-file" or not safe_request_manifest(argv[9]):
            return None
        if argv[10] != "--second-request-file" or not safe_request_manifest(argv[11]):
            return None
        if argv[12] != "--first-private-marker" or not re.fullmatch(r"[A-Za-z0-9._-]{4,128}", argv[13]):
            return None
        if argv[14] != "--second-private-marker" or not re.fullmatch(r"[A-Za-z0-9._-]{4,128}", argv[15]):
            return None
        return {"db": argv[3], "engagement_id": argv[5], "task_id": argv[7],
                "request_files": [argv[9], argv[11]]}
    return None


def allowed_argv(argv):
    if len(argv) < 2 or argv[0] not in {"python", "python3"}:
        return False
    script = argv[1]
    if script in {"scripts/analyze_http_framing.py", "scripts/analyze_race_capture.py", "scripts/analyze_protocol_artifacts.py"}:
        return passive_framing_args(argv) is not None
    if script in {"scripts/active_ssrf_probe.py", "scripts/active_authentication_check.py", "scripts/active_cache_check.py"}:
        return active_security_args(argv) is not None
    if script == "scripts/run_orchestrator.py":
        return orchestrator_args(argv) is not None
    if script == "scripts/active_surface.py":
        return active_surface_args(argv) is not None
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
    config_path, db_path = engagement_paths(args["db"])
    if not config_path.is_file() or config_path.is_symlink() or config.get("engagement_id") != args["engagement_id"]:
        return False
    manifest_path = ROOT / args["request_file"]
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return False
    try:
        manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        with sqlite3.connect(db_path) as connection:
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
            (item for item in task_input.get("request_files", []) + task_input.get("generated_request_files", [])
             if item.get("path") == args["request_file"]),
            None,
        )
        return bool(
            engagement["status"] == "active"
            and rules.get("execution_mode", "active") == "active"
            and rules.get("execution_enabled") is True
            and rules.get("authorization_verified") is True
            and task["agent"] in {"active-testing-agent", "exploitation-agent", "validation-agent", "recon-agent", "enumeration-agent", "vulnerability-agent"}
            and task["status"] == "running"
            and task_input.get("active_testing") is True
            and pinned and pinned.get("sha256") == manifest_hash
        )
    except (OSError, sqlite3.Error, ValueError, TypeError, json.JSONDecodeError):
        return False


def _active_surface_is_approved(args, config):
    config_path, db_path = engagement_paths(args["db"])
    if not config_path.is_file() or config_path.is_symlink() or config.get("engagement_id") != args["engagement_id"]:
        return False
    try:
        with sqlite3.connect(db_path) as connection:
            connection.row_factory = sqlite3.Row
            engagement = connection.execute(
                "SELECT status,rules_json,scope_json FROM engagements WHERE engagement_id=?",
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
        if engagement["status"] != "active" or rules.get("execution_enabled") is not True or rules.get("authorization_verified") is not True:
            return False
        if task["status"] != "running" or task_input.get("active_testing") is not True or not task_input.get("scope_subset"):
            return False
        from core.active_executor import ActiveExecutionError, _validate_request_scope
        try:
            _validate_request_scope(args["target_url"], json.loads(engagement["scope_json"]), task_input["scope_subset"])
        except (ActiveExecutionError, ValueError):
            return False
        return bool(
            engagement["status"] == "active"
            and rules.get("execution_mode", "active") == "active"
            and rules.get("execution_enabled") is True
            and rules.get("authorization_verified") is True
            and task["agent"] in {"recon-agent", "enumeration-agent", "vulnerability-agent", "active-testing-agent"}
            and task["status"] == "running"
            and task_input.get("active_testing") is True
            and task_input.get("scope_subset")
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
    if passive_framing_args(argv):
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "allow",
        }}))
        return
    active_args = active_http_args(argv)
    surface_args = active_surface_args(argv)
    orchestration_args = orchestrator_args(argv)
    security_args = active_security_args(argv)
    db_arg = active_args["db"] if active_args else surface_args["db"] if surface_args else security_args["db"] if security_args else orchestration_args["db"] if orchestration_args else DB
    config_path, db_path = engagement_paths(db_arg)
    if config_path is None or not config_path.is_file() or config_path.is_symlink():
        deny("The engagement-specific local config is required for agent runtime commands.")
    try:
        engagement = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        deny("Invalid local engagement config.")
    if orchestration_args and engagement.get("engagement_id") != orchestration_args["engagement_id"]:
        deny("Orchestrator engagement ID does not match the selected isolated database/config pair.")
    if security_args:
        for request_file in security_args["request_files"]:
            if not _active_request_is_approved({
                "db": security_args["db"], "engagement_id": security_args["engagement_id"],
                "task_id": security_args["task_id"], "request_file": request_file,
            }, engagement):
                deny("Specialist security test requires an active approved task and every request manifest SHA-256-pinned in that task.")
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "allow",
        }}))
        return
    if active_args:
        if not _active_request_is_approved(active_args, engagement):
            deny("Active HTTP request is not authorized by the approved engagement, running task, and pinned manifest.")
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "allow",
        }}))
        return
    if surface_args:
        if not _active_surface_is_approved(surface_args, engagement):
            deny("Surface discovery requires an active, explicitly approved engagement and running scoped discovery task.")
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "allow",
        }}))
        return
    db_status = None
    try:
        with sqlite3.connect(db_path) as connection:
            row = connection.execute(
                "SELECT status FROM engagements WHERE engagement_id=?",
                (engagement.get("engagement_id"),),
            ).fetchone()
            db_status = row[0] if row else None
    except sqlite3.Error:
        deny("Unable to verify engagement state; default deny.")
    if db_status == "active":
        safe_read_only = (
            orchestration_args is not None
            or argv[1] == "scripts/knowledge_base.py"
            or (
                argv[1] == "scripts/workflow.py"
                and len(argv) == 7
                and argv[4] == "status"
                and argv[5] == "--engagement-id"
                and argv[6] == engagement.get("engagement_id")
            )
        )
        if not safe_read_only:
            deny("Only the active HTTP broker and allowlisted read-only status/KB commands are permitted during active execution.")
    elif engagement.get("rules_of_engagement", {}).get("execution_enabled") is not False:
        deny("Local config cannot enable active execution; operator approval must be recorded in the engagement database.")
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "allow",
    }}))


if __name__ == "__main__":
    main()
