#!/usr/bin/env python3
"""Execute one operator-pinned SSRF canary request through the HTTP broker."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.active_executor import ActiveExecutionError, ActiveHTTPExecutor
from core.orchestration import Workflow
from core.security_testing import _load_manifest, analyze_ssrf_probe, validate_scoped_callback_url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--request-file", required=True)
    parser.add_argument("--callback-url", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--callback-events", type=Path)
    args = parser.parse_args()
    with Workflow(args.db, project_root=ROOT) as workflow:
        row = workflow.store.connection.execute(
            "SELECT scope_json FROM engagements WHERE engagement_id=?", (args.engagement_id,)
        ).fetchone()
        if row is None:
            raise ActiveExecutionError("Unknown engagement")
        callback_host = validate_scoped_callback_url(args.callback_url, json.loads(row["scope_json"]))
        executor = ActiveHTTPExecutor(workflow, ROOT)
        manifest = _load_manifest(executor, args.request_file)
        serialized = json.dumps(manifest, sort_keys=True)
        if args.marker not in serialized or args.callback_url not in serialized:
            raise ActiveExecutionError("Pinned request manifest must contain the exact callback URL and unique marker")
        response = executor.execute_request_file(args.engagement_id, args.task_id, args.request_file)
        events = []
        callback_evidence = []
        if args.callback_events:
            event_path = args.callback_events
            if event_path.is_absolute() or ".." in event_path.parts or event_path.parts[:1] != (".local",):
                raise ActiveExecutionError("Callback evidence must be confined to .local/")
            event_candidate = ROOT / event_path
            local_root = ROOT / ".local"
            if local_root.is_symlink() or event_candidate.is_symlink():
                raise ActiveExecutionError("Callback evidence path must not use symlinks")
            event_resolved = event_candidate.resolve(strict=True)
            if not event_resolved.is_file() or not event_resolved.is_relative_to(local_root.resolve(strict=True)):
                raise ActiveExecutionError("Callback evidence must be a regular file inside .local/")
            if event_resolved.stat().st_size > 65536:
                raise ActiveExecutionError("Callback evidence file exceeds 64 KiB")
            supplied = json.loads(event_resolved.read_text(encoding="utf-8"))
            if not isinstance(supplied, list) or len(supplied) > 100:
                raise ActiveExecutionError("Callback evidence must be a JSON array of at most 100 events")
            events = [item for item in supplied if isinstance(item, dict) and item.get("marker") == args.marker]
            if events:
                safe_events = [{
                    key: event.get(key) for key in ("marker", "timestamp", "source_ip", "method", "path")
                    if key in event
                } for event in events]
                artifact = executor.vault.capture(
                    args.engagement_id, "other",
                    "ssrf-callback-" + hashlib.sha256(args.marker.encode()).hexdigest()[:16] + ".json",
                    json.dumps(safe_events, ensure_ascii=False, indent=2).encode(),
                    "vulnerability-agent", redacted=True,
                )
                callback_evidence.append(artifact["evidence_id"])
        result = analyze_ssrf_probe(response, marker=args.marker, callback_events=events)
        result["callback_host"] = callback_host
        result["evidence_refs"] = list(dict.fromkeys(result["evidence_refs"] + callback_evidence))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result["status"] == "candidate_only":
            return 0
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ActiveExecutionError, ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
