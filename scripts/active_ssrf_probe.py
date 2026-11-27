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
from core.security_testing import (_load_manifest, analyze_ssrf_probe,
                                   load_marker_matched_callback_events, redact_callback_events,
                                   validate_scoped_callback_url)


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
        if str(manifest.get("method", "")).upper() not in {"GET", "HEAD", "OPTIONS"} or manifest.get("body") not in (None, ""):
            raise ActiveExecutionError("SSRF canary workflow permits only read-only GET, HEAD or OPTIONS manifests without a body")
        request_url = str(manifest.get("url", ""))
        if args.marker not in args.callback_url or args.marker not in request_url or args.callback_url not in request_url:
            raise ActiveExecutionError("Pinned request URL must contain the exact HTTPS callback URL and unique marker")
        response = executor.execute_request_file(args.engagement_id, args.task_id, args.request_file)
        events = []
        callback_evidence = []
        if args.callback_events:
            events = load_marker_matched_callback_events(args.callback_events, ROOT, args.marker)
            if events:
                safe_events = redact_callback_events(events)
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
