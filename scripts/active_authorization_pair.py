#!/usr/bin/env python3
"""Execute a pinned, read-only synthetic IDOR/BOLA request pair through the broker."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.active_executor import ActiveExecutionError, ActiveHTTPExecutor
from core.authorization_execution import execute_object_access_comparison
from core.orchestration import Workflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--owner-request-file", required=True)
    parser.add_argument("--other-request-file", required=True)
    parser.add_argument("--owner-identity", required=True)
    parser.add_argument("--other-identity", required=True)
    parser.add_argument("--object-reference", required=True)
    args = parser.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    with Workflow(args.db, project_root=ROOT) as workflow:
        executor = ActiveHTTPExecutor(workflow, ROOT)
        result = execute_object_access_comparison(
            executor,
            args.engagement_id,
            args.task_id,
            args.owner_request_file,
            args.other_request_file,
            owner_identity=args.owner_identity,
            other_identity=args.other_identity,
            object_reference=args.object_reference,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") == "partial_execution":
        raise SystemExit(3)


if __name__ == "__main__":
    try:
        main()
    except (ActiveExecutionError, ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
