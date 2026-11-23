#!/usr/bin/env python3
"""Execute one operator-reviewed, scope-pinned HTTP request for an active task."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.active_executor import ActiveExecutionError, ActiveHTTPExecutor
from core.orchestration import Workflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--request-file", required=True)
    args = parser.parse_args()
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    with Workflow(args.db) as workflow:
        result = ActiveHTTPExecutor(workflow, ROOT).execute_request_file(
            args.engagement_id, args.task_id, args.request_file
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ActiveExecutionError, ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
