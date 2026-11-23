#!/usr/bin/env python3
"""Run an operator-authored, schema- and Skill-validated plan through sequential specialist dispatch."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.dispatch import dispatch_plan
from core.orchestration import Workflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--claude-bin", default="claude")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    with Workflow(args.db) as workflow:
        result = dispatch_plan(
            workflow, args.engagement_id, args.model,
            args.claude_bin, args.timeout_seconds,
        )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    # A completed dispatch pass may legitimately leave operator-gated branches.
    # The JSON status is authoritative; reserve non-zero exits for execution errors.
    if result["status"] not in {"completed", "needs_operator", "failed", "incomplete"}:
        raise SystemExit(2)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
