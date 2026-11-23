#!/usr/bin/env python3
"""Generate a validated engagement plan with the LLM orchestrator and optionally dispatch it."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.llm_orchestrator import run_orchestrator
from core.orchestration import Workflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--claude-bin", default="claude")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--plan-out")
    args = parser.parse_args()
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    with Workflow(args.db) as workflow:
        result = run_orchestrator(
            workflow, args.engagement_id, args.model, args.claude_bin,
            args.timeout_seconds, dispatch=not args.plan_only,
        )
    if args.plan_out:
        target = Path(args.plan_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result["plan"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
