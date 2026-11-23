#!/usr/bin/env python3
"""Compare authenticated and anonymous GET/HEAD/OPTIONS access via the broker."""
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.active_executor import ActiveExecutionError, ActiveHTTPExecutor
from core.orchestration import Workflow
from core.security_testing import execute_readonly_pair, analyze_authentication_pair

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",default=".local/state.sqlite3")
    parser.add_argument("--engagement-id",required=True)
    parser.add_argument("--task-id",required=True)
    parser.add_argument("--authenticated-request-file",required=True)
    parser.add_argument("--anonymous-request-file",required=True)
    parser.add_argument("--protected-resource",required=True)
    args=parser.parse_args()
    with Workflow(args.db,project_root=ROOT) as workflow:
        executor=ActiveHTTPExecutor(workflow,ROOT)
        pair=execute_readonly_pair(executor,args.engagement_id,args.task_id,
            args.authenticated_request_file,args.anonymous_request_file,
            identity_mode="authenticated_vs_anonymous",
            first_label="authenticated",second_label="anonymous")
    result=analyze_authentication_pair(pair,authenticated_label="authenticated",
        anonymous_label="anonymous",protected_resource=args.protected_resource)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if result.get("status")=="partial_execution": raise SystemExit(3)
    return 0 if result.get("status")=="candidate_only" else 1

if __name__=="__main__":
    try: raise SystemExit(main())
    except (ActiveExecutionError,ValueError,KeyError,OSError,json.JSONDecodeError) as exc:
        print(json.dumps({"error":str(exc)},ensure_ascii=False),file=sys.stderr); raise SystemExit(2)
