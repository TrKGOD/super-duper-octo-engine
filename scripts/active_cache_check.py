#!/usr/bin/env python3
"""Compare cache isolation for two synthetic identities using sequential GETs."""
import argparse
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.active_executor import ActiveExecutionError,ActiveHTTPExecutor
from core.orchestration import Workflow
from core.security_testing import execute_readonly_pair,analyze_cache_pair

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",default=".local/state.sqlite3")
    parser.add_argument("--engagement-id",required=True)
    parser.add_argument("--task-id",required=True)
    parser.add_argument("--first-request-file",required=True)
    parser.add_argument("--second-request-file",required=True)
    parser.add_argument("--first-private-marker",required=True)
    parser.add_argument("--second-private-marker",required=True)
    args=parser.parse_args()
    with Workflow(args.db,project_root=ROOT) as workflow:
        executor=ActiveHTTPExecutor(workflow,ROOT)
        pair=execute_readonly_pair(executor,args.engagement_id,args.task_id,
            args.first_request_file,args.second_request_file,
            identity_mode="two_identities",first_label="synthetic-identity-a",
            second_label="synthetic-identity-b")
    result=analyze_cache_pair(pair,first_private_marker=args.first_private_marker,
        second_private_marker=args.second_private_marker)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if result.get("status")=="partial_execution": raise SystemExit(3)
    return 0 if result.get("status")=="candidate_only" else 1

if __name__=="__main__":
    try: raise SystemExit(main())
    except (ActiveExecutionError,ValueError,KeyError,OSError,json.JSONDecodeError) as exc:
        print(json.dumps({"error":str(exc)},ensure_ascii=False),file=sys.stderr); raise SystemExit(2)
