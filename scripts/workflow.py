#!/usr/bin/env python3
"""CLI for Claude Code to persist plans, task transitions and agent handoffs."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.orchestration import Workflow

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db",default=".local/state.sqlite3")
    sub=p.add_subparsers(dest="command",required=True)
    x=sub.add_parser("init"); x.add_argument("--engagement",required=True)
    x=sub.add_parser("plan"); x.add_argument("--engagement-id",required=True); x.add_argument("--file",required=True)
    x=sub.add_parser("start"); x.add_argument("--task-id",required=True); x.add_argument("--model")
    x=sub.add_parser("handoff"); x.add_argument("--task-id",required=True); x.add_argument("--file",required=True)
    x=sub.add_parser("status"); x.add_argument("--engagement-id",required=True)
    a=p.parse_args()
    Path(a.db).parent.mkdir(parents=True,exist_ok=True)
    with Workflow(a.db) as w:
        if a.command=="init": out={"engagement_id":w.initialize(read_json(a.engagement)),"status":"draft"}
        elif a.command=="plan": out={"tasks":w.create_plan(a.engagement_id,read_json(a.file))}
        elif a.command=="start": out={"task_id":a.task_id,"run_id":w.start_task(a.task_id,a.model),"status":"running"}
        elif a.command=="handoff": w.accept_handoff(a.task_id,read_json(a.file)); out={"task_id":a.task_id,"accepted":True}
        else: out=w.status(a.engagement_id)
    print(json.dumps(out,indent=2,ensure_ascii=False))

if __name__=="__main__":
    try: main()
    except (ValueError,KeyError,OSError,json.JSONDecodeError) as e:
        print(json.dumps({"error":str(e)},ensure_ascii=False),file=sys.stderr); raise SystemExit(2)
