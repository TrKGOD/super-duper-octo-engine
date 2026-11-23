#!/usr/bin/env python3
"""Narrow command broker for workflow bookkeeping and read-only KB retrieval; never a sandbox."""
import json,re,shlex,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CONFIG=ROOT/"config/engagement.local.json"
DB=".local/state.sqlite3"; KB_DB=".local/knowledge-base.sqlite3"
def deny(message):
 print(json.dumps({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":message}})); raise SystemExit(0)
def safe_local_json(path):
 p=Path(path); return not p.is_absolute() and ".." not in p.parts and p.parts[:1]==(".local",) and p.suffix==".json"
def allowed_argv(argv):
 if len(argv)<2 or argv[0] not in {"python","python3"}: return False
 script=argv[1]
 if script=="scripts/migrate.py": return argv==[argv[0],script,"--db",DB]
 if script=="scripts/knowledge_base.py":
  a=argv[2:]
  if len(a)==7 and a[:3]==["--db",KB_DB,"search"] and a[3]=="--query" and re.fullmatch(r"[A-Za-z0-9 _.-]{1,160}",a[4]) and a[5]=="--limit" and a[6].isdigit(): return 1<=int(a[6])<=10
  if len(a)==7 and a[:3]==["--db",KB_DB,"search-patterns"] and a[3]=="--query" and re.fullmatch(r"[A-Za-z0-9 _.-]{1,160}",a[4]) and a[5]=="--limit" and a[6].isdigit(): return 1<=int(a[6])<=10
  if len(a)==5 and a[:3]==["--db",KB_DB,"show"] and a[3]=="--document-id" and re.fullmatch(r"KB-[A-F0-9]{16}",a[4]): return True
  return False
 if script!="scripts/workflow.py": return False
 a=argv[2:]
 if len(a)<3 or a[:2]!=["--db",DB]: return False
 c=a[2:]
 if len(c)==3 and c[0]=="status" and c[1]=="--engagement-id" and bool(c[2]): return True
 if len(c)==3 and c[0]=="init" and c[1]=="--engagement" and c[2]=="config/engagement.local.json": return True
 if len(c)==5 and c[0]=="plan" and c[1]=="--engagement-id" and bool(c[2]) and c[3]=="--file" and safe_local_json(c[4]): return True
 if len(c)==3 and c[0]=="start" and c[1]=="--task-id" and bool(c[2]): return True
 if len(c)==5 and c[0]=="handoff" and c[1]=="--task-id" and bool(c[2]) and c[3]=="--file" and safe_local_json(c[4]): return True
 if len(c)==5 and c[0]=="finding" and c[1]=="--file" and safe_local_json(c[2]) and c[3]=="--engagement-id" and bool(c[4]): return True
 return False
def main():
 try: payload=json.load(sys.stdin)
 except Exception: deny("Unable to parse tool input; default deny.")
 command=str(payload.get("tool_input",{}).get("command","")).strip()
 if not command or any(x in command for x in (";","|","&",">","<","\n","\r","$","`")): deny("Only one allowlisted local workflow or read-only KB command is permitted.")
 try: argv=shlex.split(command)
 except ValueError: deny("Unable to parse command; default deny.")
 if not allowed_argv(argv): deny("Command is not in the local workflow/KB read-only allowlist.")
 if not CONFIG.exists(): deny("Local engagement config is required for agent runtime commands.")
 try: engagement=json.loads(CONFIG.read_text(encoding="utf-8"))
 except Exception: deny("Invalid local engagement config.")
 if engagement.get("rules_of_engagement",{}).get("execution_enabled") is not False: deny("Agent runtime commands are allowed only while execution_enabled=false.")
 print(json.dumps({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}))
if __name__=="__main__": main()
