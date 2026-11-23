#!/usr/bin/env python3
"""Import redacted SARIF, ZAP JSON or Burp XML scanner output into evidence vault."""
import argparse
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.store import StateStore
from core.evidence import EvidenceVault
from core.evidence_adapters import import_sarif, import_zap_json, import_burp_xml

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",default=".local/state.sqlite3")
    parser.add_argument("--project-root",default=".")
    parser.add_argument("--engagement-id",required=True)
    parser.add_argument("--format",choices=["sarif","zap-json","burp-xml"],required=True)
    parser.add_argument("--input",required=True)
    parser.add_argument("--captured-by",required=True)
    parser.add_argument("--redacted",action="store_true",help="Assert that secrets and personal data were redacted before import")
    args=parser.parse_args()
    if not args.redacted:
        parser.error("--redacted is required; redact scanner exports before ingestion")
    path=Path(args.input)
    raw=path.read_bytes()
    with StateStore(args.db) as store:
        vault=EvidenceVault(store,args.project_root)
        if args.format=="sarif": result=import_sarif(vault,args.engagement_id,raw,args.captured_by,True)
        elif args.format=="zap-json": result=import_zap_json(vault,args.engagement_id,raw,args.captured_by,True)
        else: result=import_burp_xml(vault,args.engagement_id,raw,args.captured_by,True)
    print(json.dumps({"imported_hypotheses":result,"warning":"Scanner imports are unvalidated hypotheses, not confirmed findings."},indent=2))

if __name__=="__main__":
    main()
