#!/usr/bin/env python3
"""Passively review supplied HTTP header captures for framing anomalies."""
import argparse
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.security_testing import analyze_http_framing

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,required=True)
    args=parser.parse_args()
    if args.input.stat().st_size>65536: raise ValueError("Input exceeds 64 KiB")
    data=json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(data,dict): raise ValueError("Input must be a JSON object with a headers field")
    print(json.dumps(analyze_http_framing(data),ensure_ascii=False,indent=2))
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except (ValueError,OSError,json.JSONDecodeError) as exc:
        print(json.dumps({"error":str(exc)},ensure_ascii=False),file=sys.stderr); raise SystemExit(2)
