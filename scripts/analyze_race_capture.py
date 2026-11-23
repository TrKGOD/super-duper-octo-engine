#!/usr/bin/env python3
"""Passively analyze operator-supplied isolated-lab race-condition logs."""
import argparse
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.security_testing import analyze_race_capture

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,required=True)
    args=parser.parse_args()
    if args.input.is_absolute() or ".." in args.input.parts or args.input.parts[:1] != (".local",):
        raise ValueError("Input must be confined to .local/")
    candidate=ROOT/args.input
    if (ROOT/".local").is_symlink() or candidate.is_symlink():
        raise ValueError("Input path must not use symlinks")
    resolved=candidate.resolve(strict=True)
    if not resolved.is_file() or not resolved.is_relative_to((ROOT/".local").resolve(strict=True)):
        raise ValueError("Input must be a regular file inside .local/")
    if resolved.stat().st_size>65536:
        raise ValueError("Input exceeds 64 KiB")
    events=json.loads(resolved.read_text(encoding="utf-8"))
    print(json.dumps(analyze_race_capture(events),ensure_ascii=False,indent=2))
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except (ValueError,OSError,json.JSONDecodeError) as exc:
        print(json.dumps({"error":str(exc)},ensure_ascii=False),file=sys.stderr); raise SystemExit(2)
