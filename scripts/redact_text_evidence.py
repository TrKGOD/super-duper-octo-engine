#!/usr/bin/env python3
"""Create a best-effort redacted text copy without modifying the source.

This is a helper, not a complete secret/PII detector. Review the output manually.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.redaction import redact_with_counts

def redact_text(text):
    """Best-effort redaction incl. e-mail addresses; returns ``(clean_text, counts)``."""
    return redact_with_counts(text, pii=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = Path(args.input)
    target = Path(args.output)
    if source.resolve() == target.resolve():
        parser.error("output must be a different file; source is never overwritten")
    raw = source.read_bytes()
    if b"\x00" in raw:
        parser.error("binary input is not supported")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        parser.error("input must be UTF-8 text")
    cleaned, counts = redact_text(text)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(cleaned, encoding="utf-8")
    print(json.dumps({
        "source": str(source),
        "output": str(target),
        "redaction_counts": counts,
        "manual_review_required": True,
        "redacted_assertion_authorized": False,
        "warning": "This helper cannot detect every secret or personal-data field. Review output before marking evidence redacted.",
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        print("redaction helper failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
