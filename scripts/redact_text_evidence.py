#!/usr/bin/env python3
"""Create a best-effort redacted text copy without modifying the source.

This is a helper, not a complete secret/PII detector. Review the output manually.
"""
import argparse
import json
import re
import sys
from pathlib import Path

PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S)),
    ("authorization_header", re.compile(r"(?im)^(\s*authorization\s*:\s*)(?:bearer|basic)\s+[^\s]+", re.I)),
    ("cookie_header", re.compile(r"(?im)^(\s*(?:set-cookie|cookie)\s*:\s*).+$", re.I)),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("credential_assignment", re.compile(r"(?i)(\b(?:password|passwd|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|secret)\b\s*[:=]\s*)([\"']?)[^\s,;\"']+")),
    ("url_credentials", re.compile(r"\b(https?://)[^/@\s:]+:[^/@\s]+@")),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]


def redact_text(text):
    counts = {}
    result = text
    for name, pattern in PATTERNS:
        result, count = pattern.subn(
            lambda match: (match.group(1) + "[REDACTED]" if name in {
                "authorization_header", "cookie_header", "credential_assignment"
            } and match.lastindex else "[REDACTED]"),
            result,
        )
        if count:
            counts[name] = count
    return result, counts


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
