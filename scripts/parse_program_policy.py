#!/usr/bin/env python3
"""Parse operator-supplied bug-bounty policy text into an unverified scope draft.

No web scraping, login, private API access, or authorization decision is performed.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "templates/program-scope.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)

SECTION_ALIASES = {
    "assets_in_scope": {"in scope", "scope", "eligible assets", "targets", "assets"},
    "out_of_scope": {"out of scope", "excluded assets", "exclusions", "out-of-scope"},
    "prohibited_methods": {"prohibited activities", "prohibited testing", "out of scope activities",
                           "forbidden testing", "rules of engagement", "testing restrictions"},
    "rate_limits": {"rate limits", "request limits", "throttling", "traffic limits"},
    "testing_windows": {"testing window", "testing hours", "maintenance window", "time restrictions"},
    "data_handling": {"data handling", "sensitive data", "data protection", "privacy"},
    "safe_harbor": {"safe harbor", "legal", "authorization", "disclosure policy"},
    "bounty_eligibility": {"rewards", "bounty", "eligibility", "reward policy"},
}


def _normalize(value):
    return re.sub(r"[^a-z0-9 -]", "", value.lower()).strip()


def _sections(lines):
    sections = {}
    current = ("document", 1, [])
    for number, line in enumerate(lines, 1):
        heading = re.match(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            if current[2]:
                sections.setdefault(current[0], []).append({
                    "start": current[1], "lines": current[2],
                })
            current = (_normalize(heading.group(2)), number, [])
        else:
            current[2].append((number, line))
    if current[2]:
        sections.setdefault(current[0], []).append({
            "start": current[1], "lines": current[2],
        })
    return sections


def _find_section(sections, field):
    aliases = SECTION_ALIASES[field]
    found = []
    for heading, blocks in sections.items():
        if heading in aliases:
            found.extend(blocks)
    return found


def _extract_lines(blocks):
    values, evidence = [], []
    for block in blocks:
        for number, raw in block["lines"]:
            value = raw.strip()
            if not value:
                continue
            cleaned = re.sub(r"^\s*(?:[-*+] |\d+[.)] )", "", value).strip()
            if cleaned:
                values.append(cleaned)
                evidence.append((number, value))
    return values, evidence


def parse_policy(text, source):
    lines = text.splitlines()
    sections = _sections(lines)
    profile = {
        "profile_version": 1,
        "status": "draft_unverified",
        "operator_confirmation_required": True,
        "source": source,
        "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "program_name": None,
        "assets_in_scope": [],
        "out_of_scope": [],
        "prohibited_methods": [],
        "rate_limits": [],
        "testing_windows": [],
        "data_handling": [],
        "safe_harbor": None,
        "bounty_eligibility": None,
        "ambiguities": [],
        "evidence": [],
    }
    for line in lines:
        match = re.match(r"^\s{0,3}#\s+(.+?)\s*#*\s*$", line)
        if match:
            profile["program_name"] = match.group(1).strip()
            break

    for field in SECTION_ALIASES:
        blocks = _find_section(sections, field)
        values, evidence = _extract_lines(blocks)
        if field in {"safe_harbor", "bounty_eligibility"}:
            profile[field] = "\n".join(values) if values else None
        else:
            profile[field] = values
        for number, quote in evidence:
            profile["evidence"].append({
                "field": field,
                "section": next((heading for heading, items in sections.items()
                                 if any(any(line_number == number for line_number, _ in item["lines"])
                                        for item in items)), "unknown"),
                "quote": quote[:1000],
                "line": number,
            })
        if not blocks:
            profile["ambiguities"].append("No clearly labelled section found for: " + field)

    if not profile["assets_in_scope"]:
        profile["ambiguities"].append("No in-scope assets were extracted; do not test any asset.")
    if not profile["out_of_scope"]:
        profile["ambiguities"].append("No explicit exclusions were extracted; operator must verify exclusions.")
    if not profile["prohibited_methods"]:
        profile["ambiguities"].append("No prohibited-method section was identified; treat all active methods as prohibited.")
    if not profile["rate_limits"]:
        profile["ambiguities"].append("No rate limit was extracted; do not generate traffic.")
    # Preserve explicit rate/limit statements even when headings are inconsistent.
    for number, line in enumerate(lines, 1):
        if re.search(r"\b(rate|requests? per second|rps|throttl|requests? per minute)\b", line, re.I):
            if line.strip() not in profile["rate_limits"]:
                profile["rate_limits"].append(line.strip())
                profile["evidence"].append({
                    "field": "rate_limits", "section": "keyword_fallback",
                    "quote": line.strip()[:1000], "line": number,
                })

    errors = list(VALIDATOR.iter_errors(profile))
    if errors:
        raise ValueError("; ".join(error.message for error in errors))
    return profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Local policy text/Markdown supplied by the operator")
    parser.add_argument("--output", default=".local/program-scope-draft.json")
    args = parser.parse_args()
    source_path = Path(args.input)
    text = source_path.read_text(encoding="utf-8")
    profile = parse_policy(text, str(source_path))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": profile["status"],
        "operator_confirmation_required": True,
        "source_sha256": profile["source_sha256"],
        "extracted_evidence_lines": len(profile["evidence"]),
        "ambiguities": profile["ambiguities"],
        "output": str(target),
        "warning": "Draft extraction only. Never treat this file as verified authorization or a machine-approved scope.",
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print("policy parser failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
