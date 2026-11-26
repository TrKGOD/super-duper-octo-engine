"""Report renderers: structured report dict -> Markdown / HTML / JSON / SARIF.

Machine-readable output (JSON, SARIF) is kept separate from the human-readable report
(Markdown, HTML). Rendering is pure (no I/O) and escapes untrusted text.
"""
from __future__ import annotations

import html
import json

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note",
                "info": "note", "unknown": "warning"}


def to_json(structured: dict) -> str:
    return json.dumps(structured, indent=2, ensure_ascii=False, sort_keys=True)


def to_markdown(structured: dict) -> str:
    rt = structured["report_type"]
    eng = structured["engagement"]
    lines = [f"# Witherhoard {rt.replace('_', ' ').title()} Report", "",
             f"**Engagement:** {eng['engagement_id']}  ",
             f"**Status:** {eng['status']}  ",
             "**Authorization reference:** [REDACTED]", ""]

    if rt == "executive":
        lines += ["## Executive summary", "", structured["executive_summary"], "",
                  f"**Overall posture:** {structured['overall_posture']}", "",
                  "## Confirmed findings by severity", ""]
        lines += [f"- {sev}: {n}" for sev, n in structured["confirmed_by_severity"].items()] or ["- none"]
        lines += ["", "## Key risks", ""]
        lines += [f"- [{r['severity']}] {r['title']} ({r['asset']})" for r in structured["key_risks"]] or ["- none"]
    elif rt == "technical":
        lines += [f"## Confirmed findings ({structured['confirmed_count']})", ""]
        for f in structured["confirmed_findings"]:
            lines += [f"### {f['title']}", "",
                      f"- Finding ID: {f['finding_id']}", f"- Severity: {f['severity']}",
                      f"- Vulnerability class: {f['vulnerability_class']}",
                      f"- Asset: {f['asset']} | Method: {f['method']} | Parameter: {f['parameter']}",
                      f"- Independently validated by: {f['validated_by']}", "",
                      "#### Description", "", str(f["description"]), "",
                      "#### Impact", "", str(f["impact"] or "Not specified."), "",
                      "#### Evidence (integrity-verified)", ""]
            lines += [f"- {e['evidence_id']} — {e['type']}; SHA-256 {e['sha256']}" for e in f["evidence"]]
            lines.append("")
        unval = structured["unvalidated"]
        lines += ["## Unvalidated / candidates (NOT confirmed)", "",
                  f"- Unvalidated findings: {len(unval['unvalidated_findings'])}",
                  f"- Scanner candidates: {len(unval['candidate_observations'])}", ""]
    elif rt == "attack_surface":
        surface = structured["surface"]
        for key in ("hosts", "services", "endpoints", "routes", "parameters", "technologies"):
            lines += [f"## {key.title()} ({len(surface[key])})", ""]
            lines += [f"- {item['key']} ({item['trust']})" for item in surface[key][:50]]
            lines.append("")
        lines += ["> " + surface["coverage_note"], ""]
    elif rt == "tool_execution":
        lines += [f"- Candidates generated: {structured['candidates_generated']}",
                  f"- Findings confirmed: {structured['findings_confirmed']}", "", "## Tools", ""]
        for tool, counts in structured["tool_execution"]["by_tool"].items():
            lines.append(f"- {tool}: detected={counts['detected']} candidates={counts['candidates']} "
                         f"errors={counts['errors']}")
    elif rt == "evidence_package":
        lines += ["## Evidence packages", ""]
        for pkg in structured["packages"]:
            lines.append(f"- {pkg['finding_id']}: {len(pkg['evidence'])} evidence item(s), "
                         f"{len(pkg['validation_records'])} validation record(s)")

    lines += ["", "## Limitations", ""]
    lines += [f"- {lim}" for lim in structured.get("limitations", [])]
    return "\n".join(lines)


def to_html(structured: dict) -> str:
    rendered = html.escape(to_markdown(structured))
    return ("<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>Witherhoard Report</title></head><body><pre>" + rendered + "</pre></body></html>")


def to_sarif(structured: dict) -> dict:
    results = []
    for f in structured.get("confirmed_findings", []):
        results.append({
            "ruleId": f.get("vulnerability_class") or "finding",
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["title"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["asset"]}}}],
            "properties": {"finding_id": f["finding_id"], "validated_by": f["validated_by"],
                           "validation_records": f["validation_records"]},
        })
    return {
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "Witherhoard",
                                      "informationUri": "https://github.com/TrKGOD/witherhoard",
                                      "rules": []}},
                  "results": results}],
    }
