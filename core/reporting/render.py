"""Report renderers: structured report dict -> Markdown / HTML / JSON / SARIF.

Machine-readable output (JSON, SARIF) is kept separate from the human-readable report
(Markdown, HTML). Rendering is pure (no I/O) and escapes untrusted text.
"""
from __future__ import annotations

import html
import json

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note",
                "info": "note", "unknown": "warning"}


def _line(value) -> str:
    """One line of untrusted text: line breaks would let a field forge report structure."""
    return " ".join(str(value if value is not None else "").split())


def _quote(value) -> list:
    """A block of untrusted text, quoted so that it cannot introduce headings of its own."""
    return ["> " + line if line.strip() else ">" for line in str(value if value is not None else "").splitlines()] or [">"]


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
        lines += ["## Scope", "", "```json", json.dumps(structured["scope"], indent=2, sort_keys=True), "```", "",
                  "## Methodology", ""]
        lines += [f"- {step}" for step in structured["methodology"]]
        lines += ["", f"## Confirmed findings ({structured['confirmed_count']})", ""]
        for f in structured["confirmed_findings"]:
            basis = ("vault-verified evidence" if f["validation_evidence_verified"]
                     else "NOT vault-verified (predates the evidence chain or ran on embedded data)")
            lines += [f"### {_line(f['title'])}", "",
                      f"- Finding ID: {_line(f['finding_id'])}", f"- Severity: {_line(f['severity'])}",
                      f"- Vulnerability class: {_line(f['vulnerability_class'])}",
                      f"- Asset: {_line(f['asset'])} | Method: {_line(f['method'])} | Parameter: {_line(f['parameter'])}",
                      f"- Independently validated by: {_line(f['validated_by'])}",
                      f"- Validation basis: {basis}", "",
                      "#### Description", ""] + _quote(f["description"]) + ["",
                      "#### Reproduction conditions", ""]
            lines += [f"- {_line(p)}" for p in f["preconditions"]] or ["- Not recorded."]
            lines += ["", "#### Impact", ""] + _quote(f["impact"] or "Not specified.") + ["",
                      "#### Remediation (general guidance)", "",
                      "> " + (structured["remediation_guidance"].get(f["finding_id"]) or "No class-specific guidance available."),
                      "", "#### Evidence (integrity-verified)", ""]
            lines += [f"- {e['evidence_id']} — {e['type']}; SHA-256 {e['sha256']}" for e in f["evidence"]]
            lines.append("")
        unval = structured["unvalidated"]
        lines += ["## Unvalidated / candidates (NOT confirmed)", "",
                  f"- Unvalidated findings: {len(unval['unvalidated_findings'])}",
                  f"- Scanner candidates: {len(unval['candidate_observations'])}", ""]
        coverage = structured["coverage"]
        lines += ["## Coverage summary", "", f"- Hypotheses generated: {coverage['hypotheses_total']}"]
        for test_class, bucket in sorted(coverage["by_test_class"].items()):
            lines.append(f"- {test_class}: {bucket['hypotheses']} generated, {bucket['executed']} executed "
                         f"({bucket['supported']} supported, {bucket['refuted']} refuted, "
                         f"{bucket['inconclusive']} inconclusive, {bucket['blocked']} blocked)")
        lines += [f"- Endpoints never tested: {len(coverage['untested_endpoints'])}", ""]
        lines += ["## Unresolved hypotheses (NOT findings)", ""]
        for item in structured["unresolved_hypotheses"]:
            needs = ", ".join(r.get("kind", "?") for r in item["evidence_requests"]) or "none recorded"
            lines.append(f"- [{item['status']}] {_line(item['category'])} on {_line(item['target'])}: "
                         f"{_line(item['reason'])} (needs: {_line(needs)})")
        if not structured["unresolved_hypotheses"]:
            lines.append("- none")
        summary = structured["execution_summary"]
        lines += ["", "## Execution summary", ""]
        lines += [f"- {e['kind']} / {e['status']}: {e['count']}" for e in summary["by_kind_and_status"]] or ["- no executions"]
        for pending in summary["awaiting_operator_reconciliation"]:
            lines.append(f"- AWAITING OPERATOR: {pending['execution_id']} ({pending['tool_id']}, {pending['status']})")
        lines.append("")
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
