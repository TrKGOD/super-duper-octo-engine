#!/usr/bin/env python3
"""Render a Markdown report from persisted independently validated findings only."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.evidence import EvidenceVault, EvidenceError
from core.evidence_scoring import score_finding
from core.store import StateStore


def safe_text(value):
    text = str(value or "")
    lines = []
    for line in text.splitlines():
        if line.lstrip().startswith(("#", "-", "*", ">", "|")):
            line = "\\" + line
        line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        lines.append(line.replace(chr(96), "&#96;"))
    return "\n".join(lines)


def render_report(store, engagement_id, project_root):
    engagement = store.connection.execute(
        "SELECT authorization_reference,status,scope_json FROM engagements WHERE engagement_id=?",
        (engagement_id,),
    ).fetchone()
    if engagement is None:
        raise ValueError("Unknown engagement: " + engagement_id)
    rows = store.connection.execute(
        """SELECT finding_id,title,status,severity,asset,method,parameter,description,
                  impact,evidence_refs_json,proposed_by,validated_by,validation_notes,preconditions_json
           FROM findings WHERE engagement_id=? AND status IN ('validated','reported')
           ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
             WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, finding_id""",
        (engagement_id,),
    ).fetchall()
    vault = EvidenceVault(store, project_root)
    sections = [
        "# Security Assessment Report",
        "",
        f"**Engagement:** {safe_text(engagement_id)}  ",
        f"**Status:** {safe_text(engagement['status'])}  ",
        "**Authorization reference:** [REDACTED]",
        "",
        "> This report includes only findings persisted as independently validated or reported. Evidence integrity is rechecked at render time. This tool does not independently establish legal authorization.",
        "",
    ]
    included, excluded = [], []
    for row in rows:
        refs = json.loads(row["evidence_refs_json"])
        evidence = store.finding_evidence(row["finding_id"])
        integrity = {}
        for evidence_id in refs:
            try:
                integrity[evidence_id] = vault.verify(evidence_id)["valid"]
            except (EvidenceError, OSError):
                integrity[evidence_id] = False
        if not refs or not all(integrity.values()):
            excluded.append({"finding_id": row["finding_id"], "reason": "missing or failed evidence integrity verification"})
            continue
        finding = dict(row)
        finding["evidence_refs"] = refs
        readiness = score_finding(finding, evidence, integrity)
        included.append(row["finding_id"])
        sections.extend([
            f"## {safe_text(row['title'])}",
            "",
            f"- **Finding ID:** {safe_text(row['finding_id'])}",
            f"- **Status:** {safe_text(row['status'])}",
            f"- **Severity:** {safe_text(row['severity'])}",
            f"- **Asset:** {safe_text(row['asset'])}",
            f"- **Method:** {safe_text(row['method'])}",
            f"- **Parameter:** {safe_text(row['parameter'])}",
            f"- **Proposed by:** {safe_text(row['proposed_by'])}",
            f"- **Independently validated by:** {safe_text(row['validated_by'])}",
            f"- **Evidence readiness:** {readiness['score']}/100 (not a validity score)",
            "",
            "### Description", "",
            safe_text(row["description"]),
            "",
            "### Impact", "",
            safe_text(row["impact"] or "Not specified."),
            "",
            "### Preconditions", "",
        ])
        preconditions = json.loads(row["preconditions_json"] or "[]")
        sections.extend([f"- {safe_text(item)}" for item in preconditions] or ["- Not specified."])
        sections.extend(["", "### Validation notes", "", safe_text(row["validation_notes"] or "Not specified."), "", "### Verified evidence", ""])
        for item in evidence:
            sections.append(
                f"- {safe_text(item['evidence_id'])} — {safe_text(item['evidence_type'])}; "
                f"SHA-256 {safe_text(item['sha256'])}; integrity verified; "
                f"redacted assertion: {bool(item['redacted'])}"
            )
        sections.append("")

    sections.extend([
        "## Excluded from this report", "",
        f"Validated/reported records excluded due to evidence integrity problems: {len(excluded)}",
    ])
    for item in excluded:
        sections.append(f"- {safe_text(item['finding_id'])} — {safe_text(item['reason'])}")
    sections.extend([
        "", "## Limitations", "",
        "- Hypotheses, observations, rejected findings, and findings awaiting validation are not presented as confirmed vulnerabilities.",
        "- Evidence readiness is a documentation aid, not proof of exploitability or impact.",
        "- Authorization, scope, test methods, and program policy must be confirmed separately by the operator.",
        "",
    ])
    return "\n".join(sections), {"included": included, "excluded": excluded}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-root", default=".")
    args = parser.parse_args()
    with StateStore(args.db) as store:
        report, manifest = render_report(store, args.engagement_id, args.project_root)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(report, encoding="utf-8")
    print(json.dumps({
        "output": str(target),
        "included_findings": len(manifest["included"]),
        "excluded_findings": len(manifest["excluded"]),
        "warning": "Only independently validated/reported findings with currently verified evidence are included.",
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("report rendering failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
