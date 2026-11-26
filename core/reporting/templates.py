"""Versioned report templates.

Each builder turns a :class:`ReportContext` into a structured report dict. **Only confirmed
(validated/reported/resolved, integrity-verified) findings appear in confirmed sections.**
Unvalidated findings and scanner candidates are kept in a separate, clearly-labelled section
and are never presented as confirmed vulnerabilities.
"""
from __future__ import annotations

TEMPLATE_VERSION = "1.0"

_LIMITATIONS = [
    "Hypotheses, observations, rejected findings, and findings awaiting validation are not "
    "presented as confirmed vulnerabilities.",
    "Scanner candidates are leads, not confirmations.",
    "Evidence integrity is re-verified at report time; records failing verification are excluded.",
    "Authorization, scope, test methods and program policy must be confirmed separately by the operator.",
]


def _by_severity(findings) -> dict:
    counts = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return dict(sorted(counts.items()))


def _base(ctx, report_type) -> dict:
    return {"report_type": report_type, "template_version": TEMPLATE_VERSION,
            "engagement": ctx.engagement()}


def build_technical(ctx) -> dict:
    included, excluded = ctx.confirmed_findings()
    report = _base(ctx, "technical")
    report.update({
        "confirmed_findings": included,
        "excluded_findings": excluded,
        "unvalidated": ctx.unvalidated(),
        "confirmed_count": len(included),
        "limitations": _LIMITATIONS,
    })
    return report


def build_executive(ctx) -> dict:
    included, _ = ctx.confirmed_findings()
    report = _base(ctx, "executive")
    report.update({
        "executive_summary": f"{len(included)} independently validated finding(s) in scope.",
        "overall_posture": "needs_attention" if included else "no_confirmed_findings",
        "confirmed_by_severity": _by_severity(included),
        "key_risks": [{"title": f["title"], "severity": f["severity"],
                       "asset": f["asset"]} for f in included[:5]],
        "remediation_priorities": [f["finding_id"] for f in included
                                   if f["severity"] in ("critical", "high")],
        "limitations": _LIMITATIONS,
    })
    return report


def build_attack_surface(ctx) -> dict:
    report = _base(ctx, "attack_surface")
    report["surface"] = ctx.attack_surface()
    return report


def build_tool_execution(ctx) -> dict:
    included, _ = ctx.confirmed_findings()
    unvalidated = ctx.unvalidated()
    report = _base(ctx, "tool_execution")
    report.update({
        "tool_execution": ctx.tool_execution(),
        "candidates_generated": len(unvalidated["candidate_observations"]),
        "findings_confirmed": len(included),
    })
    return report


def build_evidence_package(ctx) -> dict:
    included, _ = ctx.confirmed_findings()
    report = _base(ctx, "evidence_package")
    report.update({
        "packages": [{"finding_id": f["finding_id"], "evidence": f["evidence"],
                      "validation_records": f["validation_records"]} for f in included],
        "note": "Evidence integrity re-verified at report time; references and hashes only — no secrets.",
    })
    return report


BUILDERS = {
    "executive": build_executive,
    "technical": build_technical,
    "attack_surface": build_attack_surface,
    "tool_execution": build_tool_execution,
    "evidence_package": build_evidence_package,
}
