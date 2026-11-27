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


METHODOLOGY = [
    "Observation: same-origin discovery through the scope-enforcing HTTP broker; results are 'observed' "
    "graph facts, never authorization.",
    "Hypotheses are generated from graph facts, prioritised with a transparent score, and each must pass "
    "deterministic policy (scope, identity, test class, state-change approval) before anything runs.",
    "Execution happens only through the broker; every request is a ledger execution with linked, "
    "SHA-256-verified evidence.",
    "Validation is independent of the proposer: the engine resolves the evidence itself and judges it "
    "with deterministic oracles; only vault-verified validations can confirm a finding.",
    "A finding is reported as confirmed only after an independent validator confirmed it and its "
    "evidence integrity re-verified at report time.",
]

# General, vetted remediation guidance per validated vulnerability class (not target-specific advice).
REMEDIATION_GUIDANCE = {
    "object_authorization": "Enforce object-level authorization on the server for every request: verify that the "
                            "authenticated principal owns or is permitted to access the referenced object; never "
                            "rely on identifier secrecy.",
    "function_authorization": "Enforce function-level authorization centrally (deny by default): check the caller's "
                              "role or permission for every privileged operation on the server side.",
    "sqli": "Use parameterised queries / prepared statements for all database access and apply least-privilege "
            "database accounts.",
    "reflected_input": "Contextually encode all output, apply a restrictive Content-Security-Policy and validate input.",
    "security_header": "Set the missing security response header at the edge or application layer.",
}


def _by_severity(findings) -> dict:
    counts = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return dict(sorted(counts.items()))


def _base(ctx, report_type) -> dict:
    return {"report_type": report_type, "template_version": TEMPLATE_VERSION,
            "engagement": ctx.engagement()}


def _dynamic_limitations(ctx, included, investigation) -> list:
    limitations = list(_LIMITATIONS)
    unverified = [f["finding_id"] for f in included if not f.get("validation_evidence_verified")]
    if unverified:
        limitations.append(
            f"{len(unverified)} confirmed finding(s) were validated before vault-verified evidence resolution "
            "existed (or on embedded data); re-validate them before relying on the evidence chain: "
            + ", ".join(unverified))
    if investigation["hypotheses_without_automated_executor"]:
        limitations.append(
            f"{investigation['hypotheses_without_automated_executor']} hypothesis(es) belong to categories with no "
            "automated executor in this release (injection, reflection, outbound-request); they were generated "
            "but NOT tested.")
    if investigation["untested_endpoints"]:
        limitations.append(f"{len(investigation['untested_endpoints'])} discovered endpoint(s) were never tested.")
    return limitations


def build_technical(ctx) -> dict:
    included, excluded = ctx.confirmed_findings()
    investigation = ctx.investigation()
    report = _base(ctx, "technical")
    report.update({
        "scope": report["engagement"]["scope"],
        "methodology": METHODOLOGY,
        "confirmed_findings": included,
        "excluded_findings": excluded,
        "remediation_guidance": {f["finding_id"]: REMEDIATION_GUIDANCE.get(f["vulnerability_class"] or "", "")
                                 for f in included},
        "unvalidated": ctx.unvalidated(),
        "unresolved_hypotheses": investigation["unresolved_hypotheses"],
        "coverage": {"by_test_class": investigation["coverage_by_test_class"],
                     "untested_endpoints": investigation["untested_endpoints"],
                     "hypotheses_total": investigation["hypotheses_total"]},
        "execution_summary": ctx.execution_summary(),
        "confirmed_count": len(included),
        "limitations": _dynamic_limitations(ctx, included, investigation),
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
