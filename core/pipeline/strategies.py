"""Which hypotheses the pipeline can execute and validate on its own — and which it cannot.

The honest state of this release: **authorization comparisons** (object-level and function-level)
have an automated, broker-mediated executor and a deterministic oracle that works on
vault-resolved evidence. The other hypothesis families the planner can generate (injection,
reflection, outbound-request) need specialist-built, operator-pinned request manifests; the
pipeline does not pretend to test them. For those it returns an explicit, actionable evidence
request instead of a fabricated result, so the gap is visible in the report and never silent.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Strategy:
    category: str                 # planner hypothesis category
    capability: str               # capability the tool selector must resolve
    vulnerability_class: str      # validation oracle that judges the evidence
    max_profile: str              # highest execution profile this strategy may use
    automated: bool               # True only when an executor + oracle exist and are tested
    title: str
    note: str = ""


STRATEGIES = {
    "idor_bola": Strategy(
        "idor_bola", "authorization_comparison", "object_authorization", "active_controlled", True,
        "Broken object-level authorization",
        "Paired read-only requests for the same object as its declared owner and as another identity."),
    "bfla": Strategy(
        "bfla", "authorization_comparison", "function_authorization", "active_controlled", True,
        "Broken function-level authorization",
        "Paired read-only requests to a role-restricted function as a privileged and an unprivileged identity."),
    "sqli": Strategy(
        "sqli", "injection_testing", "sqli", "active_controlled", False, "SQL injection",
        "Requires specialist-built, operator-pinned request manifests; no automated executor in this release."),
    "xss": Strategy(
        "xss", "reflection_testing", "reflected_input", "active_controlled", False, "Reflected input",
        "Requires specialist-built, operator-pinned request manifests; no automated executor in this release."),
    "ssrf": Strategy(
        "ssrf", "outbound_request_testing", "ssrf", "active_controlled", False, "Server-side request forgery",
        "Requires explicitly authorized callback infrastructure; no automated executor or oracle in this release."),
}
