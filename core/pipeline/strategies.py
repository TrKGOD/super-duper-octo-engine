"""Which hypotheses the pipeline can execute and validate on its own — and which it cannot.

The honest state of this release: **authorization comparisons** (object-level and function-level),
**SQL injection**, **reflected input (XSS)** and **server-side request forgery** each have an
automated, broker-mediated executor and a deterministic oracle that works on vault-resolved
evidence. Every one of them is deliberately narrower than "test this endpoint for X":

* SQLi and XSS probe only the first (alphabetically) declared QUERY-string parameter of an
  endpoint, over GET/HEAD only. Form fields, JSON bodies, headers, cookies and a second query
  parameter on the same endpoint are not automated — the planner's per-endpoint hypothesis does
  not distinguish parameters, so this is a real coverage gap, stated here rather than hidden.
* SQLi sends exactly one well-known technique: a quote-delimited boolean pair
  (``' OR '1'='1`` / ``' OR '1'='2``). No numeric-context, UNION, stacked, time-based or
  error-extraction payloads are constructed.
* XSS sends one benign, non-executing marker and classifies where it lands with
  ``core.html_context`` (a standard-library HTML parse, not a payload-mutation engine); an
  ambiguous or inconclusive placement is never guessed into a confirmation.
* SSRF needs an engagement already configured with ``rules_of_engagement.ssrf_callback_url``
  (an operator-run, scope-listed HTTPS listener — this framework never stands up or hosts one)
  and only targets a query parameter whose name matches a URL-fetch hint. Absence of a callback
  never refutes a finding: it only ever reaches SUPPORTED or INCONCLUSIVE.
* All four refuse a state-changing (POST/PUT/PATCH/DELETE) target outright; those still need an
  operator-pinned, individually approved manifest.

For everything else the pipeline returns an explicit, actionable evidence request instead of a
fabricated result, so a gap is visible in the report and never silent.
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
        "sqli", "injection_testing", "sqli", "active_controlled", True, "SQL injection",
        "One quote-delimited boolean pair against the endpoint's first query parameter, GET-only; "
        "no numeric-context, UNION, stacked, time-based or error-extraction technique."),
    "xss": Strategy(
        "xss", "reflection_testing", "reflected_input", "active_controlled", True, "Reflected input",
        "One benign marker against the endpoint's first query parameter, GET-only; its landing "
        "context is classified by core.html_context, never guessed when ambiguous."),
    "ssrf": Strategy(
        "ssrf", "outbound_request_testing", "ssrf", "active_controlled", True, "Server-side request forgery",
        "Requires an operator-run, scope-listed callback already configured as "
        "rules_of_engagement.ssrf_callback_url; this framework never hosts the listener itself."),
}
