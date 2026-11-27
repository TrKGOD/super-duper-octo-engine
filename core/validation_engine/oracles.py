"""Deterministic validation oracles, one per vulnerability class.

Each oracle maps observed evidence to a disposition using a deterministic rule, not the
proposer's claim and not "the payload was accepted". Where a sound analyzer already exists
it is reused (object/function authorization, SQLi differential); reflected-input and
security-header oracles are added here. Every oracle returns
``{"disposition", "explanation", "comparison"}``.
"""
from __future__ import annotations

import html
import re

from core.authorization_testing import compare_function_access, compare_object_access
from core.protocol_testing import analyze_sqli_pair
from core.validation_engine.records import INCONCLUSIVE, REFUTED, SUPPORTED


class OracleError(ValueError):
    pass


def evidence_request(kind: str, reason: str, **detail) -> dict:
    """A structured statement of what further evidence would settle an inconclusive result.

    The planner turns these into follow-up work *only when the facts they ask for change*, so
    an inconclusive test is never simply repeated.
    """
    return {"kind": kind, "reason": reason, "detail": detail}


def object_authorization(request: dict) -> dict:
    """BOLA/IDOR: reuse the object-access comparison; access by a non-owner confirms it."""
    comparison = compare_object_access(
        request["owner_response"], request["other_response"],
        owner_identity=request["owner_identity"], other_identity=request["other_identity"],
        object_reference=request["object_reference"])
    classification = comparison["classification"]
    ownership_confirmed = bool(request.get("ownership_confirmed"))
    requests: list = []
    if classification == "potential_bola_same_object_representation":
        disposition = SUPPORTED
        explanation = ("A non-owner identity received the owner's exact normalized object "
                       "representation — broken object-level authorization.")
    elif classification == "potential_bola_access_granted" and ownership_confirmed:
        disposition = SUPPORTED
        explanation = ("A non-owner identity received a successful response for an object "
                       "confirmed to belong to another identity.")
    elif classification == "potential_bola_access_granted":
        disposition = INCONCLUSIVE
        explanation = ("A non-owner received a success response, but object ownership was not "
                       "confirmed (could be public or shared); confirm ownership to validate.")
        requests = [evidence_request(
            "confirm_object_ownership", "ownership of the object is not declared by the control plane",
            object=request["object_reference"], owner_identity=request["owner_identity"])]
    elif classification == "access_denial_observed":
        disposition = REFUTED
        explanation = "The non-owner identity was denied; object-level authorization held."
    else:
        disposition = INCONCLUSIVE
        explanation = comparison.get("rationale", "The comparison did not establish an authorization decision.")
        kind = {"inconclusive_truncated_response": "retest_with_complete_response",
                "invalid_owner_baseline": "establish_valid_owner_baseline"}.get(classification, "additional_comparison")
        requests = [evidence_request(kind, comparison.get("rationale", explanation),
                                     object=request["object_reference"])]
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison,
            "evidence_requests": requests}


def function_authorization(request: dict) -> dict:
    """BFLA: reuse the function-access comparison across approved roles."""
    comparison = compare_function_access(
        request["baseline_response"], request["lower_privilege_response"],
        baseline_role=request["baseline_role"], comparison_role=request["comparison_role"],
        function_reference=request["function_reference"])
    classification = comparison["classification"]
    policy_confirms_restriction = bool(request.get("role_restriction_confirmed"))
    requests: list = []
    if classification == "potential_function_level_authorization_gap" and policy_confirms_restriction:
        disposition = SUPPORTED
        explanation = ("A lower-privilege role invoked a function documented as restricted — "
                       "broken function-level authorization.")
    elif classification == "potential_function_level_authorization_gap":
        disposition = INCONCLUSIVE
        explanation = ("A lower-privilege role received success, but the function's role "
                       "restriction was not confirmed; confirm the policy to validate.")
        requests = [evidence_request(
            "confirm_function_role_restriction", "the control plane does not declare the function restricted",
            function=request["function_reference"], role=request["baseline_role"])]
    elif classification == "access_denial_observed":
        disposition = REFUTED
        explanation = "The lower-privilege role was denied; function-level authorization held."
    else:
        disposition = INCONCLUSIVE
        explanation = comparison.get("rationale", "The role comparison was inconclusive.")
        requests = [evidence_request("additional_comparison", explanation, function=request["function_reference"])]
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison,
            "evidence_requests": requests}


def sqli(request: dict) -> dict:
    """SQL injection: reuse the differential analyzer; a boolean differential validates."""
    comparison = analyze_sqli_pair(request["samples"])
    requests: list = []
    if comparison["boolean_pair_differs"]:
        disposition = SUPPORTED
        explanation = ("True/false payloads produced a reproducible, controlled response "
                       "difference consistent with SQL injection (no data extracted).")
    elif comparison["findings"]:
        disposition = INCONCLUSIVE
        explanation = ("A SQL signal was observed (error string or timing) but no reproducible "
                       "boolean differential; gather controlled samples before confirming.")
        requests = [evidence_request("additional_controlled_samples", explanation,
                                     signals=list(comparison["findings"]))]
    else:
        disposition = REFUTED
        explanation = "No SQL-injection signal was established across the samples."
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison,
            "evidence_requests": requests}


# "unknown" is deliberately NOT executable: a marker found somewhere in a body is not evidence
# that it can execute, so an unestablished context is inconclusive, never a confirmation.
_EXECUTABLE_CONTEXTS = {"html_body", "html_attribute", "script"}


def reflected_input(request: dict) -> dict:
    """Reflected XSS: a unique marker must appear UN-encoded in an executable context."""
    marker = str(request.get("marker", "")).strip()
    body = str(request.get("response_body", ""))
    context = str(request.get("context", "unknown"))
    if not marker:
        raise OracleError("reflected_input requires a unique marker")
    present = marker in body
    encoded_present = (html.escape(marker) in body) or (re.sub(r"[<>\"'&]", "", marker) in body and not present)
    comparison = {"marker_present_raw": present, "encoded_form_present": encoded_present, "context": context}
    requests: list = []
    if present and context in _EXECUTABLE_CONTEXTS:
        disposition = SUPPORTED
        explanation = f"The marker was reflected unencoded in an executable context ({context})."
    elif not present and encoded_present:
        disposition = REFUTED
        explanation = "The marker was reflected only in an encoded/escaped form; output is sanitized."
    elif not present:
        disposition = REFUTED
        explanation = "The marker was not reflected in the response."
    else:
        disposition = INCONCLUSIVE
        explanation = "The marker was reflected but the sink context does not establish execution."
        requests = [evidence_request("determine_execution_context", explanation, observed_context=context)]
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison,
            "evidence_requests": requests}


_SECURITY_HEADERS = {
    "content-security-policy", "strict-transport-security", "x-content-type-options",
    "referrer-policy", "permissions-policy", "x-frame-options",
}


def security_header(request: dict) -> dict:
    """Security misconfiguration: a required header is absent (deterministic, low severity)."""
    headers = {str(k).lower() for k in (request.get("response_headers") or {})}
    required = str(request.get("required_header", "")).lower()
    if required not in _SECURITY_HEADERS:
        raise OracleError("security_header requires a known required_header")
    comparison = {"required_header": required, "present": required in headers,
                  "observed_security_headers": sorted(headers & _SECURITY_HEADERS)}
    if required in headers:
        disposition = REFUTED
        explanation = f"The required security header '{required}' is present."
    else:
        disposition = SUPPORTED
        explanation = f"The required security header '{required}' is absent (misconfiguration)."
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison}


ORACLES = {
    "object_authorization": object_authorization,
    "function_authorization": function_authorization,
    "sqli": sqli,
    "reflected_input": reflected_input,
    "security_header": security_header,
}
