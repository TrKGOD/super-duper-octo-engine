"""Evidence-driven candidate generation.

Derives testable hypotheses from what the graph actually shows, so tests are selected by
context rather than sprayed. Attack-path proposals (BOLA/BFLA) become hypotheses; per-
endpoint families are generated only when the enabling evidence exists (a parameter for
injection, an object reference or dynamic id for IDOR, a URL-like parameter for SSRF).

An external proposer (e.g. an LLM) can supply additional candidates via
``candidate_from_proposal``; they flow through the same deterministic policy and scoring,
so a proposal can never widen scope or authorization.
"""
from __future__ import annotations

from core.graph.paths import propose_attack_paths
from core.graph.store import AttackGraph
from core.planner.hypothesis import Hypothesis

FAMILIES = {
    "idor_bola": {"test_class": "web-authorization-idor", "skill": "web-authorization-idor", "risk": "high"},
    "bfla": {"test_class": "web-authorization-bac", "skill": "web-authorization-bac", "risk": "high"},
    "sqli": {"test_class": "web-sqli", "skill": "web-sqli", "risk": "high"},
    "xss": {"test_class": "web-xss", "skill": "web-xss", "risk": "medium"},
    "ssrf": {"test_class": "web-ssrf", "skill": "web-ssrf", "risk": "high"},
}

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SSRF_HINTS = ("url", "uri", "callback", "webhook", "redirect", "next", "dest", "target", "link", "fetch", "feed")


def _is_state_changing(endpoint: dict) -> bool:
    attrs = endpoint.get("attributes", {})
    return str(attrs.get("method", "GET")).upper() in _STATE_CHANGING_METHODS or bool(attrs.get("state_changing"))


def _accessing_identity(graph: AttackGraph, endpoint_id: str) -> str | None:
    for edge_type in ("CAN_ACCESS", "OBSERVED_ACCESS"):
        for edge in graph.edges(edge_type, dst_id=endpoint_id):
            node = graph.get_node_by_id(edge["src"])
            if node and node["node_type"] in ("identity", "user"):
                return node["key"]
    return None


def _endpoint_parameters(graph: AttackGraph, endpoint_id: str) -> list[dict]:
    params = []
    for edge in graph.edges("ACCEPTS", src_id=endpoint_id):
        node = graph.get_node_by_id(edge["dst"])
        if node:
            params.append(node)
    return params


def _hyp(engagement_id, category, endpoint, *, required_identity=None, proposed_test, expected,
         supporting=(), state_changing=False, confidence=0.2, preconditions=()):
    meta = FAMILIES[category]
    return Hypothesis(
        engagement_id=engagement_id, category=category, test_class=meta["test_class"],
        skill=meta["skill"], risk=meta["risk"], target_node_id=endpoint["node_id"],
        target_label=endpoint.get("label") or endpoint.get("key"),
        required_identity=required_identity, proposed_test=proposed_test, expected_outcomes=expected,
        supporting_evidence=list(supporting), state_changing=state_changing, confidence=confidence,
        preconditions=list(preconditions))


def generate_candidates(graph: AttackGraph, engagement_id: str) -> list[Hypothesis]:
    candidates: list[Hypothesis] = []

    # 1. Attack-path proposals (BOLA / BFLA), grounded in graph evidence.
    for path in propose_attack_paths(graph):
        if path["category"] == "cross_identity_object_access":
            endpoint_key = path["intermediate"][0]["endpoint"]
            endpoint = graph.get_node("endpoint", endpoint_key) or graph.get_node("route", endpoint_key)
            if endpoint is None:
                continue
            candidates.append(_hyp(
                engagement_id, "idor_bola", endpoint,
                required_identity=path["start"]["identity"],
                proposed_test=path["proposed_test"], expected=path["expected_observation"],
                supporting=path["supporting_evidence"], state_changing=_is_state_changing(endpoint),
                confidence=path["confidence"],
                preconditions=[f"object {path['target'].get('object')} owned by {path['target'].get('owner')}"]))
        elif path["category"] == "function_level_privilege_escalation":
            endpoint_key = path["target"]["endpoint"]
            endpoint = graph.get_node("endpoint", endpoint_key) or graph.get_node("route", endpoint_key)
            if endpoint is None:
                continue
            candidates.append(_hyp(
                engagement_id, "bfla", endpoint,
                required_identity=path["start"]["identity"],
                proposed_test=path["proposed_test"], expected=path["expected_observation"],
                supporting=path["supporting_evidence"], state_changing=_is_state_changing(endpoint),
                confidence=path["confidence"],
                preconditions=[f"restricted to role {path['target'].get('restricted_to_role')}"]))

    # 2. Per-endpoint families, gated by the evidence that makes each test meaningful.
    for endpoint in graph.nodes("endpoint"):
        eid = endpoint["node_id"]
        params = _endpoint_parameters(graph, eid)
        identity = _accessing_identity(graph, eid)
        state_changing = _is_state_changing(endpoint)
        attrs = endpoint.get("attributes", {})
        path_text = str(attrs.get("path", endpoint.get("label", "")))

        if params:
            names = ", ".join(sorted(p.get("label") or p["key"] for p in params))
            candidates.append(_hyp(
                engagement_id, "sqli", endpoint, required_identity=identity,
                proposed_test=f"Send non-destructive SQL-injection probes to parameters [{names}] of {endpoint['key']}.",
                expected="Differential or error behavior indicating unsafe query construction.",
                supporting=[f"endpoint accepts parameters: {names}"], state_changing=False, confidence=0.25))
            candidates.append(_hyp(
                engagement_id, "xss", endpoint, required_identity=identity,
                proposed_test=f"Probe parameters [{names}] of {endpoint['key']} for reflected/stored XSS with browser evidence.",
                expected="Injected marker reaches an executable sink.",
                supporting=[f"endpoint accepts parameters: {names}"], state_changing=False, confidence=0.2))
            for param in params:
                name = str(param.get("label") or param["key"]).lower()
                if any(hint in name for hint in _SSRF_HINTS):
                    candidates.append(_hyp(
                        engagement_id, "ssrf", endpoint, required_identity=identity,
                        proposed_test=f"Test URL-like parameter '{param.get('label')}' of {endpoint['key']} for SSRF with out-of-band/destination checks.",
                        expected="Server issues a request to an operator-controlled destination.",
                        supporting=[f"url-like parameter: {param.get('label')}"],
                        state_changing=state_changing, confidence=0.3))

        references_object = bool(graph.edges("REFERENCES", src_id=eid))
        if references_object or "{id}" in path_text:
            candidates.append(_hyp(
                engagement_id, "idor_bola", endpoint, required_identity=identity,
                proposed_test=f"As an authorized identity, vary the object identifier in {endpoint['key']} to another identity's object.",
                expected="Access to an object the identity does not own (broken object-level authorization).",
                supporting=["endpoint references an object or carries a dynamic id"],
                state_changing=state_changing, confidence=0.3))

    return candidates


def candidate_from_proposal(engagement_id: str, proposal: dict) -> Hypothesis:
    """Build a hypothesis from an external (e.g. LLM) proposal. Still subject to policy."""
    category = proposal.get("category")
    if category not in FAMILIES:
        from core.planner.hypothesis import PlannerError
        raise PlannerError("Unknown hypothesis category: " + str(category))
    meta = FAMILIES[category]
    return Hypothesis(
        engagement_id=engagement_id, category=category, test_class=meta["test_class"], skill=meta["skill"],
        risk=meta["risk"], target_node_id=proposal.get("target_node_id"),
        target_label=proposal.get("target_label"), required_identity=proposal.get("required_identity"),
        proposed_test=proposal.get("proposed_test", "operator-defined test"),
        expected_outcomes=proposal.get("expected_outcomes"),
        supporting_evidence=list(proposal.get("supporting_evidence", [])),
        state_changing=bool(proposal.get("state_changing")), confidence=float(proposal.get("confidence", 0.2)))
