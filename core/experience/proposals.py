"""Turn validated experience into *investigative leads* for the adaptive planner.

A past, independently validated finding is useful prior knowledge: "endpoints shaped like this
were broken in a previous engagement". It is **never**

* evidence that the current target is vulnerable (a proposal carries no evidence at all),
* a reason to skip validation (a proposal is just another hypothesis: same deterministic policy,
  same scoring, same independent validator),
* authorization (it creates no identity, role, scope or access edge), or
* a way to import another engagement's data (only categories and route shapes are used; the source
  engagement's evidence ids, identities and values are never copied).

Confidence is capped well below what a fresh observation earns, so a lead cannot out-rank
current-engagement evidence in the planner's transparent scoring.
"""
from __future__ import annotations

from core.graph.store import AttackGraph

# validation-engine vulnerability class (as stored in experience) -> planner hypothesis category
CATEGORY_MAP = {
    "object_authorization": "idor_bola",
    "function_authorization": "bfla",
    "sqli": "sqli",
    "reflected_input": "xss",
}
LEAD_CONFIDENCE_CAP = 0.3
_READ = ("GET", "HEAD")


def _accessing_identity(graph: AttackGraph, endpoint_id: str):
    for edge_type in ("CAN_ACCESS", "OBSERVED_ACCESS"):
        for edge in graph.edges(edge_type, dst_id=endpoint_id):
            node = graph.get_node_by_id(edge["src"])
            if node and node["node_type"] in ("identity", "user"):
                return node["key"]
    return None


def propose_from_experience(experience_store, graph: AttackGraph, engagement_id: str, *,
                            limit_per_category: int = 3) -> list[dict]:
    """Return planner proposals (``AdaptivePlanner.add_proposals`` input) grounded in prior experience."""
    proposals: list[dict] = []
    endpoints = graph.nodes("endpoint")
    for vulnerability_class, category in CATEGORY_MAP.items():
        experiences = [e for e in experience_store.search(category=vulnerability_class, limit=limit_per_category * 4)
                       if e["source_engagement_id"] != engagement_id][:limit_per_category]
        for experience in experiences:
            template = (experience["endpoint_characteristics"] or {}).get("path_template")
            if not template:
                continue                      # no route shape to match: it is not a usable lead
            for endpoint in endpoints:
                attrs = endpoint["attributes"]
                if attrs.get("path") != template or str(attrs.get("method", "GET")).upper() not in _READ:
                    continue
                proposals.append({
                    "category": category,
                    "target_node_id": endpoint["node_id"],
                    "target_label": endpoint["label"] or endpoint["key"],
                    "required_identity": _accessing_identity(graph, endpoint["node_id"]),
                    "proposed_test": (f"Re-test, within this engagement's scope, the pattern independently validated "
                                      f"in a previous engagement ({experience['experience_id']}): "
                                      f"{experience['execution_methodology'] or 'see experience record'}"),
                    "expected_outcomes": experience["expected_behavior"],
                    # A lead is NOT evidence: nothing goes in supporting_evidence.
                    "supporting_evidence": [],
                    "state_changing": False,
                    "confidence": min(float(experience["confidence"]), LEAD_CONFIDENCE_CAP),
                })
    return proposals
