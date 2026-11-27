"""The facts that would justify testing a hypothesis again.

An inconclusive test must not simply be repeated: running the same probe against the same facts
yields the same inconclusive result and wastes request budget. A hypothesis therefore remembers a
*fingerprint* of the relevant context when it is attempted, and becomes eligible for another
attempt only if that fingerprint has changed — e.g. an operator has since declared who owns the
object, a role was granted, a new parameter or identity was observed.

The fingerprint deliberately covers only *structural and authorization* facts around the target.
It excludes everything the planner itself writes while working (``TARGETS`` / ``SUPPORTS`` /
``VALIDATED_BY`` edges, hypothesis and evidence nodes), otherwise every attempt would change its
own fingerprint and look like new information.
"""
from __future__ import annotations

import hashlib
import json

STRUCTURAL_EDGES = frozenset({
    "BELONGS_TO", "CAN_ACCESS", "HAS_ROLE", "HAS_PERMISSION", "REFERENCES", "RETURNS", "ACCEPTS",
    "OBSERVED_ACCESS", "INVOKES", "DEPENDS_ON", "CROSSES", "AUTHENTICATES_WITH", "USES",
})


def _other_end(graph, edge, anchor_id):
    other_id = edge["dst"] if edge["src"] == anchor_id else edge["src"]
    other = graph.get_node_by_id(other_id)
    direction = "out" if edge["src"] == anchor_id else "in"
    return [edge["edge_type"], direction, other["node_type"] if other else None,
            other["key"] if other else other_id, edge["trust"]]


def hypothesis_context(graph, hypothesis: dict) -> list:
    facts: list = []
    target_id = hypothesis.get("target_node_id")
    target = graph.get_node_by_id(target_id) if target_id else None
    if target is not None:
        facts.append(["target", target["node_type"], target["key"], target["trust"],
                      json.dumps(target["attributes"], sort_keys=True, default=str)])
        incident = graph.edges(src_id=target_id) + graph.edges(dst_id=target_id)
        for edge in incident:
            if edge["edge_type"] in STRUCTURAL_EDGES:
                facts.append(_other_end(graph, edge, target_id))
        # who owns the objects this target refers to is exactly what ownership-dependent tests need
        for edge in graph.edges("REFERENCES", src_id=target_id) + graph.edges("RETURNS", src_id=target_id):
            obj = graph.get_node_by_id(edge["dst"])
            for owner_edge in graph.edges("BELONGS_TO", src_id=edge["dst"]):
                facts.append(["owner", obj["key"] if obj else edge["dst"], *_other_end(graph, owner_edge, edge["dst"])])
    identity_key = hypothesis.get("required_identity")
    if identity_key:
        identity = graph.get_node("identity", identity_key) or graph.get_node("user", identity_key)
        if identity is not None:
            for edge in graph.edges("HAS_ROLE", src_id=identity["node_id"]):
                facts.append(["identity-role", identity_key, *_other_end(graph, edge, identity["node_id"])])
    return sorted(facts, key=lambda item: json.dumps(item, sort_keys=True, default=str))


def fingerprint(graph, hypothesis: dict) -> str:
    material = json.dumps(hypothesis_context(graph, hypothesis), sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
