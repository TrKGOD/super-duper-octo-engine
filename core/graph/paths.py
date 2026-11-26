"""Attack-path reasoning over the graph.

Generic traversal plus concrete, evidence-grounded pattern detectors (cross-identity
object access / BOLA-IDOR, and function-level privilege escalation / BFLA). Proposed
paths are **hypotheses for the planner**, never confirmed findings and never executed
here. They only reference entities already in the graph, so reasoning cannot broaden
scope or invent identities.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.graph.store import AttackGraph


@dataclass
class AttackPath:
    category: str
    start: dict
    target: dict
    intermediate: list
    relationship_explanations: list
    supporting_evidence: list
    missing_evidence: list
    required_authorization: list
    proposed_test: str
    expected_observation: str
    risk: str
    confidence: float = 0.3

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "start": self.start,
            "target": self.target,
            "intermediate": self.intermediate,
            "relationship_explanations": self.relationship_explanations,
            "supporting_evidence": self.supporting_evidence,
            "missing_evidence": self.missing_evidence,
            "required_authorization": self.required_authorization,
            "proposed_test": self.proposed_test,
            "expected_observation": self.expected_observation,
            "risk": self.risk,
            "confidence": self.confidence,
            "status": "hypothesis",
            "note": "Proposed attack path is an evidence-motivated hypothesis, not a confirmed finding.",
        }


def find_paths(graph: AttackGraph, start_id: str, target_id: str, *, max_depth: int = 6,
               edge_types=None) -> list[list[dict]]:
    """Breadth-first enumeration of simple (acyclic) edge paths from start to target."""
    if graph.get_node_by_id(start_id) is None or graph.get_node_by_id(target_id) is None:
        return []
    results: list[list[dict]] = []
    queue = [(start_id, [], {start_id})]
    while queue:
        current, path, visited = queue.pop(0)
        if len(path) >= max_depth:
            continue
        for link in graph.neighbors(current, direction="out"):
            edge, node = link["edge"], link["node"]
            if edge_types and edge["edge_type"] not in edge_types:
                continue
            if node["node_id"] in visited:
                continue
            new_path = path + [edge]
            if node["node_id"] == target_id:
                results.append(new_path)
            else:
                queue.append((node["node_id"], new_path, visited | {node["node_id"]}))
    return results


def _identity_nodes(graph: AttackGraph) -> list[dict]:
    return graph.nodes("identity") + graph.nodes("user")


def _access_edges(graph: AttackGraph, identity_id: str) -> list[dict]:
    edges = graph.edges("OBSERVED_ACCESS", src_id=identity_id) + graph.edges("CAN_ACCESS", src_id=identity_id)
    return edges


def _has_role(graph: AttackGraph, identity_id: str, role_id: str) -> bool:
    return any(edge["dst"] == role_id for edge in graph.edges("HAS_ROLE", src_id=identity_id))


def detect_cross_identity_object_access(graph: AttackGraph) -> list[AttackPath]:
    """BOLA/IDOR: identity A reaches an endpoint that references an object owned by B != A."""
    paths: list[AttackPath] = []
    for actor in _identity_nodes(graph):
        for access in _access_edges(graph, actor["node_id"]):
            endpoint = graph.get_node_by_id(access["dst"])
            if endpoint is None or endpoint["node_type"] not in ("endpoint", "route"):
                continue
            ref_edges = graph.edges("REFERENCES", src_id=endpoint["node_id"]) + \
                graph.edges("RETURNS", src_id=endpoint["node_id"])
            for ref in ref_edges:
                obj = graph.get_node_by_id(ref["dst"])
                if obj is None:
                    continue
                for owns in graph.edges("BELONGS_TO", src_id=obj["node_id"]):
                    owner = graph.get_node_by_id(owns["dst"])
                    if owner is None or owner["node_id"] == actor["node_id"]:
                        continue
                    evidence = list(access.get("evidence_refs", [])) + list(ref.get("evidence_refs", []))
                    paths.append(AttackPath(
                        category="cross_identity_object_access",
                        start={"identity": actor["key"], "node_id": actor["node_id"]},
                        target={"object": obj["key"], "owner": owner["key"]},
                        intermediate=[{"endpoint": endpoint["key"]}],
                        relationship_explanations=[
                            f"identity '{actor['key']}' {access['edge_type']} endpoint '{endpoint['key']}'",
                            f"endpoint '{endpoint['key']}' {ref['edge_type']} object '{obj['key']}'",
                            f"object '{obj['key']}' BELONGS_TO identity '{owner['key']}'",
                        ],
                        supporting_evidence=evidence,
                        missing_evidence=[
                            f"confirmation that '{actor['key']}' actually receives or mutates "
                            f"'{owner['key']}'-owned object '{obj['key']}' via '{endpoint['key']}'"],
                        required_authorization=[actor["key"], owner["key"]],
                        proposed_test=(
                            f"As authorized identity '{actor['key']}', request '{endpoint['key']}' "
                            f"referencing object '{obj['key']}' owned by '{owner['key']}'."),
                        expected_observation=(
                            f"If vulnerable, '{actor['key']}' reads or modifies '{owner['key']}'-owned "
                            f"object '{obj['key']}' (broken object-level authorization)."),
                        risk="high",
                        confidence=0.4 if evidence else 0.3,
                    ))
    return paths


def detect_function_level_escalation(graph: AttackGraph) -> list[AttackPath]:
    """BFLA: identity reached an endpoint restricted to a role the identity does not hold."""
    paths: list[AttackPath] = []
    for actor in _identity_nodes(graph):
        observed = graph.edges("OBSERVED_ACCESS", src_id=actor["node_id"])
        for access in observed:
            endpoint = graph.get_node_by_id(access["dst"])
            if endpoint is None:
                continue
            # Roles explicitly authorized for this endpoint.
            for grant in graph.edges("CAN_ACCESS", dst_id=endpoint["node_id"]):
                role = graph.get_node_by_id(grant["src"])
                if role is None or role["node_type"] != "role":
                    continue
                if _has_role(graph, actor["node_id"], role["node_id"]):
                    continue
                paths.append(AttackPath(
                    category="function_level_privilege_escalation",
                    start={"identity": actor["key"], "node_id": actor["node_id"]},
                    target={"endpoint": endpoint["key"], "restricted_to_role": role["key"]},
                    intermediate=[{"role_required": role["key"]}],
                    relationship_explanations=[
                        f"endpoint '{endpoint['key']}' CAN_ACCESS restricted to role '{role['key']}'",
                        f"identity '{actor['key']}' does not HAS_ROLE '{role['key']}'",
                        f"identity '{actor['key']}' was OBSERVED_ACCESS on '{endpoint['key']}'",
                    ],
                    supporting_evidence=list(access.get("evidence_refs", [])),
                    missing_evidence=[
                        f"confirmation that '{actor['key']}' successfully performs the "
                        f"'{role['key']}'-restricted function at '{endpoint['key']}'"],
                    required_authorization=[actor["key"]],
                    proposed_test=(
                        f"As authorized identity '{actor['key']}' (which lacks role '{role['key']}'), "
                        f"invoke '{endpoint['key']}' and compare with a '{role['key']}' baseline."),
                    expected_observation=(
                        f"If vulnerable, '{actor['key']}' performs a '{role['key']}'-restricted "
                        f"function (broken function-level authorization)."),
                    risk="high",
                    confidence=0.4,
                ))
    return paths


def propose_attack_paths(graph: AttackGraph) -> list[dict]:
    paths = detect_cross_identity_object_access(graph) + detect_function_level_escalation(graph)
    return [path.to_dict() for path in paths]
