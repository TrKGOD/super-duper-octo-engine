"""Safe, read-only query interface over the attack graph for agents and the planner.

Every query is engagement-scoped (the underlying :class:`AttackGraph` only ever sees one
engagement). Results are facts with provenance; they are inputs to test selection, not
findings.
"""
from __future__ import annotations

from core.graph.store import AttackGraph

_REACH_EDGES = ("CAN_ACCESS", "OBSERVED_ACCESS")


class GraphQuery:
    def __init__(self, graph: AttackGraph):
        self.graph = graph

    def _identity_id(self, identity_key: str, user: bool = False) -> str:
        return self.graph.node_id("user" if user else "identity", identity_key)

    def endpoints_for_object(self, object_key: str) -> list[dict]:
        obj_id = self.graph.node_id("object", object_key)
        if self.graph.get_node_by_id(obj_id) is None:
            return []
        endpoints = {}
        for edge_type in ("REFERENCES", "RETURNS"):
            for edge in self.graph.edges(edge_type, dst_id=obj_id):
                node = self.graph.get_node_by_id(edge["src"])
                if node:
                    endpoints[node["node_id"]] = node
        return sorted(endpoints.values(), key=lambda n: n["key"])

    def endpoints_for_identity(self, identity_key: str, *, user: bool = False) -> list[dict]:
        iid = self._identity_id(identity_key, user)
        if self.graph.get_node_by_id(iid) is None:
            return []
        reachable = {}
        for edge_type in _REACH_EDGES:
            for edge in self.graph.edges(edge_type, src_id=iid):
                node = self.graph.get_node_by_id(edge["dst"])
                if node:
                    reachable[node["node_id"]] = {**node, "via": edge_type}
        return sorted(reachable.values(), key=lambda n: n["key"])

    def objects_referenced_by_multiple_endpoints(self) -> list[dict]:
        result = []
        for obj in self.graph.nodes("object"):
            referrers = set()
            for edge_type in ("REFERENCES", "RETURNS"):
                for edge in self.graph.edges(edge_type, dst_id=obj["node_id"]):
                    referrers.add(edge["src"])
            if len(referrers) > 1:
                result.append({"object": obj["key"], "endpoint_count": len(referrers)})
        return sorted(result, key=lambda item: (-item["endpoint_count"], item["object"]))

    def workflows_using_endpoint(self, endpoint_key: str, *, node_type: str = "endpoint") -> list[dict]:
        target_id = self.graph.node_id(node_type, endpoint_key)
        if self.graph.get_node_by_id(target_id) is None:
            return []
        workflows = {}
        for edge in self.graph.edges("INVOKES", dst_id=target_id):
            node = self.graph.get_node_by_id(edge["src"])
            if node:
                workflows[node["node_id"]] = node
        return sorted(workflows.values(), key=lambda n: n["key"])

    def hypotheses_without_validation(self) -> list[dict]:
        result = []
        for hypothesis in self.graph.nodes("hypothesis"):
            supported = self.graph.edges("SUPPORTS", dst_id=hypothesis["node_id"])
            validated = self.graph.edges("VALIDATED_BY", src_id=hypothesis["node_id"])
            if not supported and not validated:
                result.append(hypothesis)
        return sorted(result, key=lambda n: n["key"])

    def low_coverage_endpoints(self) -> list[dict]:
        """Endpoints not yet targeted by any hypothesis or finding (test-coverage gaps)."""
        result = []
        for endpoint in self.graph.nodes("endpoint"):
            targeted = self.graph.edges("TARGETS", dst_id=endpoint["node_id"])
            if not targeted:
                result.append(endpoint)
        return sorted(result, key=lambda n: n["key"])

    def identity_access_differences(self, a_key: str, b_key: str, *,
                                    a_user: bool = False, b_user: bool = False) -> dict:
        a_reach = {node["key"] for node in self.endpoints_for_identity(a_key, user=a_user)}
        b_reach = {node["key"] for node in self.endpoints_for_identity(b_key, user=b_user)}
        return {
            "identity_a": a_key,
            "identity_b": b_key,
            "only_a": sorted(a_reach - b_reach),
            "only_b": sorted(b_reach - a_reach),
            "shared": sorted(a_reach & b_reach),
            "note": "Reachability differences are observations for access-control analysis, "
                    "not confirmed authorization findings.",
        }
