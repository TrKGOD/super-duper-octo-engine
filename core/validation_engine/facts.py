"""Control-plane facts the validator may rely on.

Some oracle outcomes depend on a fact that is *policy, not observation*: "this object belongs to
identity A", "this function is restricted to role R". Those facts must never be taken from the
party that proposed the finding. :class:`GraphFacts` reads them from the engagement graph and
returns a fact only if it was asserted at ``control_plane`` trust (operator-declared); anything
observed, inferred, ambiguous or missing is *not* a fact and yields ``None`` / ``False``, which
keeps the oracle inconclusive rather than letting an unverified claim confirm a finding.
"""
from __future__ import annotations

from core.graph.store import AttackGraph

_ENDPOINT_TYPES = ("endpoint", "route")


class GraphFacts:
    def __init__(self, graph: AttackGraph):
        self.graph = graph

    def _control_plane(self, node_id: str) -> dict | None:
        node = self.graph.get_node_by_id(node_id)
        return node if node is not None and node["trust"] == "control_plane" else None

    def object_owner(self, object_key: str) -> str | None:
        """The single identity the operator declared as owner of ``object_key``, else ``None``."""
        node = self.graph.get_node("object", object_key)
        if node is None or node["trust"] != "control_plane":
            return None
        owners = [edge for edge in self.graph.edges("BELONGS_TO", src_id=node["node_id"])
                  if edge["trust"] == "control_plane"]
        if len(owners) != 1:                       # undeclared or ambiguous ownership is not a fact
            return None
        owner = self._control_plane(owners[0]["dst"])
        return owner["key"] if owner else None

    def role_restriction(self, function_key: str, restricted_to_role: str, excluded_role: str) -> bool:
        """True iff the operator declared the function reachable by ``restricted_to_role`` and
        *not* by ``excluded_role``."""
        endpoint = next((self.graph.get_node(t, function_key) for t in _ENDPOINT_TYPES
                         if self.graph.get_node(t, function_key) is not None), None)
        if endpoint is None:
            return False
        granted = {self.graph.get_node_by_id(edge["src"])["key"]
                   for edge in self.graph.edges("CAN_ACCESS", dst_id=endpoint["node_id"])
                   if edge["trust"] == "control_plane"
                   and self.graph.get_node_by_id(edge["src"]) is not None
                   and self.graph.get_node_by_id(edge["src"])["node_type"] == "role"}
        return restricted_to_role in granted and excluded_role not in granted
