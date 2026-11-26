"""Knowledge Graph integration (Component B).

Projects Knowledge Base patterns and their taxonomy references into the **existing**
engagement attack graph (`core/graph/`) as knowledge nodes and edges, so the system can
answer "which known patterns apply to this endpoint / technology / vulnerability class?" and
"which tools test for this class?".

The graph's trust boundary is preserved and never weakened: every knowledge node/edge is
written with `inferred` (or, for operator-registered tool capabilities, `observed`) trust and
carries provenance. The bridge creates **only** knowledge node/edge types — never an
identity, role, permission, or any authorization edge — so untrusted KB content can never
grant authorization. The store's `ensure_authorization_trust` still rejects any authorization
edge below control-plane trust, independently of this module.
"""
from __future__ import annotations

from core.graph.schema import GraphError
from core.graph.store import AttackGraph

_REF_NODE_TYPE = {"cwe": "cwe", "cve": "cve", "capec": "capec", "owasp": "owasp", "attack": "attack_technique"}
_CONFIDENCE = {"high": 0.6, "medium": 0.4, "low": 0.2}


class KnowledgeGraphError(GraphError):
    pass


def vulnerability_class_key(vulnerability_type: str) -> str:
    return str(vulnerability_type).strip().lower().replace(" ", "_").replace("/", "_")


class KnowledgeGraphBridge:
    def __init__(self, graph: AttackGraph, kb_db, *, source: str = "knowledge-base"):
        self.graph = graph
        self.kb = kb_db
        self.source = source

    def _prov(self, extra: dict | None = None) -> list:
        entry = {"source": self.source}
        if extra:
            entry.update(extra)
        return [entry]

    def _has_references_table(self) -> bool:
        return self.kb.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='kb_references'").fetchone() is not None

    def ingest_pattern(self, pattern_id: str, *, endpoint_node_id: str | None = None,
                       technology: str | None = None) -> dict:
        """Project one KB pattern into the graph. Returns counts of what was created."""
        row = self.kb.execute("SELECT * FROM kb_patterns WHERE pattern_id=?", (pattern_id,)).fetchone()
        if row is None:
            raise KnowledgeGraphError("Unknown KB pattern: " + str(pattern_id))
        document_id = row["document_id"]
        prov = self._prov({"document_id": document_id, "pattern_id": pattern_id})
        confidence = _CONFIDENCE.get(str(row["confidence"]).strip().lower(), 0.3)

        pattern_node = self.graph.upsert_node(
            "knowledge_pattern", pattern_id, label=row["vulnerability_type"],
            attributes={"domain": row["domain"]}, trust="inferred", provenance=prov, confidence=confidence)
        created = {"pattern": pattern_node, "references": 0, "links": 0}

        vclass = vulnerability_class_key(row["vulnerability_type"])
        vclass_node = self.graph.upsert_node("vulnerability_class", vclass, label=row["vulnerability_type"],
                                             trust="inferred", provenance=prov)
        self.graph.upsert_edge(pattern_node, "DESCRIBES", vclass_node, trust="inferred", provenance=prov)

        technology_node = None
        if technology:
            technology_node = self.graph.upsert_node("technology", str(technology), trust="inferred", provenance=prov)

        references = (self.kb.execute(
            "SELECT ref_type, ref_value FROM kb_references WHERE document_id=? ORDER BY ref_type, ref_value",
            (document_id,)).fetchall() if self._has_references_table() else [])
        for ref in references:
            node_type = _REF_NODE_TYPE.get(ref["ref_type"])
            if node_type is None:
                continue
            ref_node = self.graph.upsert_node(node_type, ref["ref_value"], trust="inferred", provenance=prov)
            self.graph.upsert_edge(pattern_node, "REFERENCES_WEAKNESS", ref_node, trust="inferred", provenance=prov)
            created["references"] += 1
            if technology_node and node_type in ("cwe", "capec", "attack_technique"):
                self.graph.upsert_edge(ref_node, "APPLIES_TO", technology_node, trust="inferred", provenance=prov)

        if endpoint_node_id and self.graph.get_node_by_id(endpoint_node_id):
            self.graph.upsert_edge(pattern_node, "RELEVANT_TO", endpoint_node_id, trust="inferred", provenance=prov)
            created["links"] += 1
        if technology_node:
            self.graph.upsert_edge(pattern_node, "RELEVANT_TO", technology_node, trust="inferred", provenance=prov)
            created["links"] += 1
        return created

    def register_tool(self, tool_id: str, vulnerability_classes, *, provenance_source: str = "operator") -> str:
        """Record an operator-declared tool capability (which classes a tool tests for)."""
        prov = [{"source": provenance_source}]
        tool_node = self.graph.upsert_node("tool", tool_id, trust="observed", provenance=prov, confidence=0.8)
        for vclass in vulnerability_classes:
            key = vulnerability_class_key(vclass)
            vnode = self.graph.upsert_node("vulnerability_class", key, label=str(vclass),
                                           trust="inferred", provenance=prov)
            self.graph.upsert_edge(tool_node, "TESTS_FOR", vnode, trust="observed", provenance=prov)
        return tool_node


# -- graph-assisted knowledge queries ------------------------------------
def _sources(graph: AttackGraph, edge_type: str, dst_id: str, node_type: str | None = None) -> list[dict]:
    result = []
    for edge in graph.edges(edge_type, dst_id=dst_id):
        node = graph.get_node_by_id(edge["src"])
        if node and (node_type is None or node["node_type"] == node_type):
            result.append(node)
    return sorted(result, key=lambda n: n["key"])


def patterns_for_endpoint(graph: AttackGraph, endpoint_node_id: str) -> list[dict]:
    return _sources(graph, "RELEVANT_TO", endpoint_node_id, node_type="knowledge_pattern")


def patterns_for_technology(graph: AttackGraph, technology: str) -> list[dict]:
    return _sources(graph, "RELEVANT_TO", graph.node_id("technology", str(technology)),
                    node_type="knowledge_pattern")


def patterns_for_vulnerability_class(graph: AttackGraph, vulnerability_type: str) -> list[dict]:
    vnode = graph.node_id("vulnerability_class", vulnerability_class_key(vulnerability_type))
    return _sources(graph, "DESCRIBES", vnode, node_type="knowledge_pattern")


def tools_for_vulnerability_class(graph: AttackGraph, vulnerability_type: str) -> list[dict]:
    vnode = graph.node_id("vulnerability_class", vulnerability_class_key(vulnerability_type))
    return _sources(graph, "TESTS_FOR", vnode, node_type="tool")


def weaknesses_of_pattern(graph: AttackGraph, pattern_id: str) -> list[dict]:
    pnode = graph.node_id("knowledge_pattern", pattern_id)
    result = []
    for edge in graph.edges("REFERENCES_WEAKNESS", src_id=pnode):
        node = graph.get_node_by_id(edge["dst"])
        if node:
            result.append({"type": node["node_type"], "value": node["key"]})
    return sorted(result, key=lambda item: (item["type"], item["value"]))
