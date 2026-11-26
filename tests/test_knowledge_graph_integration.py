"""Knowledge Graph integration (Component B) tests.

Verifies that KB patterns project into the existing engagement graph as inferred knowledge
(nodes/edges with provenance), that the graph-assisted queries work, and — critically — that
knowledge content can never create an identity/role/permission or an authorization edge: the
graph's control-plane authorization boundary is preserved.
"""
import json
import tempfile
import unittest
from pathlib import Path

from scripts.migrate import migrate
from scripts.knowledge_base import connect, import_pattern, init_db
from core.store import StateStore
from core.graph import AttackGraph, GraphError, GraphIngestor
from core.knowledge import (KnowledgeGraphBridge, KnowledgeGraphError, ingest_content,
                           patterns_for_endpoint, patterns_for_technology,
                           patterns_for_vulnerability_class, tools_for_vulnerability_class,
                           weaknesses_of_pattern)

META = {"title": "BOLA writeup", "platform": "Fixture", "source_url": "https://example.org/b",
        "disclosure_status": "public", "rights_basis": "Fixture authored for this unit test.",
        "collected_at": "2026-11-26T00:00:00Z", "published_at": None, "content_type": "research_summary",
        "vulnerability_types": ["BOLA"], "technologies": ["REST API"], "asset_types": ["api"],
        "tags": ["authorization"], "author": None, "license": "CC0-1.0", "notes": None}

PATTERN = {"pattern_id": "PAT-G", "vulnerability_type": "BOLA",
           "root_cause": "Missing object-level authorization check.",
           "preconditions": ["Two synthetic identities"],
           "reproduction_summary": "Compare object access across two lab identities.",
           "evidence_summary": "Cross-identity object response observed in lab.",
           "impact": "Access to another tenant object.",
           "remediation": "Enforce server-side object authorization.",
           "false_positives": [], "confidence": "high", "source_spans": ["BOLA section"],
           "domain": "api", "tags": ["idor"]}


class BridgeTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.kb = connect(root / "kb.sqlite")
        init_db(self.kb)
        doc_id = ingest_content(self.kb, "BOLA object reference writeup; see CWE-639.", "text/plain", META)
        pattern_path = root / "pat.json"
        pattern_path.write_text(json.dumps({**PATTERN, "document_id": doc_id}), encoding="utf-8")
        import_pattern(self.kb, str(pattern_path))

        db = str(root / "state.sqlite3")
        migrate(db)
        self.store = StateStore(db)
        self.store.create_engagement("eng", "AUTH", {}, {}, status="active")
        self.graph = AttackGraph(self.store.connection, "eng")
        self.endpoint = GraphIngestor(self.graph).register_endpoint("GET", "https://app.local:443", "/api/orders/{id}")
        self.bridge = KnowledgeGraphBridge(self.graph, self.kb)

    def tearDown(self):
        try:
            self.store.close()
            self.kb.close()
        except Exception:
            pass
        self.tmp.cleanup()


class IngestionTests(BridgeTestBase):
    def test_pattern_projects_as_inferred_knowledge(self):
        created = self.bridge.ingest_pattern("PAT-G", endpoint_node_id=self.endpoint, technology="REST API")
        self.assertEqual(created["references"], 1)        # CWE-639
        self.assertEqual(created["links"], 2)             # endpoint + technology
        pattern = self.graph.get_node("knowledge_pattern", "PAT-G")
        self.assertEqual(pattern["trust"], "inferred")
        self.assertEqual(self.graph.get_node("cwe", "CWE-639")["trust"], "inferred")
        self.assertTrue(pattern["provenance"])

    def test_unknown_pattern_raises(self):
        with self.assertRaises(KnowledgeGraphError):
            self.bridge.ingest_pattern("NOPE")


class QueryTests(BridgeTestBase):
    def setUp(self):
        super().setUp()
        self.bridge.ingest_pattern("PAT-G", endpoint_node_id=self.endpoint, technology="REST API")

    def test_graph_assisted_queries(self):
        self.assertEqual([p["key"] for p in patterns_for_endpoint(self.graph, self.endpoint)], ["PAT-G"])
        self.assertEqual([p["key"] for p in patterns_for_vulnerability_class(self.graph, "BOLA")], ["PAT-G"])
        self.assertEqual([p["key"] for p in patterns_for_technology(self.graph, "REST API")], ["PAT-G"])
        self.assertEqual(weaknesses_of_pattern(self.graph, "PAT-G"), [{"type": "cwe", "value": "CWE-639"}])

    def test_tool_capability(self):
        self.bridge.register_tool("sqlmap", ["sqli"])
        tools = tools_for_vulnerability_class(self.graph, "sqli")
        self.assertEqual([t["key"] for t in tools], ["sqlmap"])
        self.assertEqual(self.graph.get_node("tool", "sqlmap")["trust"], "observed")


class AuthorizationBoundaryTests(BridgeTestBase):
    def test_knowledge_creates_no_authorization_or_principals(self):
        self.bridge.ingest_pattern("PAT-G", endpoint_node_id=self.endpoint, technology="REST API")
        # No authorization edges and no principal nodes were created from KB content.
        self.assertEqual(self.graph.edges("CAN_ACCESS"), [])
        self.assertEqual(self.graph.edges("HAS_ROLE"), [])
        self.assertEqual(self.graph.nodes("identity"), [])
        self.assertEqual(self.graph.nodes("role"), [])
        self.assertEqual(self.graph.nodes("permission"), [])

    def test_knowledge_node_cannot_be_authorization_source(self):
        self.bridge.ingest_pattern("PAT-G", endpoint_node_id=self.endpoint)
        pattern_node = self.graph.node_id("knowledge_pattern", "PAT-G")
        # A knowledge pattern can never be the source of an authorization grant.
        with self.assertRaises(GraphError):
            self.graph.upsert_edge(pattern_node, "CAN_ACCESS", self.endpoint, trust="control_plane")


if __name__ == "__main__":
    unittest.main()
