"""Attack / knowledge graph tests.

Covers entity/edge persistence and dedup, provenance and trust upgrade, cross-engagement
isolation, invalid-relationship rejection, the authorization trust boundary (untrusted
data can never grant authorization), traversal, attack-path generation, evidence
association, identity comparison, and ingestion of a Browser Intelligence report.
"""
import tempfile
import unittest
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.graph import (AttackGraph, GraphError, GraphIngestor, GraphQuery, IngestError,
                        find_paths, propose_attack_paths)


class GraphTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "state.sqlite3")
        migrate(self.db)
        self.store = StateStore(self.db)
        self.store.create_engagement("eng-a", "AUTH-A", {"allowed_domains": ["app.local"]}, {}, status="active")
        self.graph = AttackGraph(self.store.connection, "eng-a")
        self.ing = GraphIngestor(self.graph)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()


class SchemaAndPersistenceTests(GraphTestBase):
    def test_migration_creates_graph_tables(self):
        names = {row["name"] for row in self.store.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        self.assertIn("graph_nodes", names)
        self.assertIn("graph_edges", names)

    def test_node_upsert_is_idempotent_and_merges_provenance(self):
        first = self.graph.upsert_node("endpoint", "GET /x", trust="observed",
                                       provenance=[{"source": "browser"}], confidence=0.5)
        second = self.graph.upsert_node("endpoint", "GET /x", trust="observed",
                                        provenance=[{"source": "har"}], confidence=0.7)
        self.assertEqual(first, second)
        self.assertEqual(len(self.graph.nodes("endpoint")), 1)
        node = self.graph.get_node_by_id(first)
        self.assertEqual(len(node["provenance"]), 2)
        self.assertEqual(node["confidence"], 0.7)

    def test_trust_is_upgraded_not_downgraded(self):
        self.graph.upsert_node("identity", "alice", trust="inferred")
        self.graph.upsert_node("identity", "alice", trust="control_plane")
        self.assertEqual(self.graph.get_node("identity", "alice")["trust"], "control_plane")
        # A later weaker assertion does not downgrade.
        self.graph.upsert_node("identity", "alice", trust="observed")
        self.assertEqual(self.graph.get_node("identity", "alice")["trust"], "control_plane")

    def test_edge_dedup_and_evidence_merge(self):
        a = self.graph.upsert_node("endpoint", "GET /a", trust="observed")
        b = self.graph.upsert_node("endpoint", "GET /b", trust="observed")
        e1 = self.graph.upsert_edge(a, "DEPENDS_ON", b, trust="observed", evidence_refs=["ev1"])
        e2 = self.graph.upsert_edge(a, "DEPENDS_ON", b, trust="observed", evidence_refs=["ev2"])
        self.assertEqual(e1, e2)
        self.assertEqual(len(self.graph.edges("DEPENDS_ON")), 1)
        self.assertEqual(set(self.graph.edges("DEPENDS_ON")[0]["evidence_refs"]), {"ev1", "ev2"})


class IsolationTests(GraphTestBase):
    def test_cross_engagement_isolation(self):
        self.store.create_engagement("eng-b", "AUTH-B", {}, {}, status="active")
        graph_b = AttackGraph(self.store.connection, "eng-b")
        self.graph.upsert_node("endpoint", "GET /secret", trust="observed")
        self.assertEqual(len(self.graph.nodes("endpoint")), 1)
        self.assertEqual(graph_b.nodes("endpoint"), [])
        self.assertIsNone(graph_b.get_node("endpoint", "GET /secret"))
        # Same natural key yields a different node id per engagement.
        self.assertNotEqual(self.graph.node_id("endpoint", "GET /secret"),
                            graph_b.node_id("endpoint", "GET /secret"))


class ValidationTests(GraphTestBase):
    def test_unknown_node_and_edge_types_are_rejected(self):
        with self.assertRaises(GraphError):
            self.graph.upsert_node("banana", "x", trust="observed")
        a = self.graph.upsert_node("endpoint", "GET /a", trust="observed")
        b = self.graph.upsert_node("role", "admin", trust="control_plane")
        with self.assertRaises(GraphError):
            self.graph.upsert_edge(a, "NOT_A_REAL_EDGE", b, trust="observed")

    def test_edge_endpoint_types_are_constrained(self):
        role = self.graph.upsert_node("role", "admin", trust="control_plane")
        perm = self.graph.upsert_node("permission", "users:write", trust="control_plane")
        # HAS_PERMISSION must go role -> permission, not permission -> role.
        with self.assertRaises(GraphError):
            self.graph.upsert_edge(perm, "HAS_PERMISSION", role, trust="control_plane")


class AuthorizationTrustBoundaryTests(GraphTestBase):
    def test_store_refuses_authorization_edge_below_control_plane(self):
        identity = self.graph.upsert_node("identity", "alice", trust="control_plane")
        endpoint = self.graph.upsert_node("endpoint", "GET /admin", trust="observed")
        with self.assertRaisesRegex(GraphError, "control_plane"):
            self.graph.upsert_edge(identity, "CAN_ACCESS", endpoint, trust="observed")

    def test_untrusted_proposal_cannot_assert_authorization(self):
        with self.assertRaises(IngestError):
            self.ing.propose([{ "kind": "edge", "edge_type": "CAN_ACCESS",
                               "src": {"node_type": "identity", "key": "alice"},
                               "dst": {"node_type": "endpoint", "key": "GET /admin"}}], source="vuln-agent")

    def test_untrusted_proposal_cannot_invent_identities(self):
        with self.assertRaises(IngestError):
            self.ing.propose([{"kind": "node", "node_type": "identity", "key": "mallory"}], source="vuln-agent")

    def test_untrusted_proposal_accepts_structure_and_hypotheses(self):
        accepted = self.ing.propose([
            {"kind": "node", "node_type": "hypothesis", "key": "h-idor-1", "label": "possible IDOR"},
            {"kind": "edge", "edge_type": "TARGETS",
             "src": {"node_type": "hypothesis", "key": "h-idor-1"},
             "dst": {"node_type": "endpoint", "key": "GET /api/orders/{id}"}},
        ], source="vuln-agent")
        self.assertEqual(accepted, {"nodes": 1, "edges": 1})
        self.assertEqual(self.graph.get_node("hypothesis", "h-idor-1")["trust"], "inferred")


class TraversalAndPathTests(GraphTestBase):
    def test_find_paths_enumerates_simple_paths(self):
        a = self.graph.upsert_node("endpoint", "GET /a", trust="observed")
        b = self.graph.upsert_node("endpoint", "GET /b", trust="observed")
        c = self.graph.upsert_node("endpoint", "GET /c", trust="observed")
        self.graph.upsert_edge(a, "DEPENDS_ON", b, trust="observed")
        self.graph.upsert_edge(b, "DEPENDS_ON", c, trust="observed")
        paths = find_paths(self.graph, a, c)
        self.assertEqual(len(paths), 1)
        self.assertEqual([edge["edge_type"] for edge in paths[0]], ["DEPENDS_ON", "DEPENDS_ON"])

    def test_bola_cross_identity_object_access_is_proposed(self):
        self.ing.register_identity("alice")
        self.ing.register_identity("bob")
        endpoint = self.ing.register_endpoint("GET", "https://app.local", "/api/orders/{id}")
        obj = self.graph.upsert_node("object", "order-7", trust="control_plane")
        self.graph.upsert_edge(endpoint, "REFERENCES", obj, trust="observed")
        self.ing.declare_object_owner("order-7", "bob")
        self.ing.observe_access("alice", endpoint, evidence_refs=["req-12"])

        proposals = propose_attack_paths(self.graph)
        bola = [p for p in proposals if p["category"] == "cross_identity_object_access"]
        self.assertEqual(len(bola), 1)
        path = bola[0]
        self.assertEqual(path["start"]["identity"], "alice")
        self.assertEqual(path["target"]["owner"], "bob")
        self.assertIn("req-12", path["supporting_evidence"])
        self.assertEqual(path["risk"], "high")
        self.assertEqual(path["status"], "hypothesis")
        self.assertIn("alice", path["required_authorization"])
        self.assertIn("bob", path["required_authorization"])

    def test_bfla_privilege_escalation_is_proposed(self):
        self.ing.register_identity("carol")
        endpoint = self.ing.register_endpoint("POST", "https://app.local", "/admin/users")
        self.ing.authorize_role_access("admin", endpoint)   # endpoint restricted to admin role
        self.ing.observe_access("carol", endpoint, evidence_refs=["req-99"])  # carol lacks admin

        proposals = propose_attack_paths(self.graph)
        bfla = [p for p in proposals if p["category"] == "function_level_privilege_escalation"]
        self.assertEqual(len(bfla), 1)
        self.assertEqual(bfla[0]["target"]["restricted_to_role"], "admin")

    def test_no_false_path_when_actor_owns_object(self):
        self.ing.register_identity("alice")
        endpoint = self.ing.register_endpoint("GET", "https://app.local", "/api/orders/{id}")
        obj = self.graph.upsert_node("object", "order-1", trust="control_plane")
        self.graph.upsert_edge(endpoint, "REFERENCES", obj, trust="observed")
        self.ing.declare_object_owner("order-1", "alice")      # alice owns her own object
        self.ing.observe_access("alice", endpoint)
        proposals = propose_attack_paths(self.graph)
        self.assertEqual([p for p in proposals if p["category"] == "cross_identity_object_access"], [])


class QueryTests(GraphTestBase):
    def _seed(self):
        self.ing.register_identity("alice")
        self.ing.register_identity("bob")
        self.e_orders = self.ing.register_endpoint("GET", "https://app.local", "/api/orders/{id}")
        self.e_invoices = self.ing.register_endpoint("GET", "https://app.local", "/api/invoices/{id}")
        self.obj = self.graph.upsert_node("object", "order-7", trust="control_plane")
        self.graph.upsert_edge(self.e_orders, "REFERENCES", self.obj, trust="observed")
        self.graph.upsert_edge(self.e_invoices, "REFERENCES", self.obj, trust="observed")
        self.ing.authorize_access("alice", self.e_orders)
        self.ing.observe_access("bob", self.e_invoices)

    def test_query_methods(self):
        self._seed()
        q = GraphQuery(self.graph)
        self.assertEqual({n["key"] for n in q.endpoints_for_object("order-7")},
                         {"GET https://app.local/api/orders/{id}", "GET https://app.local/api/invoices/{id}"})
        self.assertEqual([n["key"] for n in q.endpoints_for_identity("alice")],
                         ["GET https://app.local/api/orders/{id}"])
        multi = q.objects_referenced_by_multiple_endpoints()
        self.assertEqual(multi[0]["object"], "order-7")
        self.assertEqual(multi[0]["endpoint_count"], 2)
        # Neither endpoint is targeted by a hypothesis yet -> both are coverage gaps.
        self.assertEqual(len(q.low_coverage_endpoints()), 2)

    def test_identity_access_differences(self):
        self._seed()
        q = GraphQuery(self.graph)
        diff = q.identity_access_differences("alice", "bob")
        self.assertEqual(diff["only_a"], ["GET https://app.local/api/orders/{id}"])
        self.assertEqual(diff["only_b"], ["GET https://app.local/api/invoices/{id}"])

    def test_hypotheses_without_validation(self):
        self.ing.propose([{"kind": "node", "node_type": "hypothesis", "key": "h1"}], source="agent")
        q = GraphQuery(self.graph)
        self.assertEqual([h["key"] for h in q.hypotheses_without_validation()], ["h1"])
        # Attach supporting evidence -> no longer unvalidated.
        ev = self.graph.upsert_node("evidence", "ev-1", trust="observed")
        hyp = self.graph.node_id("hypothesis", "h1")
        self.graph.upsert_edge(ev, "SUPPORTS", hyp, trust="observed")
        self.assertEqual(q.hypotheses_without_validation(), [])


class BrowserIngestTests(GraphTestBase):
    REPORT = {
        "network_endpoints": [
            {"method": "GET", "origin": "https://app.local:443", "path_template": "/api/orders/{id}",
             "content_types": ["application/json"], "query_param_names": ["expand"]},
        ],
        "forms": [
            {"method": "POST", "origin": "https://app.local:443", "action_template": "/account/delete",
             "state_changing": True, "destructive": True, "fields": [{"name": "confirm", "type": "text"}]},
        ],
        "routes": [{"template": "/dashboard", "methods": ["GET"], "dynamic": False}],
        "workflows": [{"name": "wf1", "steps": [{"action": "open", "route": "/dashboard", "kind": "click"}]}],
    }

    def test_browser_report_ingested_as_observed_structure(self):
        self.ing.register_identity("alice")
        created = self.ing.ingest_browser_report(self.REPORT, source="browser", identity_key="alice",
                                                 evidence_refs=["har-1"])
        self.assertEqual(created["endpoints"], 1)
        self.assertGreaterEqual(created["parameters"], 2)  # query param + form field
        self.assertEqual(created["observed_access"], 2)    # one per endpoint (api + form)
        endpoint = self.graph.get_node("endpoint", "GET https://app.local:443/api/orders/{id}")
        self.assertEqual(endpoint["trust"], "observed")
        # The observed access is OBSERVED_ACCESS, never an authorization grant.
        self.assertEqual(self.graph.edges("CAN_ACCESS"), [])
        self.assertTrue(self.graph.edges("OBSERVED_ACCESS"))

    def test_browser_report_requires_registered_identity(self):
        with self.assertRaises(IngestError):
            self.ing.ingest_browser_report(self.REPORT, identity_key="ghost")


if __name__ == "__main__":
    unittest.main()
