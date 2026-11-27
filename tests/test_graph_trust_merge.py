"""Graph trust boundary: a weaker source can add facts but never rewrite stronger ones."""
import tempfile
import unittest
from pathlib import Path

from core.graph import AttackGraph, GraphIngestor
from core.planner import PolicyValidator
from core.store import StateStore
from scripts.migrate import migrate

SCOPE = {"allowed_domains": ["app.local"], "allowed_http_ports": [443], "allowed_applications": [],
         "allowed_ips": [], "allowed_cidrs": [], "excluded_assets": []}
RULES = {"allowed_test_classes": ["web-authorization-idor"], "prohibited_test_classes": []}


class TrustMergeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db = str(Path(self.tmp.name) / "s.sqlite3")
        migrate(db)
        self.store = StateStore(db)
        self.store.create_engagement("eng", "AUTH", SCOPE, RULES, status="active")
        self.graph = AttackGraph(self.store.connection, "eng")
        self.ingest = GraphIngestor(self.graph)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_an_observation_cannot_rewrite_a_control_plane_nodes_attributes(self):
        node = self.ingest.register_endpoint("GET", "https://app.local:443", "/api/orders/{id}",
                                             attributes={"owner_team": "payments"})
        self.graph.upsert_node("endpoint", "GET https://app.local:443/api/orders/{id}",
                               attributes={"origin": "https://evil.example", "owner_team": "attacker",
                                           "note": "seen in traffic"},
                               trust="observed", label="hijacked", confidence=0.99)
        stored = self.graph.get_node_by_id(node)
        self.assertEqual(stored["trust"], "control_plane")
        self.assertEqual(stored["attributes"]["origin"], "https://app.local:443")        # unchanged
        self.assertEqual(stored["attributes"]["owner_team"], "payments")                  # unchanged
        self.assertEqual(stored["attributes"]["note"], "seen in traffic")                 # new fact accepted
        self.assertEqual(stored["label"], "/api/orders/{id}")
        self.assertEqual(stored["confidence"], 1.0)

    def test_the_policy_check_still_sees_the_operator_declared_origin(self):
        node = self.ingest.register_endpoint("GET", "https://app.local:443", "/api/orders/{id}")
        self.graph.upsert_node("endpoint", "GET https://app.local:443/api/orders/{id}",
                               attributes={"origin": "https://evil.example:443"}, trust="inferred")
        policy = PolicyValidator(SCOPE, RULES, self.graph)
        hypothesis = {"test_class": "web-authorization-idor", "target_node_id": node,
                      "required_identity": None, "state_changing": False}
        self.assertEqual(policy.validate(hypothesis), ("READY", None))
        self.assertTrue(policy._target_url(node).startswith("https://app.local"))

    def test_inferred_knowledge_cannot_overwrite_or_raise_an_observed_fact(self):
        node = self.graph.upsert_node("endpoint", "GET https://app.local/x", attributes={"state": "seen"},
                                      trust="observed", confidence=0.5)
        self.graph.upsert_node("endpoint", "GET https://app.local/x", attributes={"state": "guessed"},
                               trust="inferred", confidence=0.95)
        stored = self.graph.get_node_by_id(node)
        self.assertEqual((stored["trust"], stored["attributes"]["state"], stored["confidence"]),
                         ("observed", "seen", 0.5))

    def test_a_stronger_assertion_still_upgrades_and_overrides(self):
        node = self.graph.upsert_node("endpoint", "GET https://app.local/y", attributes={"state": "guessed"},
                                      trust="inferred", confidence=0.2)
        self.graph.upsert_node("endpoint", "GET https://app.local/y", attributes={"state": "seen"},
                               trust="observed", confidence=0.6)
        stored = self.graph.get_node_by_id(node)
        self.assertEqual((stored["trust"], stored["attributes"]["state"], stored["confidence"]),
                         ("observed", "seen", 0.6))

    def test_edges_follow_the_same_rule(self):
        a = self.graph.upsert_node("endpoint", "GET https://app.local/a", trust="observed")
        b = self.graph.upsert_node("endpoint", "GET https://app.local/b", trust="observed")
        self.graph.upsert_edge(a, "DEPENDS_ON", b, trust="observed", attributes={"via": "link"}, confidence=0.5)
        edge_id = self.graph.upsert_edge(a, "DEPENDS_ON", b, trust="inferred",
                                         attributes={"via": "guess", "extra": 1}, confidence=0.9)
        edge = next(e for e in self.graph.edges("DEPENDS_ON") if e["edge_id"] == edge_id)
        self.assertEqual((edge["trust"], edge["attributes"], edge["confidence"]),
                         ("observed", {"via": "link", "extra": 1}, 0.5))

    def test_authorization_edges_remain_control_plane_only(self):
        identity = self.ingest.register_identity("alice")
        endpoint = self.graph.upsert_node("endpoint", "GET https://app.local/z", trust="observed")
        with self.assertRaises(Exception):
            self.graph.upsert_edge(identity, "CAN_ACCESS", endpoint, trust="observed")


if __name__ == "__main__":
    unittest.main()
