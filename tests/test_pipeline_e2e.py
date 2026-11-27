"""End-to-end acceptance: observation -> hypothesis -> policy -> tool -> execution -> evidence ->
independent validation -> graph/coverage -> next cycle, against a local synthetic fixture.

The target is a tiny *access-control policy fixture* on loopback (synthetic records, bearer
credentials from environment variables). A switch decides whether it enforces ownership, so every
scenario has a positive case (the fixture grants cross-identity access) and a negative case (it
denies) — false positives are measured, not assumed away. Nothing here leaves the machine.

Everything below the fixture is the real stack: the scope-enforcing HTTP broker, the evidence
vault, the execution ledger, the validation engine, the finding lifecycle, the attack graph and
the adaptive planner. The only test double is the fixture target itself.
"""
import html
import json
import os
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from core.execution_ledger import ExecutionLedger
from core.graph import AttackGraph, GraphIngestor
from core.pipeline import AssessmentPipeline, IdentityDirectory, build_pipeline_registry
from core.planner import PlannerBudget
from core.validation_engine import ValidationRecordStore
from tests.lab import LabEngagement

CLASSES = ["http-read-only", "web-authorization-idor", "web-authorization-bac", "web-sqli", "web-xss", "web-ssrf"]
ENV = {"WH_TOK_ALICE": "Bearer tok-alice", "WH_TOK_BOB": "Bearer tok-bob", "WH_TOK_ADMIN": "Bearer tok-admin"}
IDENTITIES = {"alice": {"Authorization": "WH_TOK_ALICE"}, "bob": {"Authorization": "WH_TOK_BOB"},
              "admin": {"Authorization": "WH_TOK_ADMIN"}}


class AccessPolicyFixture(BaseHTTPRequestHandler):
    """Synthetic records behind bearer credentials; ``enforce_ownership`` / ``protect_admin`` pick the policy."""
    tokens = {"Bearer tok-alice": "alice", "Bearer tok-bob": "bob", "Bearer tok-admin": "admin"}
    orders = {"7": {"id": 7, "owner": "bob", "item": "synthetic item 7"},
              "8": {"id": 8, "owner": "alice", "item": "synthetic item 8"}}
    enforce_ownership = False
    protect_admin = False
    hits: list = []

    # -- toggles for the automated sqli/xss/ssrf executors (core/pipeline/executor.py) ------------
    sqli_vulnerable = False          # /search?q=: naive string-built lookup vs. exact-match only
    reflect_unescaped = False        # /search?q=: raw echo vs. html.escape'd, when not sqli_vulnerable
    ssrf_fetch_enabled = False       # /api/fetch?url=: "fetches" (records) the url vs. refuses it
    ssrf_events_path = None          # Path a "fetch" appends a synthetic callback event to (or None)
    lookup_rows = {"1": "widget-one", "2": "widget-two", "3": "widget-three"}

    def _send(self, status, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        who = self.tokens.get(self.headers.get("Authorization", ""))
        # The raw path (query string included): two sqli/xss probes to the same route with
        # DIFFERENT query values are not duplicates, and must not look like any to a test that
        # compares hits for repeats (test_pipeline_metrics.py's duplicate-request count).
        type(self).hits.append((self.path, who))
        if path == "/":
            self._send(200, b'<html><body><a href="/api/orders/7">order</a> <a href="/api/admin/users">users</a>'
                            b'<form action="/search" method="get"><input name="q"></form></body></html>',
                       "text/html")
        elif path.startswith("/api/orders/"):
            order = self.orders.get(path.rsplit("/", 1)[1])
            if who is None:
                self._send(401, {"error": "unauthenticated"})
            elif order is None:
                self._send(404, {"error": "not found"})
            elif type(self).enforce_ownership and order["owner"] != who and who != "admin":
                self._send(403, {"error": "forbidden"})
            else:
                self._send(200, order)
        elif path == "/api/admin/users":
            if who is None:
                self._send(401, {"error": "unauthenticated"})
            elif type(self).protect_admin and who != "admin":
                self._send(403, {"error": "forbidden"})
            else:
                self._send(200, [{"user": "alice"}, {"user": "bob"}])
        elif path == "/search":
            # XSS fixture only: reflects "q" into the page, raw or HTML-escaped. Never reflects
            # itself in a way that would also make the SQLi oracle's fingerprint differential
            # meaningful (core/pipeline/executor.py's own reflection-confound check catches that
            # case anyway, but /api/lookup below is the clean, unambiguous SQLi fixture).
            term = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            shown = term if type(self).reflect_unescaped else html.escape(term)
            self._send(200, f"<html><body><p>results for {shown}</p></body></html>".encode(), "text/html")
        elif path == "/api/lookup":
            # SQLi fixture only: a naive stand-in for "SELECT ... WHERE id = '{term}'" built by
            # string concatenation when sqli_vulnerable, an exact match otherwise. Returns row
            # VALUES (never the raw term), so neither case ever reflects the payload itself.
            term = parse_qs(urlsplit(self.path).query).get("term", [""])[0]
            if type(self).sqli_vulnerable and "' OR '1'='1" in term:
                rows = list(type(self).lookup_rows.values())
            elif type(self).sqli_vulnerable and "' OR '1'='2" in term:
                rows = []
            else:
                rows = [v for k, v in type(self).lookup_rows.items() if k == term]
            self._send(200, {"results": rows})
        elif path == "/api/fetch":
            target = parse_qs(urlsplit(self.path).query).get("url", [""])[0]
            if type(self).ssrf_fetch_enabled:
                # Stands in for the target server itself issuing the outbound request: instead of
                # actually fetching anything, it appends a synthetic event to the path the test
                # pointed ssrf_events_path at - as if an operator's own external listener had just
                # logged an inbound hit carrying the marker. No real network fetch happens.
                marker = parse_qs(urlsplit(target).query).get("wh", [""])[0]
                events_path = type(self).ssrf_events_path
                if marker and events_path is not None:
                    existing = json.loads(events_path.read_text(encoding="utf-8")) if events_path.exists() else []
                    existing.append({"marker": marker, "source_ip": "203.0.113.9"})
                    events_path.write_text(json.dumps(existing), encoding="utf-8")
                self._send(200, {"status": "fetched"})
            else:
                self._send(400, {"error": "external fetch is disabled"})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *_):
        pass


class PipelineBase(unittest.TestCase):
    enforce_ownership = False
    protect_admin = False

    def setUp(self):
        AccessPolicyFixture.hits = []
        AccessPolicyFixture.enforce_ownership = self.enforce_ownership
        AccessPolicyFixture.protect_admin = self.protect_admin
        AccessPolicyFixture.sqli_vulnerable = False
        AccessPolicyFixture.reflect_unescaped = False
        AccessPolicyFixture.ssrf_fetch_enabled = False
        AccessPolicyFixture.ssrf_events_path = None
        self.env = patch.dict(os.environ, ENV)
        self.env.start()
        self.lab = LabEngagement(AccessPolicyFixture, allowed_classes=CLASSES, extra_rules=self.rules(),
                                 extra_scope=self.extra_scope()).open()
        self.connection = self.lab.workflow.store.connection
        self.graph = AttackGraph(self.connection, self.lab.engagement_id)
        self.ingest = GraphIngestor(self.graph)
        self.origin = self.lab.server.origin
        self.ledger = ExecutionLedger(self.connection)

    def tearDown(self):
        self.lab.close()
        self.env.stop()

    def rules(self):
        return {}

    def extra_scope(self):
        return {}

    def pipeline(self, *, identities=None, registry=None, budget=None):
        return AssessmentPipeline(
            self.lab.workflow, self.lab.engagement_id, IdentityDirectory(identities or IDENTITIES),
            registry=registry, project_root=self.lab.root,
            budget=budget or PlannerBudget(max_cycles=4, max_tasks=30, select_per_cycle=10))

    def endpoint_id(self, path):
        return self.graph.get_node("endpoint", f"GET {self.origin}{path}")["node_id"]

    def seed_endpoints_without_traffic(self):
        for path in ("/api/orders/{id}", "/api/admin/users"):
            self.ingest.register_endpoint("GET", self.origin, path, trust="observed", provenance="discovery")

    def register_query_endpoint(self, method, path, param_name):
        """Direct graph registration (bypassing the crawler) of an endpoint and one query
        parameter, shaped exactly as core/pipeline/discovery.py's project_discovery would have
        projected them -- including the empty ``attributes`` dict on the parameter node, which is
        why core/pipeline/executor.py reads a parameter's name from ``label``, not ``attributes``."""
        endpoint_id = self.ingest.register_endpoint(method, self.origin, path, trust="observed", provenance="discovery")
        key = f"{method.upper()} {self.origin}{path}?{param_name}"
        param_id = self.graph.upsert_node("parameter", key, label=param_name, trust="observed",
                                          provenance=[{"source": "discovery"}], confidence=0.5)
        self.graph.upsert_edge(endpoint_id, "ACCEPTS", param_id, trust="observed",
                               provenance=[{"source": "discovery"}], confidence=0.5)
        return endpoint_id

    def seed_control_plane(self, *, declare_owner: bool, bfla: bool = False):
        for who in ("alice", "bob", "admin"):
            self.ingest.register_identity(who)
        self.ingest.grant_role("admin", "admin-role")
        self.ingest.grant_role("alice", "user-role")
        self.ingest.grant_role("bob", "user-role")
        orders = self.endpoint_id("/api/orders/{id}")
        self.ingest.authorize_access("alice", orders)
        order = self.graph.upsert_node("object", "order-7", attributes={"identifier": "7"}, trust="control_plane",
                                       provenance=[{"source": "operator"}], confidence=1.0)
        self.graph.upsert_edge(orders, "REFERENCES", order, trust="observed", provenance=[{"source": "traffic-capture"}])
        if declare_owner:
            self.ingest.declare_object_owner("order-7", "bob")
        if bfla:
            admin = self.endpoint_id("/api/admin/users")
            self.ingest.authorize_role_access("admin-role", admin)
            self.ingest.observe_access("alice", admin)       # a previously captured, authenticated visit

    def hypothesis(self, planner_report_or_none=None, category="idor_bola"):
        rows = self.connection.execute(
            "SELECT * FROM planner_hypotheses WHERE engagement_id=? AND category=?",
            (self.lab.engagement_id, category)).fetchall()
        return rows[0] if rows else None

    def http_executions(self):
        return [e for e in self.ledger.list(self.lab.engagement_id) if e["kind"] == "http"]

    def target_requests(self, path_prefix):
        return [h for h in AccessPolicyFixture.hits if h[0].startswith(path_prefix)]


class TenStepAcceptanceTests(PipelineBase):
    """The mission's ten acceptance steps, in order, on one engagement."""

    def test_full_lifecycle_against_a_permissive_fixture(self):
        pipeline = self.pipeline()

        # 1. OBSERVATION -> graph. The guarded discovery runner crawls through the broker.
        discovered = pipeline.discover(self.origin + "/")
        self.assertGreaterEqual(discovered["projected"]["endpoints"], 2)
        orders = self.graph.get_node_by_id(self.endpoint_id("/api/orders/{id}"))
        self.assertEqual(orders["trust"], "observed")                      # observation is not authorization
        self.assertEqual(orders["provenance"][0]["source"], "discovery")
        self.assertEqual(self.graph.edges("CAN_ACCESS"), [])               # discovery asserted no authorization
        discovery_executions = len(self.http_executions())
        self.assertGreater(discovery_executions, 0)

        # 2. HYPOTHESIS from graph facts + 3. PRIORITISATION + 4. POLICY
        self.seed_control_plane(declare_owner=False, bfla=True)
        first = pipeline.run()
        categories = {h["category"]: h for h in map(dict, self.connection.execute(
            "SELECT * FROM planner_hypotheses WHERE engagement_id=?", (self.lab.engagement_id,)))}
        self.assertIn("idor_bola", categories)
        self.assertIn("bfla", categories)
        self.assertIn("sqli", categories)                                  # from the discovered form parameter
        self.assertGreater(categories["idor_bola"]["score"], 0)            # scored, transparently
        self.assertIn("impact", json.loads(categories["idor_bola"]["score_breakdown_json"])["factors"])

        # Nothing was sent for the IDOR hypothesis, which could not be justified yet: object
        # ownership is undeclared. The sqli hypothesis DID run (it has an automated executor): a
        # boolean-pair probe against /search?q=: the fixture's /search route reflects "q" back
        # (HTML-escaped by default) for the XSS tests' sake, so the executor's own reflection-
        # confound check (core/pipeline/executor.py) correctly declines to trust the fingerprint
        # differential here, rather than reusing the pre-existing oracle's SUPPORTED verdict on a
        # difference that is really just two different payload strings being echoed back.
        self.assertEqual(self.target_requests("/api/orders/7"), [])
        idor = self.hypothesis(category="idor_bola")
        self.assertEqual(idor["status"], "INCONCLUSIVE")
        self.assertEqual(json.loads(idor["evidence_requests_json"])[0]["kind"], "confirm_object_ownership")
        self.assertEqual(idor["executed"], 0)                                # an unexecuted attempt is not coverage
        sqli = self.hypothesis(category="sqli")
        self.assertEqual(sqli["status"], "INCONCLUSIVE")
        self.assertEqual(sqli["status_reason"], "reflection_confound")
        self.assertEqual(json.loads(sqli["evidence_requests_json"])[0]["kind"], "possible_reflection_confound")
        self.assertEqual(sqli["executed"], 1)                                     # this one DID reach the target
        # ...while the BFLA hypothesis, whose role restriction the operator DID declare, ran this cycle.
        self.assertEqual(self.hypothesis(category="bfla")["status"], "SUPPORTED")
        self.assertEqual({who for _, who in self.target_requests("/api/admin/users") if who}, {"admin", "alice"})
        self.assertEqual(self.connection.execute("SELECT COUNT(*) c FROM findings WHERE status='validated'").fetchone()["c"], 1)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"], 1)
        after_first_run = len(self.http_executions())

        # 10. NEXT CYCLE uses newly acquired information: the operator declares who owns the object.
        self.ingest.declare_object_owner("order-7", "bob")
        second = pipeline.run()

        # 5. TOOL SELECTION and 6. EXECUTION through the broker
        idor = self.hypothesis(category="idor_bola")
        self.assertEqual(idor["status"], "SUPPORTED")
        decisions = [json.loads(r["result_json"]) for r in self.connection.execute(
            "SELECT result_json FROM planner_decisions WHERE hypothesis_id=? AND selected=1", (idor["hypothesis_id"],))]
        self.assertEqual(decisions[-1]["tool_id"], "broker-authz-compare")
        self.assertEqual(self.target_requests("/api/orders/7")[-2:], [("/api/orders/7", "bob"), ("/api/orders/7", "alice")])
        new_executions = self.http_executions()[after_first_run:]
        pair = [e for e in new_executions if e["request"].get("target_host") and e["status"] == "COMPLETED"
                and e["execution_profile"] == "safe"]
        self.assertGreaterEqual(len(pair), 2)

        # 7. EVIDENCE persisted, SHA-256 verified, linked to the execution that produced it
        pair_ids = {e["execution_id"] for e in new_executions}
        linked = self.connection.execute(
            "SELECT evidence_id,execution_id,sha256 FROM evidence WHERE execution_id IN (%s)" % ",".join("?" * len(pair_ids)),
            tuple(pair_ids)).fetchall()
        self.assertGreaterEqual(len(linked), 4)                                   # request + response per execution
        for row in linked:
            self.assertTrue(self.pipeline_vault().verify(row["evidence_id"])["valid"])

        # 8. INDEPENDENT VALIDATION: a verified record, then a finding confirmed by a different party
        records = ValidationRecordStore(self.connection, self.lab.engagement_id)
        record = records.for_hypothesis(idor["hypothesis_id"])[0]
        self.assertEqual(record["disposition"], "SUPPORTED")
        self.assertTrue(record["evidence_verified"])
        self.assertTrue(records.verify(record["record_id"]))
        self.assertEqual({d["role"] for d in record["evidence_hashes"]}, {"owner_response", "other_response"})
        findings = self.connection.execute("SELECT * FROM findings WHERE status='validated' ORDER BY created_at").fetchall()
        self.assertEqual(len(findings), 2)                                        # BFLA (cycle 1) + BOLA (cycle 2)
        for finding in findings:
            self.assertEqual((finding["proposed_by"], finding["validated_by"]),
                             ("adaptive-planner", "exploit-validation-engine"))
            self.assertNotEqual(finding["proposed_by"], finding["validated_by"])
        finding = next(f for f in findings if "orders" in f["title"])

        # 9. GRAPH and COVERAGE updated
        finding_node = self.graph.get_node("finding", finding["finding_id"])
        self.assertEqual(finding_node["attributes"]["status"], "validated")
        self.assertTrue(self.graph.edges("VALIDATED_BY", src_id=finding_node["node_id"]))
        observed = {self.graph.get_node_by_id(e["src"])["key"] for e in self.graph.edges("OBSERVED_ACCESS")}
        self.assertTrue({"alice", "bob"} <= observed)
        idor_class = second["coverage"]["by_test_class"]["web-authorization-idor"]
        self.assertEqual((idor_class["attempted"], idor_class["SUPPORTED"]), (1, 1))
        sqli_class = second["coverage"]["by_test_class"]["web-sqli"]
        self.assertEqual((sqli_class["hypotheses"], sqli_class["attempted"], sqli_class["INCONCLUSIVE"]), (1, 1, 1))
        untested = second["coverage"]["untested_endpoints"]
        # /search is no longer a gap: sqli has an automated executor now and really reached it.
        self.assertFalse(any("/search" in key for key in untested))
        self.assertFalse(any("/api/orders/" in key for key in untested))

        # BFLA on the permissive fixture: the unprivileged identity reached the restricted function.
        self.assertEqual(self.hypothesis(category="bfla")["status"], "SUPPORTED")

        # 10 (again). A further cycle repeats nothing: no new request, nothing newly ready.
        before = len(self.http_executions())
        third = pipeline.run()
        self.assertEqual(len(self.http_executions()), before)
        self.assertEqual(third["stop_reason"], "no_ready_candidates")
        self.assertEqual(third["pending_operator_reconciliation"], [])

    def pipeline_vault(self):
        from core.evidence import EvidenceVault
        return EvidenceVault(self.lab.workflow.store, self.lab.root)


class NegativeCaseTests(PipelineBase):
    enforce_ownership = True
    protect_admin = True

    def test_an_enforcing_fixture_yields_refutations_and_no_findings(self):
        self.seed_endpoints_without_traffic()
        self.seed_control_plane(declare_owner=True, bfla=True)
        report = self.pipeline().run()
        self.assertEqual(self.hypothesis(category="idor_bola")["status"], "REFUTED")
        self.assertEqual(self.hypothesis(category="bfla")["status"], "REFUTED")
        self.assertEqual(self.connection.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"], 0)
        self.assertEqual(report["supported"], [])
        # the refutation is as evidence-backed as a confirmation would have been
        record = ValidationRecordStore(self.connection, self.lab.engagement_id).for_hypothesis(
            self.hypothesis(category="idor_bola")["hypothesis_id"])[0]
        self.assertTrue(record["evidence_verified"])
        self.assertEqual(record["disposition"], "REFUTED")


class SingleParameterAutomationTests(PipelineBase):
    """Focused positive/negative coverage for the three single-endpoint automated executors
    (core/pipeline/strategies.py: sqli, xss, ssrf). Each endpoint is direct-registered
    (``register_query_endpoint``), so these are independent of the crawler and of each other.
    """

    def rules(self):
        return {"ssrf_callback_url": "https://callback.example.test/canary",
                "ssrf_callback_events_path": ".local/ssrf-events.json"}

    def extra_scope(self):
        return {"allowed_domains": ["callback.example.test"]}

    def test_sqli_true_positive_creates_a_finding(self):
        self.register_query_endpoint("GET", "/api/lookup", "term")
        AccessPolicyFixture.sqli_vulnerable = True
        self.pipeline().run()
        hyp = self.hypothesis(category="sqli")
        self.assertEqual(hyp["status"], "SUPPORTED")
        self.assertEqual(hyp["executed"], 1)
        record = ValidationRecordStore(self.connection, self.lab.engagement_id).for_hypothesis(hyp["hypothesis_id"])[0]
        self.assertTrue(record["evidence_verified"])
        finding = self.connection.execute(
            "SELECT * FROM findings WHERE engagement_id=?", (self.lab.engagement_id,)).fetchone()
        self.assertIsNotNone(finding)
        self.assertIn("SQL injection", finding["title"])
        self.assertEqual(finding["status"], "validated")

    def test_sqli_true_negative_against_a_parameterized_lookup(self):
        self.register_query_endpoint("GET", "/api/lookup", "term")
        AccessPolicyFixture.sqli_vulnerable = False
        self.pipeline().run()
        hyp = self.hypothesis(category="sqli")
        self.assertEqual(hyp["status"], "REFUTED")
        self.assertEqual(self.connection.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"], 0)

    def test_sqli_refuses_a_state_changing_endpoint_without_sending_anything(self):
        # candidates.py hardcodes state_changing=False on a sqli hypothesis regardless of the
        # endpoint's real method, so the executor's own check is the only thing stopping this.
        self.register_query_endpoint("POST", "/api/update", "term")
        AccessPolicyFixture.sqli_vulnerable = True
        before = len(AccessPolicyFixture.hits)
        self.pipeline().run()
        hyp = self.hypothesis(category="sqli")
        self.assertEqual(hyp["status"], "INCONCLUSIVE")
        self.assertEqual(hyp["status_reason"], "state_changing_endpoint")
        self.assertEqual(hyp["executed"], 0)
        self.assertEqual(len(AccessPolicyFixture.hits), before)        # nothing was ever sent

    def test_xss_true_positive_when_the_marker_is_reflected_unescaped(self):
        self.register_query_endpoint("GET", "/search", "q")
        AccessPolicyFixture.reflect_unescaped = True
        self.pipeline().run()
        hyp = self.hypothesis(category="xss")
        self.assertEqual(hyp["status"], "SUPPORTED")
        finding = self.connection.execute(
            "SELECT * FROM findings WHERE engagement_id=?", (self.lab.engagement_id,)).fetchone()
        self.assertIsNotNone(finding)
        self.assertIn("Reflected input", finding["title"])

    def test_xss_true_negative_when_the_marker_is_escaped(self):
        self.register_query_endpoint("GET", "/search", "q")
        AccessPolicyFixture.reflect_unescaped = False
        self.pipeline().run()
        hyp = self.hypothesis(category="xss")
        self.assertEqual(hyp["status"], "REFUTED")
        self.assertEqual(self.connection.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"], 0)

    def test_ssrf_supported_when_a_matching_callback_is_observed(self):
        self.register_query_endpoint("GET", "/api/fetch", "url")
        AccessPolicyFixture.ssrf_fetch_enabled = True
        AccessPolicyFixture.ssrf_events_path = self.lab.root / ".local" / "ssrf-events.json"
        self.pipeline().run()
        hyp = self.hypothesis(category="ssrf")
        self.assertEqual(hyp["status"], "SUPPORTED")
        record = ValidationRecordStore(self.connection, self.lab.engagement_id).for_hypothesis(hyp["hypothesis_id"])[0]
        self.assertTrue(record["evidence_verified"])
        finding = self.connection.execute(
            "SELECT * FROM findings WHERE engagement_id=?", (self.lab.engagement_id,)).fetchone()
        self.assertIsNotNone(finding)
        self.assertIn("Server-side request forgery", finding["title"])

    def test_ssrf_inconclusive_and_never_refuted_without_a_callback(self):
        self.register_query_endpoint("GET", "/api/fetch", "url")
        AccessPolicyFixture.ssrf_fetch_enabled = False       # the target never fetches it
        AccessPolicyFixture.ssrf_events_path = self.lab.root / ".local" / "ssrf-events.json"
        self.pipeline().run()
        hyp = self.hypothesis(category="ssrf")
        self.assertEqual(hyp["status"], "INCONCLUSIVE")
        self.assertNotEqual(hyp["status"], "REFUTED")
        self.assertEqual(self.connection.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"], 0)


class SsrfWithoutConfiguredCallbackTests(PipelineBase):
    """A separate engagement (no ssrf_callback_url) so this never mixes with the tests above."""

    def test_ssrf_hypothesis_is_inconclusive_and_never_probed(self):
        # /api/fetch?url= also gets sqli and xss hypotheses (any endpoint with a parameter does);
        # those run and reach the fixture, so only the SSRF hypothesis's own outcome is checked.
        self.register_query_endpoint("GET", "/api/fetch", "url")
        self.pipeline().run()
        hyp = self.hypothesis(category="ssrf")
        self.assertEqual(hyp["status"], "INCONCLUSIVE")
        self.assertEqual(hyp["status_reason"], "ssrf_callback_not_configured")
        self.assertEqual(hyp["executed"], 0)


class PolicyAndSelectionTests(PipelineBase):
    def test_a_test_class_the_engagement_does_not_allow_is_rejected_before_anything_runs(self):
        self.lab.workflow.store.connection.execute(
            "UPDATE engagements SET rules_json=? WHERE engagement_id=?",
            (json.dumps({**json.loads(self.connection.execute(
                "SELECT rules_json FROM engagements WHERE engagement_id=?", (self.lab.engagement_id,)).fetchone()["rules_json"]),
                "allowed_test_classes": ["http-read-only"]}), self.lab.engagement_id))
        self.connection.commit()
        self.seed_endpoints_without_traffic()
        self.seed_control_plane(declare_owner=True)
        self.pipeline().run()
        idor = self.hypothesis(category="idor_bola")
        self.assertEqual((idor["status"], idor["status_reason"]), ("BLOCKED", "test_class_not_allowed"))
        rejected = [json.loads(r["rationale_json"]) for r in self.connection.execute(
            "SELECT rationale_json FROM planner_decisions WHERE hypothesis_id=? AND selected=0", (idor["hypothesis_id"],))]
        self.assertEqual(rejected[0]["reason"], "test_class_not_allowed")
        self.assertEqual(self.target_requests("/api/orders/"), [])

    def test_an_unavailable_tool_is_reported_not_faked(self):
        registry = build_pipeline_registry()
        registry.update("broker-authz-compare", status="disabled")
        self.seed_endpoints_without_traffic()
        self.seed_control_plane(declare_owner=True)
        self.pipeline(registry=registry).run()
        idor = self.hypothesis(category="idor_bola")
        self.assertEqual(idor["status_reason"], "no_authorized_tool")
        requests = json.loads(idor["evidence_requests_json"])
        self.assertEqual(requests[0]["kind"], "tool_unavailable")
        self.assertEqual(requests[0]["detail"]["rejected"][0]["reason"], "disabled")
        self.assertEqual(self.target_requests("/api/orders/"), [])

    def test_the_engagements_maximum_profile_bounds_tool_selection(self):
        connection = self.connection
        rules = json.loads(connection.execute("SELECT rules_json FROM engagements WHERE engagement_id=?",
                                              (self.lab.engagement_id,)).fetchone()["rules_json"])
        rules["max_execution_profile"] = "safe"
        connection.execute("UPDATE engagements SET rules_json=? WHERE engagement_id=?",
                           (json.dumps(rules), self.lab.engagement_id))
        connection.commit()
        self.seed_endpoints_without_traffic()
        self.seed_control_plane(declare_owner=True)
        self.pipeline().run()
        idor = self.hypothesis(category="idor_bola")
        self.assertEqual(idor["status_reason"], "no_authorized_tool")
        self.assertEqual(json.loads(idor["evidence_requests_json"])[0]["detail"]["rejected"][0]["reason"],
                         "exceeds_engagement_max_profile")

    def test_availability_of_the_builtin_tool_depends_on_a_real_prerequisite(self):
        registry = build_pipeline_registry()
        report = registry.availability_report("broker-authz-compare")
        self.assertEqual(report["state"], "requires_operator_configuration")
        self.assertIn("prerequisite:http_broker", [c["check"] for c in report["checks"] if not c["ok"]])
        registry.declare("http_broker", True)
        self.assertEqual(registry.availability_report("broker-authz-compare")["state"], "available")

    def test_missing_credentials_for_an_identity_block_the_comparison_visibly(self):
        self.seed_endpoints_without_traffic()
        self.seed_control_plane(declare_owner=True)
        self.pipeline(identities={"alice": {"Authorization": "WH_TOK_ALICE"}}).run()      # no credentials for bob
        idor = self.hypothesis(category="idor_bola")
        self.assertEqual(idor["status_reason"], "identity_credentials_not_provisioned")
        self.assertEqual(self.target_requests("/api/orders/"), [])

    def test_the_directory_accepts_only_environment_references_never_secret_values(self):
        from core.pipeline import IdentityDirectoryError
        for bad in ({"a": {"Authorization": "Bearer abc123"}}, {"a": {"Host": "WH_TOK"}}, {"a": {}}, {"": {"X-Key": "WH_X"}}):
            with self.assertRaises(IdentityDirectoryError, msg=repr(bad)):
                IdentityDirectory(bad)


class CrashRecoveryTests(PipelineBase):
    def test_a_crash_mid_comparison_is_held_for_an_operator_and_nothing_is_resent(self):
        from core import active_executor
        self.seed_endpoints_without_traffic()
        self.seed_control_plane(declare_owner=True)
        pipeline = self.pipeline()
        real_send = active_executor._send_once
        calls = {"n": 0}

        def die_on_the_second_request(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt          # models SIGKILL: no `except Exception` cleanup runs
            return real_send(*args, **kwargs)

        with patch.object(active_executor, "_send_once", die_on_the_second_request):
            with self.assertRaises(KeyboardInterrupt):
                pipeline.run()
        idor = self.hypothesis(category="idor_bola")
        self.assertEqual(idor["status"], "RUNNING")                       # exactly what a kill leaves behind
        self.assertTrue(idor["last_execution_id"].startswith("task:"))
        hits_before = len(self.target_requests("/api/orders/7"))
        self.assertEqual(hits_before, 1)                                  # only the first request reached the target

        # "Restart": the lease of the dead process lapses, a new pipeline starts.
        self.connection.execute("UPDATE executions SET lease_expires_at=1 WHERE status IN ('RUNNING','AUTHORIZED')")
        self.connection.commit()
        restarted = self.pipeline()
        report = restarted.run()
        stuck = [e for e in self.ledger.list(self.lab.engagement_id) if e["status"] == "RECONCILIATION_REQUIRED"]
        self.assertEqual(len(stuck), 1)
        self.assertEqual(report["pending_operator_reconciliation"][0]["execution_id"], stuck[0]["execution_id"])
        idor = self.hypothesis(category="idor_bola")
        self.assertEqual((idor["status"], idor["status_reason"]), ("BLOCKED", "awaiting_reconciliation"))
        restarted.run()
        self.assertEqual(len(self.target_requests("/api/orders/7")), hits_before, "a held execution was re-sent")

        # Only an explicit operator decision releases it, and then exactly one bounded retry is allowed.
        self.ledger.resolve(stuck[0]["execution_id"], operator="lab-operator", resolution="failed_no_effect",
                            reason="Verified in the fixture's own log that the second request never arrived")
        restarted.run()
        self.assertEqual(self.hypothesis(category="idor_bola")["status"], "SUPPORTED")
        self.assertEqual(len(self.target_requests("/api/orders/7")), hits_before + 2)


if __name__ == "__main__":
    unittest.main()
