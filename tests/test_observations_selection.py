"""Normalized observations + tool selection (Component F) tests.

Verifies capability-based deterministic tool selection (authorized, available, non-redundant;
RESTRICTED never auto-selected), the normalized observation model with correct dispositions
and no secret leakage, and graph correlation that projects only DETECTED structure while
candidates remain leads (never confirmed facts or authorization).
"""
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.graph import AttackGraph
from core.workers.tools import ToolSpec
from core.tools import (CapabilityRequest, ProfilePolicy, ToolDefinition, ToolRegistry, ToolResult,
                       ToolSelector, ObservationStore, PASSIVE, RESTRICTED, SAFE, correlate_to_graph,
                       normalize_tool_result)

PY = sys.executable
ENABLED = {"execution_enabled": True, "authorization_verified": True}


def tool_def(tool_id, *, capabilities=(), profile=SAFE, vuln=(), binary=None):
    return ToolDefinition(
        tool_id=tool_id, name=tool_id, category="recon", version="1.0",
        spec=ToolSpec(tool_id, tool_id, "1.0", "x", command=(PY, "-c", "print(1)")),
        capabilities=tuple(capabilities), vulnerability_classes=tuple(vuln),
        execution_profile=profile, binary=binary, parser="passthrough", status="lab_tested")


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.reg = ToolRegistry()
        self.reg.register(tool_def("synth-recon", capabilities=("asset_discovery",), profile=SAFE))
        self.reg.register(tool_def("synth-exploit", capabilities=("exploitation",), profile=RESTRICTED))
        self.sel = ToolSelector(self.reg, ProfilePolicy(ENABLED))

    def test_capability_selects_available_authorized_tool(self):
        result = self.sel.select(CapabilityRequest(capability="asset_discovery"))
        self.assertEqual([t["tool_id"] for t in result["selected"]], ["synth-recon"])

    def test_redundant_capability_is_deferred(self):
        result = self.sel.select(CapabilityRequest(capability="asset_discovery",
                                                   covered_capabilities=("asset_discovery",)))
        self.assertEqual(result["selected"], [])
        self.assertEqual(result["deferred"][0]["reason"], "capability_already_covered")

    def test_restricted_never_auto_selected(self):
        result = self.sel.select(CapabilityRequest(capability="exploitation", auto_selected=True))
        self.assertEqual(result["selected"], [])
        self.assertTrue(any(r["reason"] == "restricted_never_auto_selected" for r in result["rejected"]))

    def test_profile_cap_defers_higher_profile_tools(self):
        result = self.sel.select(CapabilityRequest(capability="asset_discovery", max_profile=PASSIVE))
        self.assertEqual(result["selected"], [])
        self.assertEqual(result["deferred"][0]["reason"], "exceeds_requested_profile_cap")


class ObservationTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db = str(Path(self.tmp.name) / "state.sqlite3")
        migrate(db)
        self.store = StateStore(db)
        self.store.create_engagement("eng", "AUTH", {}, {}, status="active")
        self.obs = ObservationStore(self.store.connection, "eng")

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass
        self.tmp.cleanup()


class NormalizationTests(ObservationTestBase):
    def _result(self):
        return ToolResult(
            tool_id="nuclei", profile="active_controlled", artifact="out_0.log",
            observations=[
                {"type": "http_service", "url": "https://app.local/api?token=SEKRET99", "status": 200,
                 "technologies": ["nginx"]},
                {"type": "vulnerability_candidate", "template": "CVE-1", "severity": "high",
                 "matched_at": "https://app.local/api", "disposition": "CANDIDATE"}])

    def test_dispositions_and_traceability(self):
        definition = ToolDefinition(tool_id="nuclei", name="nuclei", category="web", version="1.0",
                                    spec=ToolSpec("nuclei", "nuclei", "1.0", "x", command=(PY, "-c", "print(1)")),
                                    capabilities=("vulnerability_scanning",), vulnerability_classes=("cve",),
                                    execution_profile="active_controlled", binary="nuclei", parser="nuclei")
        ids = normalize_tool_result(self.obs, definition, self._result(), task_id="t1", execution_id="e1",
                                    asset="app.local")
        self.assertEqual(len(ids), 2)
        detected = self.obs.list(disposition="DETECTED")[0]
        candidate = self.obs.candidates()[0]
        self.assertEqual(detected["observation_type"], "http_service")
        self.assertEqual(detected["tool_id"], "nuclei")
        self.assertEqual(detected["task_id"], "t1")
        self.assertEqual(detected["execution_id"], "e1")
        self.assertEqual(candidate["vulnerability_class"], "cve")
        self.assertEqual(candidate["severity_candidate"], "high")

    def test_no_secret_leakage(self):
        definition = ToolDefinition(tool_id="nuclei", name="nuclei", category="web", version="1.0",
                                    spec=ToolSpec("nuclei", "nuclei", "1.0", "x", command=(PY, "-c", "print(1)")),
                                    capabilities=(), vulnerability_classes=("cve",),
                                    execution_profile="active_controlled", binary="nuclei", parser="nuclei")
        normalize_tool_result(self.obs, definition, self._result(), asset="app.local")
        import json
        blob = json.dumps(self.obs.list())
        self.assertNotIn("SEKRET99", blob)       # stripped from references and redacted in data


class CorrelationTests(ObservationTestBase):
    def test_only_detected_structure_is_projected(self):
        definition = ToolDefinition(tool_id="httpx", name="httpx", category="recon", version="1.0",
                                    spec=ToolSpec("httpx", "httpx", "1.0", "x", command=(PY, "-c", "print(1)")),
                                    capabilities=("http_probing",), vulnerability_classes=("cve",),
                                    execution_profile=SAFE, binary="httpx", parser="httpx")
        result = ToolResult(tool_id="httpx", profile="safe", observations=[
            {"type": "http_service", "url": "https://app.local/login", "status": 200},
            {"type": "vulnerability_candidate", "template": "CVE-2", "severity": "low",
             "matched_at": "https://app.local/login", "disposition": "CANDIDATE"}])
        normalize_tool_result(self.obs, definition, result, asset="app.local")
        graph = AttackGraph(self.store.connection, "eng")
        created = correlate_to_graph(graph, self.obs.list())
        self.assertEqual(created["routes"], 1)
        self.assertEqual(created["skipped_candidates"], 1)   # candidate not projected as structure
        route = graph.get_node("route", "https://app.local/login")
        self.assertEqual(route["trust"], "observed")
        # A candidate never becomes an authorization edge or a confirmed finding.
        self.assertEqual(graph.edges("CAN_ACCESS"), [])


if __name__ == "__main__":
    unittest.main()
