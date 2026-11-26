"""Tool Registry & Adapter Framework (Component D) tests.

Covers the execution-profile policy (RESTRICTED never auto-selected; approval rules), the
extended registry (capability/class lookup, honest availability, deterministic selection),
and the adapter executing a synthetic tool end-to-end through the real Phase 5 worker broker
— proving there is no raw-shell path and that output is parsed into observations.
"""
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.workers import WorkerError, WorkerManager
from core.workers.tools import ToolSpec
from core.tools import (ACTIVE_CONTROLLED, AdapterError, BrokeredCommandAdapter, PASSIVE,
                       ProfileError, ProfilePolicy, RESTRICTED, SAFE, ToolDefinition, ToolRegistry,
                       requires_operator_approval, validate_profile)

PY = sys.executable
ENABLED = {"execution_enabled": True, "authorization_verified": True}

SYNTH_SPEC = ToolSpec("synth-probe", "synth", "1.0", "probe",
                      command=(PY, "-c", "print('HOST: app.local'); print('PORT: 443')"),
                      timeout_seconds=15, max_output_bytes=10000)


def synth_def(**over):
    tool_id = over.get("tool_id", "synth-probe")
    spec = over.pop("spec", None) or ToolSpec(
        tool_id, "synth", "1.0", "probe",
        command=(PY, "-c", "print('HOST: app.local'); print('PORT: 443')"),
        timeout_seconds=15, max_output_bytes=10000)
    base = dict(tool_id=tool_id, name="Synthetic Probe", category="recon", version="1.0",
                spec=spec, capabilities=("asset_discovery",), vulnerability_classes=(),
                execution_profile=SAFE, binary=None, status="registered")
    base.update(over)
    return ToolDefinition(**base)


def asset_parser(raw):
    host = port = None
    for line in str(raw).splitlines():
        if line.startswith("HOST:"):
            host = line.split(":", 1)[1].strip()
        elif line.startswith("PORT:"):
            port = int(line.split(":", 1)[1].strip())
    return [{"type": "asset", "capability": "asset_discovery", "host": host, "port": port}]


class ProfilePolicyTests(unittest.TestCase):
    def test_validate_profile(self):
        with self.assertRaises(ProfileError):
            validate_profile("nuclear")

    def test_passive_always_allowed_even_without_execution(self):
        allowed, _ = ProfilePolicy({}).authorize(tool_id="t", profile=PASSIVE, auto_selected=True)
        self.assertTrue(allowed)

    def test_restricted_never_auto_selected(self):
        allowed, reason = ProfilePolicy(ENABLED).authorize(tool_id="t", profile=RESTRICTED, auto_selected=True)
        self.assertFalse(allowed)
        self.assertEqual(reason, "restricted_never_auto_selected")

    def test_restricted_needs_operator_approval(self):
        policy = ProfilePolicy(ENABLED)
        self.assertFalse(policy.authorize(tool_id="t", profile=RESTRICTED, auto_selected=False)[0])
        self.assertTrue(policy.authorize(tool_id="t", profile=RESTRICTED, auto_selected=False,
                                         operator_approved=True)[0])

    def test_state_changing_active_needs_approval(self):
        allowed, reason = ProfilePolicy(ENABLED).authorize(
            tool_id="t", profile=ACTIVE_CONTROLLED, state_changing=True, auto_selected=True)
        self.assertFalse(allowed)
        self.assertEqual(reason, "requires_operator_approval_for_state_change")

    def test_execution_disabled_blocks_active(self):
        self.assertFalse(ProfilePolicy({}).authorize(tool_id="t", profile=SAFE)[0])

    def test_max_profile_cap(self):
        policy = ProfilePolicy({**ENABLED, "max_execution_profile": SAFE})
        self.assertEqual(policy.authorize(tool_id="t", profile=ACTIVE_CONTROLLED)[1], "exceeds_engagement_max_profile")

    def test_requires_operator_approval_helper(self):
        self.assertTrue(requires_operator_approval(RESTRICTED))
        self.assertTrue(requires_operator_approval(ACTIVE_CONTROLLED, state_changing=True))
        self.assertFalse(requires_operator_approval(SAFE))


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.reg = ToolRegistry()
        self.reg.register(synth_def())
        self.reg.register(synth_def(tool_id="exploit-x", name="Exploit X",
                                    spec=ToolSpec("exploit-x", "x", "1.0", "x", command=(PY, "-c", "print(1)")),
                                    capabilities=("exploitation",), vulnerability_classes=("rce",),
                                    execution_profile=RESTRICTED, risk="high"))

    def test_lookup_and_search(self):
        self.assertEqual([t.tool_id for t in self.reg.by_capability("asset_discovery")], ["synth-probe"])
        self.assertEqual([t.tool_id for t in self.reg.by_vulnerability_class("rce")], ["exploit-x"])
        self.assertIn("synth-probe", [t.tool_id for t in self.reg.search("asset")])

    def test_availability_is_honest(self):
        self.assertEqual(self.reg.check_availability("synth-probe"), "available")      # built-in
        self.reg.register(synth_def(tool_id="needs-binary", binary="definitely-not-real-xyz123"))
        self.assertEqual(self.reg.check_availability("needs-binary"), "requires_operator_configuration")

    def test_select_excludes_restricted_and_unavailable(self):
        self.reg.register(synth_def(tool_id="needs-binary", binary="definitely-not-real-xyz123"))
        result = self.reg.select_tools(policy=ProfilePolicy(ENABLED), auto_selected=True)
        selected_ids = {t["tool_id"] for t in result["selected"]}
        rejected = {r["tool_id"]: r["reason"] for r in result["rejected"]}
        self.assertIn("synth-probe", selected_ids)
        self.assertEqual(rejected.get("exploit-x"), "restricted_never_auto_selected")
        self.assertEqual(rejected.get("needs-binary"), "requires_operator_configuration")


class AdapterExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        db = str(root / "state.sqlite3")
        migrate(db)
        self.store = StateStore(db)
        self.store.create_engagement("eng", "AUTH", {}, {}, status="active")
        self.wm = WorkerManager(self.store, root / "run")
        self.worker = self.wm.provision("eng", "task-1")
        self.adapter = BrokeredCommandAdapter(parser=asset_parser)

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_runs_through_broker_and_parses(self):
        result = self.adapter.execute(self.wm, self.worker, synth_def(), {},
                                      allowed_tools=["synth-probe"], policy=ProfilePolicy(ENABLED))
        self.assertEqual(result.exit_status, 0)
        self.assertEqual(result.observations, [{"type": "asset", "capability": "asset_discovery",
                                                "host": "app.local", "port": 443}])

    def test_restricted_tool_is_refused_before_execution(self):
        with self.assertRaises(AdapterError):
            self.adapter.execute(self.wm, self.worker, synth_def(execution_profile=RESTRICTED), {},
                                 allowed_tools=["synth-probe"], policy=ProfilePolicy(ENABLED), auto_selected=True)

    def test_adapter_cannot_bypass_the_broker_allowlist(self):
        # The broker refuses a tool that is not in the engagement's allowlist.
        with self.assertRaises(WorkerError):
            self.adapter.execute(self.wm, self.worker, synth_def(), {},
                                 allowed_tools=[], policy=ProfilePolicy(ENABLED))


if __name__ == "__main__":
    unittest.main()
