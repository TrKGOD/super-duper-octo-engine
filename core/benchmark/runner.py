"""Deterministic regression benchmark runner.

Runs a synthetic scenario through the real pipeline — attack graph → adaptive planner →
exploit validation engine — with a scripted validation executor derived from the scenario's
ground truth, then scores the validated findings. It contacts no live target and calls no
model, so it is reproducible and safe to run in CI. The real-agent benchmark
(`scripts/run_benchmark.py`) remains a separate, gated path.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.graph import AttackGraph, GraphIngestor, GraphQuery
from core.planner import AdaptivePlanner, PlannerBudget
from core.planner.hypothesis import HypothesisStore
from core.validation_engine import ExploitValidationEngine, ValidationRecordStore
from core.benchmark.metrics import compute_metrics, summarize_variance
from core.benchmark.scenarios import ALLOWED_TEST_CLASSES, CATEGORY_TO_CLASS

PLANNER_VERSION = "1.0"
VALIDATION_VERSION = "1.0"
GRAPH_VERSION = "1.0"

_SCOPE = {"allowed_domains": ["app.local"], "allowed_http_ports": [443, 80],
          "allowed_applications": [], "allowed_ips": [], "allowed_cidrs": [], "excluded_assets": []}
_RULES = {"execution_enabled": True, "authorization_verified": True,
          "allowed_test_classes": list(ALLOWED_TEST_CLASSES),
          "prohibited_test_classes": ["denial-of-service", "destructive-testing"],
          "human_approval_required_for_state_changes": True, "max_requests_per_engagement": 100}


def _synth_request(vclass: str, support: bool) -> dict:
    if vclass == "object_authorization":
        other = ({"status_code": 200, "response_excerpt": '{"id":1}'} if support
                 else {"status_code": 403, "response_excerpt": '{}'})
        return {"vulnerability_class": vclass,
                "owner_response": {"status_code": 200, "response_excerpt": '{"id":1}'},
                "other_response": other, "owner_identity": "owner", "other_identity": "attacker",
                "object_reference": "obj"}
    if vclass == "function_authorization":
        lower = {"status_code": 200} if support else {"status_code": 403}
        return {"vulnerability_class": vclass, "baseline_response": {"status_code": 200},
                "lower_privilege_response": lower, "baseline_role": "admin",
                "comparison_role": "user", "function_reference": "/fn", "role_restriction_confirmed": True}
    if vclass == "sqli":
        fp = ("b", "t", "f") if support else ("x", "x", "x")
        return {"vulnerability_class": vclass, "samples": {
            "baseline": {"status_code": 200, "normalized_fingerprint": fp[0]},
            "true_case": {"status_code": 200, "normalized_fingerprint": fp[1]},
            "false_case": {"status_code": 200, "normalized_fingerprint": fp[2]}}}
    if vclass == "reflected_input":
        body = "<p>zzmk</p>" if support else "safe output"
        return {"vulnerability_class": vclass, "marker": "zzmk", "response_body": body, "context": "html_body"}
    return {"vulnerability_class": vclass}


class BenchmarkRunner:
    def run_scenario(self, scenario, *, repetitions: int = 1) -> dict:
        runs = [self._run_once(scenario) for _ in range(repetitions)]
        baseline = runs[0]
        reproducible = all(
            (r["precision"], r["recall"], r["true_positives"], r["false_positives"], r["false_negatives"])
            == (baseline["precision"], baseline["recall"], baseline["true_positives"],
                baseline["false_positives"], baseline["false_negatives"]) for r in runs)
        return {
            "scenario": scenario.name, "version": scenario.version,
            "manifest": self._manifest(scenario, repetitions),
            "metrics": {k: baseline[k] for k in (
                "precision", "recall", "f1", "true_positives", "false_positives", "false_negatives",
                "endpoint_coverage", "validated_findings", "policy_rejections", "inconclusive",
                "fp_items", "fn_items")},
            "runs": runs, "reproducible": reproducible,
            "variance": {
                "precision": summarize_variance([r["precision"] for r in runs]),
                "recall": summarize_variance([r["recall"] for r in runs]),
                "runtime_ms": summarize_variance([r["runtime_ms"] for r in runs])},
            "cost": {"usd": 0.0, "note": "synthetic deterministic run; no model or network cost"},
        }

    def _run_once(self, scenario) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "bench.sqlite3")
            migrate(db)
            store = StateStore(db)
            try:
                store.create_engagement("bench", "AUTH-BENCH", _SCOPE, _RULES, status="active")
                graph = AttackGraph(store.connection, "bench")
                scenario.seed(GraphIngestor(graph), graph)
                engine = ExploitValidationEngine(
                    "bench", record_store=ValidationRecordStore(store.connection, "bench"))

                def executor(hyp):
                    vclass = CATEGORY_TO_CLASS.get(hyp["category"])
                    if vclass is None:
                        return {"disposition": "INCONCLUSIVE", "evidence_refs": []}
                    key = (hyp["category"], hyp["target_label"])
                    support = scenario.detector.should_detect(key, key in scenario.ground_truth)
                    record = engine.validate(_synth_request(vclass, support))
                    refs = [record.record_id] if record.disposition == "SUPPORTED" else []
                    return {"disposition": record.disposition, "evidence_refs": refs}

                planner = AdaptivePlanner(store, "bench", graph, executor=executor,
                                          budget=PlannerBudget(max_cycles=8, max_tasks=50, select_per_cycle=5))
                started = time.monotonic()
                planner.run()
                runtime_ms = int((time.monotonic() - started) * 1000)

                hyps = HypothesisStore(store.connection, "bench")
                discovered = {(h["category"], h["target_label"]) for h in hyps.list("SUPPORTED")}
                metrics = compute_metrics(scenario.ground_truth, discovered)
                endpoints = graph.nodes("endpoint")
                untested = len(GraphQuery(graph).low_coverage_endpoints())
                coverage = round((len(endpoints) - untested) / len(endpoints), 4) if endpoints else 0.0
                metrics.update({
                    "runtime_ms": runtime_ms, "endpoint_coverage": coverage,
                    "validated_findings": len(discovered),
                    "policy_rejections": len(hyps.list("BLOCKED")),
                    "inconclusive": len(hyps.list("INCONCLUSIVE"))})
                return metrics
            finally:
                store.close()

    def run_suite(self, scenarios, *, repetitions: int = 1) -> dict:
        results = [self.run_scenario(s, repetitions=repetitions) for s in scenarios]
        precisions = [r["metrics"]["precision"] for r in results if r["metrics"]["precision"] is not None]
        recalls = [r["metrics"]["recall"] for r in results if r["metrics"]["recall"] is not None]
        return {
            "scenarios": results,
            "aggregate": {
                "scenario_count": len(results),
                "macro_precision": summarize_variance(precisions)["mean"],
                "macro_recall": summarize_variance(recalls)["mean"],
                "all_reproducible": all(r["reproducible"] for r in results),
                "total_validated_findings": sum(r["metrics"]["validated_findings"] for r in results)},
        }

    @staticmethod
    def _manifest(scenario, repetitions) -> dict:
        from core.store import utc_now
        return {
            "scenario_name": scenario.name, "scenario_version": scenario.version,
            "scenario_hash": scenario.hash(), "planner_version": PLANNER_VERSION,
            "validation_version": VALIDATION_VERSION, "graph_version": GRAPH_VERSION,
            "repetitions": repetitions, "generated_at": utc_now(),
            "no_live_targets": True, "no_model_calls": True}


def compare_results(baseline: dict, candidate: dict) -> dict:
    """Regression comparison of two suite results, keyed by scenario name."""
    base = {r["scenario"]: r["metrics"] for r in baseline.get("scenarios", [])}
    cand = {r["scenario"]: r["metrics"] for r in candidate.get("scenarios", [])}
    deltas = {}
    regressed = []
    for name in sorted(set(base) & set(cand)):
        row = {}
        for metric in ("precision", "recall", "f1"):
            b, c = base[name][metric], cand[name][metric]
            if isinstance(b, (int, float)) and isinstance(c, (int, float)):
                row[metric] = round(c - b, 6)
                if c < b - 1e-9:
                    regressed.append(f"{name}.{metric}")
        deltas[name] = row
    return {"deltas": deltas, "regressed": regressed, "is_regression": bool(regressed)}
