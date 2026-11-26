"""Benchmark & Regression Lab.

A deterministic, CI-safe evaluation harness that runs synthetic scenarios through the real
attack graph → adaptive planner → exploit validation pipeline and reports precision, recall,
F1, coverage, validated-finding counts, runtime and (synthetic) cost, with a reproducible
run manifest. It measures whether the framework is actually improving across versions; it
contacts no live target and calls no model. The real-agent benchmark remains separate and
gated (`scripts/run_benchmark.py`).
"""
from core.benchmark.metrics import compute_metrics, summarize_variance
from core.benchmark.runner import (BenchmarkRunner, GRAPH_VERSION, PLANNER_VERSION,
                                    VALIDATION_VERSION, compare_results)
from core.benchmark.scenarios import (DetectorProfile, Scenario, build_default_scenarios)

__all__ = [
    "BenchmarkRunner", "compare_results", "compute_metrics", "summarize_variance",
    "Scenario", "DetectorProfile", "build_default_scenarios",
    "PLANNER_VERSION", "VALIDATION_VERSION", "GRAPH_VERSION",
]
