#!/usr/bin/env python3
"""Run the deterministic regression benchmark over the synthetic scenario suite.

This exercises the real attack graph → adaptive planner → exploit validation pipeline with
synthetic, in-memory targets. It contacts no live host and calls no model, so it is safe for
CI and for reproducible version comparisons. For real-agent benchmarking use
scripts/run_benchmark.py (separate, gated, and never run against live targets in CI).
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.benchmark import BenchmarkRunner, build_default_scenarios, compare_results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=1,
                        help="Repeat each scenario to measure variance (default 1).")
    parser.add_argument("--out", help="Write the full result JSON to this path.")
    parser.add_argument("--baseline", help="A previous result JSON to compare against for regressions.")
    args = parser.parse_args(argv)

    result = BenchmarkRunner().run_suite(build_default_scenarios(), repetitions=args.repetitions)
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    for scenario in result["scenarios"]:
        m = scenario["metrics"]
        print(f"{scenario['scenario']:<18} precision={m['precision']} recall={m['recall']} "
              f"f1={m['f1']} coverage={m['endpoint_coverage']} "
              f"validated={m['validated_findings']} reproducible={scenario['reproducible']}")
    agg = result["aggregate"]
    print(f"\nmacro_precision={agg['macro_precision']} macro_recall={agg['macro_recall']} "
          f"all_reproducible={agg['all_reproducible']}")

    exit_code = 0
    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        comparison = compare_results(baseline, result)
        if comparison["is_regression"]:
            print("REGRESSION: " + ", ".join(comparison["regressed"]))
            exit_code = 1
        else:
            print("No regression against baseline.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
