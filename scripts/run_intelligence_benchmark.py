#!/usr/bin/env python3
"""Run the deterministic intelligence-layer benchmark.

Scores retrieval quality (the real FTS retriever), tool-selection quality (the real
deterministic selector + profile policy) and reporting quality (the real reporting engine) on
synthetic, in-memory data. It contacts no live host and calls no model, so it is safe for CI
and for reproducible version comparisons. Exits non-zero on a regression against a baseline OR
on any safety violation (a RESTRICTED tool auto-selected, or a candidate / tampered-evidence
finding reaching a confirmed report section) — the safety gate is absolute, baseline or not.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.benchmark import compare_intelligence, run_intelligence_suite


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", help="Write the full result JSON to this path.")
    parser.add_argument("--baseline", help="A previous result JSON to compare against for regressions.")
    args = parser.parse_args(argv)

    result = run_intelligence_suite()
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    agg = result["aggregate"]
    print(f"retrieval   map={agg['retrieval_map']} mrr={agg['retrieval_mrr']}")
    print(f"selection   accuracy={agg['selection_accuracy']}")
    print(f"reporting   score={agg['reporting_score']}")
    print(f"safety      violations={agg['safety_violations']} all_safe={agg['all_safe']}")

    exit_code = 0
    if agg["safety_violations"]:
        print("SAFETY VIOLATION: intelligence suite produced an unsafe outcome.")
        exit_code = 1

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        comparison = compare_intelligence(baseline, result)
        if comparison["regressed"]:
            print("REGRESSION: " + ", ".join(comparison["regressed"]))
        if comparison["is_regression"]:
            exit_code = 1
        elif exit_code == 0:
            print("No regression against baseline.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
