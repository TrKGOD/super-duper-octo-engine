#!/usr/bin/env python3
"""Compare Model 1 and hybrid pipeline predictions on the same synthetic corpus."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from scripts.evaluate_benchmark import evaluate


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def compare(cases, model1_predictions, model1_manifest, hybrid_predictions, hybrid_manifest):
    left, right = load(model1_manifest), load(hybrid_manifest)
    if left.get("architecture") != "model1" or right.get("architecture") != "hybrid":
        raise ValueError("Manifest architecture labels must be model1 and hybrid")
    if left.get("model") != right.get("model"):
        raise ValueError("Both architectures must use the same model identifier")
    if left.get("corpus_sha256") != right.get("corpus_sha256"):
        raise ValueError("Both architectures must use the same exact corpus hash")
    case_objects = [
        load(path) for path in sorted(Path(cases).glob("*.json"))
    ]
    actual_hash = hashlib.sha256(
        json.dumps(case_objects, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    if actual_hash != left.get("corpus_sha256"):
        raise ValueError("Run manifests do not match the currently supplied corpus")
    m1 = evaluate(cases, model1_predictions)
    hybrid = evaluate(cases, hybrid_predictions)
    metrics = ("precision", "recall", "f1", "false_positive_rate", "evidence_completeness")
    deltas = {}
    for key in metrics:
        a, b = m1.get(key), hybrid.get(key)
        deltas[key] = round(b - a, 4) if isinstance(a, (int, float)) and isinstance(b, (int, float)) else None
    return {
        "comparison_status": "comparable_synthetic_pipeline_simulation",
        "model": left["model"],
        "corpus_sha256": left["corpus_sha256"],
        "model1": {
            "metrics": m1,
            "total_seconds": left.get("total_seconds"),
            "total_cost_usd": left.get("total_cost_usd"),
            "plan_sha256": left.get("plan_sha256"),
        },
        "hybrid": {
            "metrics": hybrid,
            "total_seconds": right.get("total_seconds"),
            "total_cost_usd": right.get("total_cost_usd"),
            "plan_sha256": right.get("plan_sha256"),
        },
        "hybrid_minus_model1": deltas,
        "limitations": [
            "Compares fixed sequential specialist plan simulations, not autonomous orchestration.",
            "Synthetic metrics do not establish real-world pentest effectiveness.",
            "Run each architecture multiple times and report variance before drawing conclusions.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default="benchmarks/cases")
    parser.add_argument("--model1-predictions", required=True)
    parser.add_argument("--model1-manifest", required=True)
    parser.add_argument("--hybrid-predictions", required=True)
    parser.add_argument("--hybrid-manifest", required=True)
    parser.add_argument("--json-out")
    args = parser.parse_args()
    try:
        result = compare(
            args.cases, args.model1_predictions, args.model1_manifest,
            args.hybrid_predictions, args.hybrid_manifest,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("architecture comparison failed: " + str(exc), file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json_out:
        target = Path(args.json_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
