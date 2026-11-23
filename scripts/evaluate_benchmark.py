#!/usr/bin/env python3
"""Evaluate agent finding predictions against synthetic benchmark cases."""
import argparse
import json
from pathlib import Path
import sys


def load_json(path):
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def evaluate(cases_dir, predictions_path, allow_missing=False):
    cases = {}
    for path in sorted(Path(cases_dir).glob("*.json")):
        case = load_json(path)
        case_id = case.get("case_id")
        if not case_id or case_id in cases:
            raise ValueError(f"Missing or duplicate case_id in {path}")
        if case.get("kind") != "synthetic":
            raise ValueError(f"Non-synthetic benchmark case rejected: {path}")
        if not isinstance(case.get("expected_finding"), bool):
            raise ValueError(f"expected_finding must be boolean: {path}")
        required = case.get("required_evidence", [])
        fixtures = case.get("fixtures", {})
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
            raise ValueError(f"required_evidence must be a string list: {path}")
        if not isinstance(fixtures, dict):
            raise ValueError(f"fixtures must be an object: {path}")
        missing_fixtures = sorted(set(required) - set(fixtures))
        if case["expected_finding"] and missing_fixtures:
            raise ValueError(
                f"Positive case lacks required fixture fields {missing_fixtures}: {path}"
            )
        cases[case_id] = case
    if not cases:
        raise ValueError("No benchmark cases found")

    payload = load_json(predictions_path)
    predictions = {}
    for item in payload.get("predictions", []):
        case_id = item.get("case_id")
        if not case_id or case_id in predictions:
            raise ValueError(f"Missing or duplicate prediction case_id: {case_id}")
        if case_id not in cases:
            raise ValueError(f"Unknown prediction case_id: {case_id}")
        if not isinstance(item.get("detected"), bool):
            raise ValueError(f"detected must be boolean: {case_id}")
        evidence = item.get("evidence_fields", [])
        if not isinstance(evidence, list) or not all(isinstance(x, str) for x in evidence):
            raise ValueError(f"evidence_fields must be a string list: {case_id}")
        predictions[case_id] = item

    missing = sorted(set(cases) - set(predictions))
    if missing and not allow_missing:
        raise ValueError("Missing predictions: " + ", ".join(missing))

    tp = fp = tn = fn = 0
    evidence_scores = []
    for case_id, case in cases.items():
        prediction = predictions.get(case_id, {"detected": False, "evidence_fields": []})
        expected, detected = case["expected_finding"], prediction["detected"]
        if expected and detected:
            tp += 1
            required = set(case.get("required_evidence", []))
            provided = set(prediction.get("evidence_fields", []))
            evidence_scores.append(len(required & provided) / len(required) if required else 1.0)
        elif expected and not detected:
            fn += 1
        elif not expected and detected:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "case_count": len(cases), "evaluated_predictions": len(predictions),
        "missing_predictions": missing, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "false_positive_rate": round(fpr, 4),
        "evidence_completeness": round(sum(evidence_scores) / len(evidence_scores), 4) if evidence_scores else None,
        "limitations": "Synthetic fixture metrics only; not a real-world model-quality claim."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default="benchmarks/cases")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--json-out")
    args = parser.parse_args()
    try:
        result = evaluate(args.cases, args.predictions, args.allow_missing)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"benchmark evaluation failed: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
