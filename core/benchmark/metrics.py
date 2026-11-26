"""Benchmark metrics.

Pure functions over sets of findings identified by ``(category, target)``. Precision/recall/
F1 are reported with their raw confusion counts; recall is undefined (``None``) when a
scenario has no ground-truth vulnerabilities, and precision is undefined when nothing was
reported — these are never silently coerced to 1.0.
"""
from __future__ import annotations

import statistics


def _as_set(items) -> set:
    return {tuple(item) for item in items}


def compute_metrics(ground_truth, discovered) -> dict:
    gt, disc = _as_set(ground_truth), _as_set(discovered)
    tp, fp, fn = gt & disc, disc - gt, gt - disc
    precision = (len(tp) / (len(tp) + len(fp))) if (tp or fp) else None
    recall = (len(tp) / (len(tp) + len(fn))) if gt else None
    if precision in (None, 0) or recall in (None, 0) or precision is None or recall is None:
        f1 = 0.0 if (precision == 0 or recall == 0) else None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "true_positives": len(tp), "false_positives": len(fp), "false_negatives": len(fn),
        "precision": precision, "recall": recall, "f1": f1,
        "tp_items": sorted(list(item) for item in tp),
        "fp_items": sorted(list(item) for item in fp),
        "fn_items": sorted(list(item) for item in fn),
    }


def summarize_variance(values) -> dict:
    nums = [v for v in values if isinstance(v, (int, float))]
    if not nums:
        return {"n": 0, "mean": None, "stdev": None, "min": None, "max": None}
    return {
        "n": len(nums), "mean": round(statistics.fmean(nums), 6),
        "stdev": round(statistics.pstdev(nums), 6) if len(nums) > 1 else 0.0,
        "min": min(nums), "max": max(nums),
    }
