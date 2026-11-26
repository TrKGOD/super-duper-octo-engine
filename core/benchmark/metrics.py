"""Benchmark metrics.

Pure functions over sets of findings identified by ``(category, target)``. Precision/recall/
F1 are reported with their raw confusion counts; recall is undefined (``None``) when a
scenario has no ground-truth vulnerabilities, and precision is undefined when nothing was
reported — these are never silently coerced to 1.0.

``retrieval_metrics`` adds rank-aware measures (precision@k, recall@k, reciprocal rank,
average precision, nDCG@k) for the Intelligence Layer's retrieval benchmark. The same honesty
rule holds: when a query has no relevant items the rank-aware measures are ``None``, never 1.0.
"""
from __future__ import annotations

import math
import statistics


def _round(value):
    return round(value, 6) if isinstance(value, (int, float)) else value


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


def _dcg(gains) -> float:
    return sum(gain / math.log2(index + 2) for index, gain in enumerate(gains))


def retrieval_metrics(relevant, ranked, *, k=None) -> dict:
    """Rank-aware retrieval quality for one query.

    ``relevant`` is the set of relevant item ids; ``ranked`` is the ordered list the retriever
    returned (most relevant first). Binary relevance. When ``relevant`` is empty the rank-aware
    measures are ``None`` (undefined), never coerced to a perfect score.
    """
    rel = set(relevant)
    ordered = list(ranked)
    cutoff = len(ordered) if k is None else min(int(k), len(ordered))
    top = ordered[:cutoff]
    hits = sum(1 for item in top if item in rel)

    precision = (hits / cutoff) if cutoff else None
    recall = (hits / len(rel)) if rel else None

    reciprocal_rank = None
    if rel:
        reciprocal_rank = 0.0
        for index, item in enumerate(ordered):
            if item in rel:
                reciprocal_rank = 1.0 / (index + 1)
                break

    average_precision = None
    if rel:
        found, running = 0, 0.0
        for index, item in enumerate(ordered):
            if item in rel:
                found += 1
                running += found / (index + 1)
        average_precision = running / len(rel)

    ndcg = None
    if rel:
        actual = _dcg([1.0 if item in rel else 0.0 for item in top])
        ideal = _dcg([1.0] * min(len(rel), cutoff)) if cutoff else 0.0
        ndcg = (actual / ideal) if ideal else 0.0

    return {
        "precision_at_k": _round(precision), "recall_at_k": _round(recall),
        "reciprocal_rank": _round(reciprocal_rank), "average_precision": _round(average_precision),
        "ndcg_at_k": _round(ndcg), "k": cutoff, "hits": hits, "relevant": len(rel),
        "retrieved": len(ordered),
    }
