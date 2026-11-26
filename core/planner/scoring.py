"""Transparent prioritization scoring.

The score is a documented weighted sum of observable factors, not the model's confidence.
Model confidence is included only as a small, capped term so it can never dominate. The
weights are heuristic priors, not calibrated to real-world exploit rates; they rank
candidates within one engagement and must not be read as probabilities.

    score = 0.30·impact + 0.20·evidence + 0.15·exploitability + 0.10·reachability
          + 0.10·coverage_value + 0.05·cost_efficiency + 0.10·confidence_capped
          − 0.15·execution_risk

All factors are in [0, 1]; `confidence_capped = min(confidence, 0.6)`.
"""
from __future__ import annotations

WEIGHTS = {
    "impact": 0.30, "evidence": 0.20, "exploitability": 0.15, "reachability": 0.10,
    "coverage_value": 0.10, "cost_efficiency": 0.05, "confidence": 0.10, "execution_risk": 0.15,
}

CATEGORY_PRIORS = {
    "idor_bola": {"impact": 0.90, "exploitability": 0.70},
    "bfla": {"impact": 0.90, "exploitability": 0.60},
    "sqli": {"impact": 0.95, "exploitability": 0.60},
    "ssrf": {"impact": 0.85, "exploitability": 0.50},
    "xss": {"impact": 0.60, "exploitability": 0.70},
}
_DEFAULT_PRIOR = {"impact": 0.5, "exploitability": 0.5}


def _get(hyp, key, default=None):
    return hyp.get(key, default) if isinstance(hyp, dict) else getattr(hyp, key, default)


def score_hypothesis(hyp, *, coverage_gap: bool = True) -> tuple[float, dict]:
    category = _get(hyp, "category")
    prior = CATEGORY_PRIORS.get(category, _DEFAULT_PRIOR)
    supporting = _get(hyp, "supporting_evidence", []) or []
    state_changing = bool(_get(hyp, "state_changing", False))
    required_identity = _get(hyp, "required_identity")
    confidence = float(_get(hyp, "confidence", 0.0) or 0.0)

    factors = {
        "impact": prior["impact"],
        "exploitability": prior["exploitability"],
        "evidence": min(1.0, len(supporting) / 3.0),
        "reachability": 1.0 if required_identity else 0.5,
        "coverage_value": 1.0 if coverage_gap else 0.3,
        "cost_efficiency": 1.0 if not state_changing else 0.6,
        "confidence": min(confidence, 0.6),
        "execution_risk": 0.6 if state_changing else 0.0,
    }
    positive = (WEIGHTS["impact"] * factors["impact"]
                + WEIGHTS["evidence"] * factors["evidence"]
                + WEIGHTS["exploitability"] * factors["exploitability"]
                + WEIGHTS["reachability"] * factors["reachability"]
                + WEIGHTS["coverage_value"] * factors["coverage_value"]
                + WEIGHTS["cost_efficiency"] * factors["cost_efficiency"]
                + WEIGHTS["confidence"] * factors["confidence"])
    score = round(positive - WEIGHTS["execution_risk"] * factors["execution_risk"], 4)
    breakdown = {"weights": WEIGHTS, "factors": {k: round(v, 4) for k, v in factors.items()}, "score": score}
    return score, breakdown
