"""Operator-authored expected-behavior registry; never silently suppresses findings."""
from __future__ import annotations

class DesignIntentError(ValueError):
    pass

def validate_design_registry(registry):
    if not isinstance(registry, list):
        raise DesignIntentError("Design-intent registry must be a list")
    seen = set()
    for item in registry:
        if not isinstance(item, dict):
            raise DesignIntentError("Design-intent entries must be objects")
        key = (item.get("asset"), item.get("feature_key"))
        if not all(isinstance(x, str) and x.strip() for x in key) or key in seen:
            raise DesignIntentError("Each entry requires a unique asset and feature_key")
        seen.add(key)
        if not isinstance(item.get("expected_behavior"), str) or not item["expected_behavior"].strip():
            raise DesignIntentError("Expected behavior must be documented")
        if not isinstance(item.get("approved_by"), str) or not item["approved_by"].strip():
            raise DesignIntentError("Expected behavior must be operator-attributed")
        if item.get("source_ref") is None:
            raise DesignIntentError("Expected behavior requires a source reference")
    return True

def assess_design_intent(finding, registry):
    validate_design_registry(registry)
    matches = [i for i in registry if i["asset"] == finding.get("asset")
               and i["feature_key"] == finding.get("feature_key")]
    if not matches:
        return {"classification": "no_design_record", "suppress": False}
    item = matches[0]
    return {"classification": "design_review_required", "suppress": False,
            "expected_behavior": item["expected_behavior"],
            "approved_by": item["approved_by"], "source_ref": item["source_ref"],
            "instruction": "Compare the observed security invariant with documented intent; design intent does not automatically make an exploitable weakness acceptable."}
