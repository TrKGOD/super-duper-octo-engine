"""Deterministic model-tier selection and bounded escalation policy."""
from __future__ import annotations

class ModelRoutingError(ValueError):
    pass

DEFAULT_POLICY = {"default_model": None, "escalation_model": None,
                  "escalate_on": ["invalid_output", "repeated_inconclusive"],
                  "max_escalations": 1}

def validate_policy(policy):
    merged = {**DEFAULT_POLICY, **(policy or {})}
    for key in ("default_model", "escalation_model"):
        value = merged.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ModelRoutingError(f"{key} must be a non-empty model identifier or null")
    if not isinstance(merged["escalate_on"], list) or any(
        x not in {"invalid_output", "repeated_inconclusive", "high_complexity"}
        for x in merged["escalate_on"]
    ):
        raise ModelRoutingError("Unsupported model escalation trigger")
    if merged["max_escalations"] not in (0, 1):
        raise ModelRoutingError("At most one escalation is supported per task")
    return merged

def select_model(task, requested_model, policy=None, attempt=0, trigger=None):
    cfg = validate_policy(policy)
    base = cfg["default_model"] or requested_model
    if not isinstance(base, str) or not base.strip():
        raise ModelRoutingError("A primary model must be selected")
    should_escalate = (attempt == 1 and cfg["max_escalations"] == 1
                       and cfg["escalation_model"]
                       and trigger in cfg["escalate_on"])
    if should_escalate:
        return {"model": cfg["escalation_model"], "tier": "escalation",
                "reason": trigger, "attempt": attempt}
    return {"model": base, "tier": "default", "reason": "configured_primary",
            "attempt": attempt}
