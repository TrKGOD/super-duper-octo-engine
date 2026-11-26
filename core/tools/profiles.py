"""Tool execution profiles and the policy that authorizes them.

Four profiles order tools by impact: PASSIVE (public data, no target probing) < SAFE
(non-destructive GET/HEAD/OPTIONS discovery) < ACTIVE_CONTROLLED (approved bounded tests) <
RESTRICTED (high-impact/destructive). A **RESTRICTED** action is never auto-selected by an
agent and always requires explicit operator approval; an ACTIVE_CONTROLLED action that is
state-changing also requires approval. The policy is deterministic and sits outside any LLM.
"""
from __future__ import annotations

PASSIVE = "passive"
SAFE = "safe"
ACTIVE_CONTROLLED = "active_controlled"
RESTRICTED = "restricted"
PROFILES = (PASSIVE, SAFE, ACTIVE_CONTROLLED, RESTRICTED)
_ORDER = {profile: index for index, profile in enumerate(PROFILES)}

# Profiles an agent may select on its own. RESTRICTED is deliberately excluded.
AUTO_SELECTABLE = frozenset({PASSIVE, SAFE, ACTIVE_CONTROLLED})


class ProfileError(ValueError):
    pass


def validate_profile(profile: str) -> str:
    if profile not in _ORDER:
        raise ProfileError("Unknown execution profile: " + str(profile))
    return profile


def rank(profile: str) -> int:
    return _ORDER[validate_profile(profile)]


def requires_operator_approval(profile: str, *, state_changing: bool = False) -> bool:
    validate_profile(profile)
    return profile == RESTRICTED or (profile == ACTIVE_CONTROLLED and state_changing)


class ProfilePolicy:
    """Deterministic authorization of a tool at its profile against engagement rules."""

    def __init__(self, rules: dict | None = None):
        rules = rules or {}
        self.execution_enabled = rules.get("execution_enabled") is True
        self.authorization_verified = rules.get("authorization_verified") is True
        self.max_profile = validate_profile(rules.get("max_execution_profile", ACTIVE_CONTROLLED))
        self.approved_restricted = set(rules.get("approved_restricted_tools", []))

    def authorize(self, *, tool_id: str, profile: str, state_changing: bool = False,
                  auto_selected: bool = True, operator_approved: bool = False) -> tuple[bool, str | None]:
        validate_profile(profile)
        # PASSIVE performs no target probing and is always permitted.
        if profile == PASSIVE:
            return True, None
        if not (self.execution_enabled and self.authorization_verified):
            return False, "engagement_not_approved_for_execution"
        # RESTRICTED is a hard rule, checked first: never auto-selected, and always requires
        # explicit operator approval (which is the special authorization that lifts the cap).
        if profile == RESTRICTED:
            if auto_selected:
                return False, "restricted_never_auto_selected"
            if not (operator_approved or tool_id in self.approved_restricted):
                return False, "restricted_requires_operator_approval"
            return True, None
        # Non-restricted profiles are bounded by the engagement's maximum profile.
        if rank(profile) > rank(self.max_profile):
            return False, "exceeds_engagement_max_profile"
        if requires_operator_approval(profile, state_changing=state_changing) and not operator_approved \
                and tool_id not in self.approved_restricted:
            return False, "requires_operator_approval_for_state_change"
        return True, None
