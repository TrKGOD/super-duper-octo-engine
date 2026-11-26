"""Deterministic policy validation of candidate hypotheses.

This is the authority that decides whether a proposed test may run. It is independent of
whoever proposed the hypothesis (deterministic generator or an LLM), so a proposal can
never widen scope, use an unauthorized identity, run a disallowed or prohibited test
class, or auto-run a state-changing test. It never grants authorization — it only refuses.
"""
from __future__ import annotations

from core.active_executor import ActiveExecutionError, _validate_request_scope


class PolicyValidator:
    def __init__(self, scope: dict, rules: dict, graph):
        self.scope = scope or {}
        self.rules = rules or {}
        self.graph = graph
        self.allowed = set(self.rules.get("allowed_test_classes", []))
        self.prohibited = set(self.rules.get("prohibited_test_classes", []))
        self.require_approval = self.rules.get("human_approval_required_for_state_changes", True)
        self.task_scope = (list(self.scope.get("allowed_domains", []))
                           + list(self.scope.get("allowed_applications", []))
                           + list(self.scope.get("allowed_ips", [])))

    def _target_url(self, hypothesis_target_id: str | None):
        if not hypothesis_target_id:
            return None
        node = self.graph.get_node_by_id(hypothesis_target_id)
        if node is None:
            return None
        attrs = node.get("attributes", {})
        origin, path = attrs.get("origin"), attrs.get("path")
        if not origin:
            return None
        return origin.rstrip("/") + (path or "/")

    def _identity_authorized(self, identity_key: str | None) -> bool:
        if not identity_key:
            return True  # anonymous test needs no identity authorization
        for node_type in ("identity", "user"):
            node = self.graph.get_node(node_type, identity_key)
            if node is not None and node["trust"] == "control_plane":
                return True
        return False

    def validate(self, hyp) -> tuple[str, str | None]:
        """Return ``(status, reason)`` — READY or a BLOCKED reason. Never grants access."""
        test_class = getattr(hyp, "test_class", None) if not isinstance(hyp, dict) else hyp.get("test_class")
        target_id = getattr(hyp, "target_node_id", None) if not isinstance(hyp, dict) else hyp.get("target_node_id")
        identity = getattr(hyp, "required_identity", None) if not isinstance(hyp, dict) else hyp.get("required_identity")
        state_changing = getattr(hyp, "state_changing", False) if not isinstance(hyp, dict) else hyp.get("state_changing")

        if test_class in self.prohibited:
            return "BLOCKED", "prohibited_test_class"

        url = self._target_url(target_id)
        if target_id is not None and url is None:
            return "BLOCKED", "target_has_no_resolvable_origin"
        if url is not None:
            try:
                _validate_request_scope(url, self.scope, self.task_scope)
            except ActiveExecutionError:
                return "BLOCKED", "target_out_of_scope"

        if not self._identity_authorized(identity):
            return "BLOCKED", "identity_not_authorized"

        if test_class not in self.allowed:
            return "BLOCKED", "test_class_not_allowed"

        if state_changing and self.require_approval:
            return "BLOCKED", "awaiting_operator_approval_for_state_change"

        return "READY", None
