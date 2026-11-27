"""Brokered, paired execution for synthetic IDOR/BOLA comparisons.

Both manifests must already be pinned to the running task. This module only
orchestrates the existing scope-enforcing broker; it never performs network I/O.
"""
from __future__ import annotations

from typing import Any

from core.active_executor import ActiveExecutionError
from core.manifests import load_request_manifest
from core.authorization_testing import compare_object_access
from core.pathsafe import is_link_like


_READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}


def _load_manifest(executor, relative_path: str) -> dict[str, Any]:
    return load_request_manifest(executor.project_root, relative_path, label="Authorization")


def _validate_pair(owner: dict[str, Any], other: dict[str, Any]) -> None:
    for manifest in (owner, other):
        method = str(manifest.get("method", "")).upper()
        if method not in _READ_ONLY_METHODS:
            raise ActiveExecutionError("Paired authorization checks allow only GET, HEAD, and OPTIONS")
        if manifest.get("body") not in (None, ""):
            raise ActiveExecutionError("Paired authorization checks cannot include request bodies")
        if manifest.get("operator_approval") is not None:
            raise ActiveExecutionError("State-changing approval fields are not valid in a read-only authorization pair")

    if owner.get("request_id") == other.get("request_id"):
        raise ActiveExecutionError("Paired authorization manifests require distinct request IDs")

    # The only permitted differences are request ID and secret environment refs.
    owner_context = {k: v for k, v in owner.items() if k not in {"request_id", "secret_headers"}}
    other_context = {k: v for k, v in other.items() if k not in {"request_id", "secret_headers"}}
    if owner_context != other_context:
        raise ActiveExecutionError(
            "Paired requests must be equivalent; only request_id and secret_headers may differ"
        )

    owner_secrets = owner.get("secret_headers") or {}
    other_secrets = other.get("secret_headers") or {}
    if not isinstance(owner_secrets, dict) or not isinstance(other_secrets, dict):
        raise ActiveExecutionError("Both identities must use broker-managed secret_headers")
    if not owner_secrets or set(owner_secrets) != set(other_secrets):
        raise ActiveExecutionError("Both identities must provide the same secret header names")
    if any(not isinstance(value, str) or not value for value in (*owner_secrets.values(), *other_secrets.values())):
        raise ActiveExecutionError("Secret headers must contain environment-variable references")
    if owner_secrets == other_secrets or set(owner_secrets.values()) & set(other_secrets.values()):
        raise ActiveExecutionError("Owner and comparison identities must use distinct secret references")


def execute_object_access_comparison(
    executor,
    engagement_id: str,
    task_id: str,
    owner_request_file: str,
    other_request_file: str,
    *,
    owner_identity: str,
    other_identity: str,
    object_reference: str,
) -> dict[str, Any]:
    """Execute an equivalent read-only request pair through ActiveHTTPExecutor.

    Manifests must be separately pinned in the approved task. If the second
    execution fails, the first response/evidence is returned as a partial
    result; callers must not report a comparison or retry automatically.
    """
    if not owner_identity.strip() or not other_identity.strip() or owner_identity == other_identity:
        raise ActiveExecutionError("Two distinct non-empty synthetic identity labels are required")
    if not object_reference.strip():
        raise ActiveExecutionError("A stable synthetic object reference is required")

    owner_manifest = _load_manifest(executor, owner_request_file)
    other_manifest = _load_manifest(executor, other_request_file)
    _validate_pair(owner_manifest, other_manifest)

    # execute_request_file enforces task state, engagement approval, scope,
    # pinned SHA-256 manifests, rate limits, request uniqueness and evidence.
    owner_result = executor.execute_request_file(
        engagement_id, task_id, owner_request_file
    )
    try:
        other_result = executor.execute_request_file(
            engagement_id, task_id, other_request_file
        )
    except Exception as exc:
        return {
            "status": "partial_execution",
            "test_type": "object_level_authorization_comparison",
            "owner_identity": owner_identity,
            "other_identity": other_identity,
            "object_reference": object_reference,
            "owner_response": owner_result,
            "other_response": None,
            "evidence_refs": list(owner_result.get("evidence_refs") or []),
            "error": str(exc)[:300],
            "limitations": [
                "Only the owner-side request completed; no authorization comparison was performed.",
                "Do not automatically replay either request; inspect the broker log and create a newly reviewed plan if appropriate.",
            ],
        }

    comparison = compare_object_access(
        owner_result,
        other_result,
        owner_identity=owner_identity,
        other_identity=other_identity,
        object_reference=object_reference,
    )
    return {
        "status": "comparison_completed",
        "owner_response": owner_result,
        "other_response": other_result,
        "comparison": comparison,
        "evidence_refs": comparison["evidence_refs"],
    }
