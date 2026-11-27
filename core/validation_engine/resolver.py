"""Resolve validation evidence from the vault — never from the caller.

Before this layer the oracles ran on whatever response bodies the *caller* put in the request;
the ``*_refs`` lists were recorded but never loaded, never integrity-checked and never even
checked to exist. An agent could therefore "validate" its own claim by passing fabricated
bodies next to plausible-looking ids.

With a resolver configured the engine accepts **only references**. For every role the resolver

* loads the evidence row and requires it to belong to *this* engagement,
* requires the expected evidence type,
* reads the artifact once through the vault (SHA-256 verified, decrypted if encrypted),
* rebuilds the oracle input from those verified bytes, and
* returns a descriptor (role, id, SHA-256, producing execution) that is written into the
  validation record, so the record proves *which* bytes it was computed from.

Inline raw inputs are refused outright. Policy facts (object ownership, role restrictions) come
from :mod:`core.validation_engine.facts`, not from the request.
"""
from __future__ import annotations

import json

from core.authorization_testing import response_fingerprint
from core.evidence import EvidenceError
from core.validation_engine.errors import EvidenceResolutionError, ValidationError

RESPONSE = "http_response"
REQUEST = "http_request"

# vulnerability class -> evidence roles, raw inline inputs that are refused, caller context keys
SPECS = {
    "object_authorization": {
        "roles": {"owner_response": RESPONSE, "other_response": RESPONSE},
        "inline": ("owner_response", "other_response", "ownership_confirmed"),
        "context": ("owner_identity", "other_identity", "object_reference")},
    "function_authorization": {
        "roles": {"baseline_response": RESPONSE, "lower_privilege_response": RESPONSE},
        "inline": ("baseline_response", "lower_privilege_response", "role_restriction_confirmed"),
        "context": ("baseline_role", "comparison_role", "function_reference")},
    "sqli": {
        "roles": {"baseline": RESPONSE, "true_case": RESPONSE, "false_case": RESPONSE},
        "inline": ("samples", "timing_samples_ms"),
        "context": ()},
    "reflected_input": {
        "roles": {"request": REQUEST, "response": RESPONSE},
        "inline": ("response_body", "response_headers", "context"),
        "context": ("marker",)},
    "security_header": {
        "roles": {"response": RESPONSE},
        "inline": ("response_headers",),
        "context": ("required_header",)},
}


class EvidenceResolver:
    def __init__(self, vault, engagement_id: str):
        self.vault = vault
        self.engagement_id = engagement_id

    # -- loading --------------------------------------------------------------------------
    def _load(self, evidence_id, role: str, evidence_type: str):
        row = self.vault.store.connection.execute(
            "SELECT evidence_id,engagement_id,evidence_type,sha256,execution_id FROM evidence WHERE evidence_id=?",
            (evidence_id,)).fetchone() if isinstance(evidence_id, str) and evidence_id else None
        if row is None or row["engagement_id"] != self.engagement_id:
            # A foreign engagement's evidence is indistinguishable from a missing one.
            raise EvidenceResolutionError(f"Evidence for role '{role}' is unknown or not part of this engagement")
        if row["evidence_type"] != evidence_type:
            raise EvidenceResolutionError(
                f"Evidence for role '{role}' must be of type '{evidence_type}', not '{row['evidence_type']}'")
        try:
            data = self.vault.read(evidence_id)
        except EvidenceError as exc:
            raise EvidenceResolutionError(f"Evidence for role '{role}' failed integrity verification") from exc
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceResolutionError(f"Evidence for role '{role}' is not a structured HTTP artifact") from exc
        if not isinstance(payload, dict):
            raise EvidenceResolutionError(f"Evidence for role '{role}' is not a structured HTTP artifact")
        descriptor = {"role": role, "evidence_id": evidence_id, "sha256": row["sha256"],
                      "evidence_type": row["evidence_type"], "execution_id": row["execution_id"]}
        return payload, descriptor

    def response(self, evidence_id, role: str):
        payload, descriptor = self._load(evidence_id, role, RESPONSE)
        status = payload.get("status")
        if not isinstance(status, int) or isinstance(status, bool):
            raise EvidenceResolutionError(f"Response evidence for role '{role}' has no HTTP status")
        result = {"status_code": status, "response_headers": payload.get("headers") or {},
                  "response_excerpt": payload.get("body"),
                  "response_body_truncated": bool(payload.get("body_truncated")),
                  "url": payload.get("url"), "evidence_refs": [evidence_id]}
        return result, descriptor

    def request(self, evidence_id, role: str):
        payload, descriptor = self._load(evidence_id, role, REQUEST)
        return {"method": payload.get("method"), "url": payload.get("url"), "body": payload.get("body"),
                "evidence_refs": [evidence_id]}, descriptor

    # -- building oracle input ---------------------------------------------------------------
    def materialize(self, vulnerability_class: str, request: dict, facts=None):
        """Return ``(oracle_request, descriptors)`` built only from verified evidence."""
        spec = SPECS.get(vulnerability_class)
        if spec is None:
            raise ValidationError("No evidence specification for vulnerability class: " + str(vulnerability_class))
        for key in spec["inline"]:
            if key in request:
                raise ValidationError(
                    f"Inline '{key}' is not accepted when evidence is resolved from the vault; "
                    "supply evidence references (and let policy facts come from the control plane)")
        references = request.get("evidence")
        if not isinstance(references, dict):
            raise ValidationError("Validation requires an 'evidence' mapping of role -> evidence id")
        unknown_roles = set(references) - set(spec["roles"])
        missing_roles = set(spec["roles"]) - set(references)
        if unknown_roles or missing_roles:
            raise ValidationError(
                f"Evidence roles for {vulnerability_class} must be exactly {sorted(spec['roles'])}"
                + (f" (missing: {sorted(missing_roles)})" if missing_roles else ""))
        if len({references[role] for role in spec["roles"]}) != len(spec["roles"]):
            raise ValidationError("Each evidence role must reference a distinct artifact")

        loaded, descriptors = {}, []
        for role, evidence_type in spec["roles"].items():
            loader = self.response if evidence_type == RESPONSE else self.request
            loaded[role], descriptor = loader(references[role], role)
            descriptors.append(descriptor)
        context = {key: request[key] for key in spec["context"] if key in request}
        builder = getattr(self, "_build_" + vulnerability_class)
        return builder(loaded, context, facts), descriptors

    def _build_object_authorization(self, loaded, context, facts):
        owner_identity = context.get("owner_identity")
        owner_of_object = facts.object_owner(context.get("object_reference", "")) if facts is not None else None
        return {**context, "owner_response": loaded["owner_response"], "other_response": loaded["other_response"],
                # policy fact from the control plane, never from the caller
                "ownership_confirmed": bool(owner_of_object) and owner_of_object == owner_identity}

    def _build_function_authorization(self, loaded, context, facts):
        confirmed = facts is not None and facts.role_restriction(
            context.get("function_reference", ""), context.get("baseline_role", ""), context.get("comparison_role", ""))
        return {**context, "baseline_response": loaded["baseline_response"],
                "lower_privilege_response": loaded["lower_privilege_response"],
                "role_restriction_confirmed": bool(confirmed)}

    def _build_sqli(self, loaded, context, facts):
        samples = {}
        for role in ("baseline", "true_case", "false_case"):
            body = loaded[role]["response_excerpt"] or ""
            samples[role] = {"status_code": loaded[role]["status_code"], "body_excerpt": body,
                             # computed here from verified bytes, not asserted by the caller
                             "normalized_fingerprint": response_fingerprint(body),
                             "evidence_refs": loaded[role]["evidence_refs"]}
        return {"samples": samples}

    def _build_reflected_input(self, loaded, context, facts):
        marker = str(context.get("marker", "")).strip()
        sent = f"{loaded['request'].get('url') or ''} {loaded['request'].get('body') or ''}"
        if not marker or marker not in sent:
            raise ValidationError("The marker was not part of the executed request recorded as evidence")
        content_type = next((str(v) for k, v in loaded["response"]["response_headers"].items()
                             if str(k).lower() == "content-type"), "")
        is_html = "html" in content_type.lower()
        return {"marker": marker, "response_body": loaded["response"]["response_excerpt"] or "",
                # The execution context cannot be proven from a response body alone, so the engine
                # never asserts one: HTML reflection stays inconclusive until it is established.
                "context": "unknown" if is_html else "non_html"}

    def _build_security_header(self, loaded, context, facts):
        return {**context, "response_headers": loaded["response"]["response_headers"]}
