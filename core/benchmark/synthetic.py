"""Synthetic, broker-shaped HTTP evidence for benchmarks and tests.

The validation engine resolves evidence from the vault and refuses data embedded in a request,
so fixtures must put real artifacts in a real vault. These helpers write artifacts in exactly
the JSON shape the HTTP broker stores (``{"url","status","headers","body",...}``), tagged
``synthetic``. They never contain real engagement data.
"""
from __future__ import annotations

import json

_BODIES = {
    "same": (200, '{"id":7,"owner":"bob"}'),        # a non-owner receives the owner's representation
    "denied": (403, '{"error":"forbidden"}'),        # a non-owner is refused
    "granted": (200, '{"id":9,"owner":"carol"}'),    # a non-owner gets a different, successful response
}


def capture_http_response(vault, engagement_id: str, name: str, *, status: int = 200, body: str = "",
                          headers: dict | None = None, url: str = "https://app.local/api/orders/7",
                          execution_id: str | None = None, captured_by: str = "synthetic-fixture") -> str:
    artifact = {"url": url, "status": status, "headers": headers or {}, "cookie_security_flags": [],
                "body": body, "body_truncated": False, "note": "synthetic benchmark/test fixture"}
    stored = vault.capture(engagement_id, "http_response", name + "-response.json",
                           json.dumps(artifact, sort_keys=True).encode(), captured_by, redacted=True,
                           execution_id=execution_id)
    return stored["evidence_id"]


def capture_http_request(vault, engagement_id: str, name: str, *, url: str, method: str = "GET",
                         body: str | None = None, execution_id: str | None = None,
                         captured_by: str = "synthetic-fixture") -> str:
    artifact = {"request_id": name, "method": method, "url": url, "headers": {}, "body": body}
    stored = vault.capture(engagement_id, "http_request", name + "-request.json",
                           json.dumps(artifact, sort_keys=True).encode(), captured_by, redacted=True,
                           execution_id=execution_id)
    return stored["evidence_id"]


def bola_request(vault, engagement_id: str, tag: str, *, other: str = "same") -> dict:
    """An object-authorization validation request whose evidence lives in ``vault``."""
    owner_status, owner_body = _BODIES["same"]
    other_status, other_body = _BODIES[other]
    return {
        "vulnerability_class": "object_authorization",
        "evidence": {
            "owner_response": capture_http_response(vault, engagement_id, tag + "-owner",
                                                    status=owner_status, body=owner_body),
            "other_response": capture_http_response(vault, engagement_id, tag + "-other",
                                                    status=other_status, body=other_body),
        },
        "owner_identity": "bob", "other_identity": "alice", "object_reference": "order-7",
    }
