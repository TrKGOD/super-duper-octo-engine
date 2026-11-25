"""In-memory authentication transport bound to an approved engagement origin.

Only GET discovery/JWKS and POST token/form exchanges are supported. Responses containing
tokens never enter evidence, audit events, task payloads or logs.
"""
import json
from urllib.parse import urlencode, urljoin, urlsplit

from core.active_executor import (
    ActiveExecutionError, _resolve_and_authorize, _PinnedHTTPConnection,
)
import ssl
import time


class BrokerAuthTransport:
    def __init__(self, workflow, engagement_id, task_scope, base_url, timeout=5):
        self.workflow = workflow
        self.engagement_id = engagement_id
        self.task_scope = list(task_scope)
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = min(max(float(timeout), 1), 8)
        self._validate_base()

    def _validate_base(self):
        row = self.workflow.store.connection.execute(
            "SELECT status,scope_json,rules_json,authorization_reference FROM engagements WHERE engagement_id=?",
            (self.engagement_id,),
        ).fetchone()
        if not row or row["status"] != "active":
            raise ActiveExecutionError("Authentication transport requires an active approved engagement")
        import json
        rules = json.loads(row["rules_json"])
        if rules.get("execution_enabled") is not True or rules.get("authorization_verified") is not True:
            raise ActiveExecutionError("Authentication transport requires explicit engagement approval")
        if "authentication-http" not in set(rules.get("allowed_test_classes", [])):
            raise ActiveExecutionError("Engagement does not explicitly allow authentication-http")
        if not row["authorization_reference"] or "REQUIRED" in row["authorization_reference"].upper():
            raise ActiveExecutionError("Authentication transport requires a written authorization reference")
        self.scope = json.loads(row["scope_json"])
        _resolve_and_authorize(self.base_url, self.scope, self.task_scope)

    def __call__(self, method, path, fields=None, purpose="authentication exchange"):
        method = str(method).upper()
        if method not in {"GET", "POST"}:
            raise ActiveExecutionError("Authentication transport permits only GET and POST")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ActiveExecutionError("Authentication endpoint must be an origin-relative absolute path")
        url = urljoin(self.base_url, path.lstrip("/"))
        base, target = urlsplit(self.base_url), urlsplit(url)
        if (base.scheme, base.hostname, base.port) != (target.scheme, target.hostname, target.port):
            raise ActiveExecutionError("Authentication endpoint cannot change origin")
        host, port, pinned_ip, parsed = _resolve_and_authorize(url, self.scope, self.task_scope)
        body = None
        headers = {"Accept": "application/json", "Accept-Encoding": "identity",
                   "User-Agent": "Hackbot-AuthBroker/1.0"}
        if method == "POST":
            if not isinstance(fields, dict):
                raise ActiveExecutionError("Authentication POST requires form fields")
            body = urlencode(fields).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection = _PinnedHTTPConnection(
            host, port, pinned_ip, self.timeout,
            ssl.create_default_context() if parsed.scheme == "https" else None,
        )
        try:
            request_path = parsed.path or "/"
            if parsed.query:
                request_path += "?" + parsed.query
            connection.request(method, request_path, body=body, headers=headers)
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                raise ActiveExecutionError("Authentication endpoint redirects are blocked")
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ActiveExecutionError("Authentication response exceeds 64 KiB")
            if response.status < 200 or response.status >= 300:
                raise ActiveExecutionError("Authentication endpoint returned HTTP " + str(response.status))
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ActiveExecutionError("Authentication endpoint must return a JSON object") from exc
            if not isinstance(payload, dict):
                raise ActiveExecutionError("Authentication endpoint response must be an object")
            return payload
        finally:
            connection.close()
