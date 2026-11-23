"""Scope-enforced HTTP execution broker for explicitly approved engagements.

The broker deliberately supports a narrow HTTP surface. It is not a sandbox:
run it inside an isolated environment with outbound network policy as well.
"""
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from core.evidence import EvidenceVault
from core.execution_policy import validate_execution_limits

ROOT = Path(__file__).resolve().parents[1]
REQUEST_SCHEMA = json.loads((ROOT / "templates/active-http-request.schema.json").read_text(encoding="utf-8"))


class ActiveExecutionError(RuntimeError):
    """Raised when an active request violates engagement policy or cannot execute."""


def _safe_asset_host(asset):
    value = str(asset).strip().lower()
    if "://" in value:
        parsed = urlsplit(value)
        return (parsed.hostname or "").rstrip(".")
    return value.rstrip(".")


def _host_matches(host, entry):
    candidate = _safe_asset_host(entry)
    if not candidate:
        return False
    if candidate.startswith("*."):
        suffix = candidate[2:]
        return host != suffix and host.endswith("." + suffix)
    return host == candidate


def _ip_in_scope(address, scope):
    ip = ipaddress.ip_address(address)
    for item in scope.get("allowed_ips", []):
        try:
            if ip == ipaddress.ip_address(str(item)):
                return True
        except ValueError:
            continue
    for item in scope.get("allowed_cidrs", []):
        try:
            if ip in ipaddress.ip_network(str(item), strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_excluded(host, addresses, scope):
    for item in scope.get("excluded_assets", []):
        value = str(item).strip()
        try:
            network = ipaddress.ip_network(value, strict=False)
            if any(ipaddress.ip_address(address) in network for address in addresses):
                return True
            continue
        except ValueError:
            pass
        if _host_matches(host, value):
            return True
    return False


def _application_match(url, applications):
    parsed = urlsplit(url)
    origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme == "https" else 80))
    for item in applications:
        candidate = urlsplit(str(item))
        if not candidate.scheme or not candidate.hostname:
            continue
        candidate_origin = (
            candidate.scheme.lower(), candidate.hostname.lower(),
            candidate.port or (443 if candidate.scheme == "https" else 80),
        )
        if candidate_origin != origin:
            continue
        prefix = candidate.path.rstrip("/")
        if not prefix or parsed.path == prefix or parsed.path.startswith(prefix + "/"):
            return True
    return False


def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _validate_request_scope(url, scope, task_scope):
    """Validate the URL against allowlists without performing DNS or network activity."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ActiveExecutionError("Only absolute HTTP/HTTPS URLs are permitted")
    if parsed.username or parsed.password or parsed.fragment:
        raise ActiveExecutionError("URL userinfo and fragments are not permitted")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    domain_allowed = any(_host_matches(host, item) for item in scope.get("allowed_domains", []))
    app_allowed = _application_match(url, scope.get("allowed_applications", []))
    literal_allowed = _ip_in_scope(host, scope) if _is_ip_literal(host) else False
    allowed_ports = {int(item) for item in scope.get("allowed_http_ports", [])}
    if port not in {80, 443} and port not in allowed_ports and not app_allowed:
        raise ActiveExecutionError("Destination port is not explicitly allowed")
    if not (domain_allowed or app_allowed or literal_allowed):
        raise ActiveExecutionError("Target hostname/IP is not explicitly in the engagement allowlist")
    literal_addresses = [host] if _is_ip_literal(host) else []
    if _is_excluded(host, literal_addresses, scope):
        raise ActiveExecutionError("Target matches an excluded asset")
    task_host_allowed = any(
        _application_match(url, [item]) if "://" in str(item) else _host_matches(host, item)
        for item in task_scope
    )
    task_ip_allowed = any(
        _ip_in_scope(address, {"allowed_ips": list(task_scope), "allowed_cidrs": list(task_scope)})
        for address in literal_addresses
    )
    if not (task_host_allowed or task_ip_allowed):
        raise ActiveExecutionError("Target is outside this task's assigned scope subset")
    return host, port, parsed


def _resolve_and_authorize(url, scope, task_scope):
    host, port, parsed = _validate_request_scope(url, scope, task_scope)

    try:
        literal_ip = ipaddress.ip_address(host)
        addresses = [str(literal_ip)]
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ActiveExecutionError("DNS resolution failed for in-scope hostname") from exc
        addresses = sorted({answer[4][0] for answer in answers})
    if not addresses:
        raise ActiveExecutionError("Hostname did not resolve to an address")

    if _is_excluded(host, addresses, scope):
        raise ActiveExecutionError("Target matches an excluded asset")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global and not _ip_in_scope(address, scope):
            raise ActiveExecutionError("DNS resolved to a non-public IP that is not explicitly in scope")
    task_host_allowed = any(
        _application_match(url, [item]) if "://" in str(item) else _host_matches(host, item)
        for item in task_scope
    )
    task_ip_allowed = any(
        _ip_in_scope(address, {"allowed_ips": list(task_scope), "allowed_cidrs": list(task_scope)})
        for address in addresses
    )
    if not (task_host_allowed or task_ip_allowed):
        raise ActiveExecutionError("Target is outside this task's assigned scope subset")
    return host, port, addresses[0], parsed


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, pinned_ip, timeout, ssl_context=None):
        super().__init__(host=host, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip
        self.ssl_context = ssl_context

    def connect(self):
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        if self.ssl_context is not None:
            self.sock = self.ssl_context.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw


def _redact_text(value):
    text = value
    text = re.sub(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s,;]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[\"']?\s*[:=]\s*[\"']?)[^\"'\s&,}]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(set-cookie\s*[:=]\s*)[^;\r\n]+", r"\1[REDACTED]", text)
    return text


def _cookie_security_flags(headers):
    """Expose cookie attributes only; never return cookie names or values."""
    result = []
    for key, value in headers.items():
        if str(key).lower() != "set-cookie":
            continue
        parts = [part.strip() for part in str(value).split(";")[1:]]
        flags = []
        for part in parts:
            name, _, setting = part.partition("=")
            normalized = name.strip().lower()
            if normalized in {"secure", "httponly"}:
                flags.append(normalized)
            elif normalized == "samesite":
                flags.append("samesite=" + setting.strip().lower())
        result.append(sorted(set(flags)))
    return result


def _is_sensitive_name(name):
    normalized = re.sub(r"[^a-z0-9]", "", str(name).lower())
    return any(term in normalized for term in (
        "authorization", "authtoken", "token", "secret", "password",
        "apikey", "accesskey", "cookie", "session", "oauthcode",
    ))


def _strip_sensitive_query(url):
    parsed = urlsplit(url)
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if not _is_sensitive_name(key)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _safe_url(url):
    parsed = urlsplit(url)
    query = [(key, "[REDACTED]" if _is_sensitive_name(key) else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _safe_headers(headers):
    result = {}
    for key, value in headers.items():
        if _is_sensitive_name(key) or key.lower() == "set-cookie":
            result[key] = "[REDACTED]"
        else:
            result[key] = _redact_text(str(value))
    return result


def _validate_request(request):
    from jsonschema import Draft202012Validator
    errors = list(Draft202012Validator(REQUEST_SCHEMA).iter_errors(request))
    if errors:
        raise ActiveExecutionError("Invalid request file: " + "; ".join(error.message for error in errors))
    method = request["method"].upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
        raise ActiveExecutionError("HTTP method is not permitted by the active broker")
    if method == "POST":
        approval = request.get("operator_approval", {})
        try:
            approved_at = datetime.fromisoformat(approval.get("approved_at", "").replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            approved_at = None
        if not (
            approval.get("approved") is True
            and isinstance(approval.get("approved_by"), str) and approval["approved_by"].strip()
            and approved_at is not None and approved_at.tzinfo is not None
            and approved_at <= datetime.now(timezone.utc)
            and isinstance(approval.get("reason"), str) and len(approval["reason"].strip()) >= 10
        ):
            raise ActiveExecutionError("POST requires a timestamped, explicit operator approval in the request manifest")
    forbidden_headers = {
        "host", "content-length", "transfer-encoding", "connection",
        "proxy-authorization", "proxy-connection", "upgrade", "te", "trailer", "accept-encoding",
    }
    sensitive_headers = {"authorization", "proxy-authorization", "cookie", "x-api-key"}
    for key, value in request.get("headers", {}).items():
        if key.lower() in forbidden_headers or key.lower() in sensitive_headers or _is_sensitive_name(key):
            raise ActiveExecutionError("Sensitive or broker-controlled headers must not be stored as plaintext; use secret_headers")
        if "\r" in key or "\n" in key or "\r" in str(value) or "\n" in str(value):
            raise ActiveExecutionError("HTTP headers must not contain line breaks")
    for key, env_name in request.get("secret_headers", {}).items():
        if key.lower() in forbidden_headers or not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", env_name):
            raise ActiveExecutionError("Invalid secret header name or environment-variable reference")
        if key.lower() in {item.lower() for item in request.get("headers", {})}:
            raise ActiveExecutionError("A header cannot be defined in both headers and secret_headers")
    body = request.get("body")
    if body is not None and (method != "POST" or not isinstance(body, str) or len(body.encode("utf-8")) > 16384):
        raise ActiveExecutionError("Only bounded text POST bodies are supported")
    return method


def _resolve_request_headers(request):
    headers = dict(request.get("headers", {}))
    for header_name, env_name in request.get("secret_headers", {}).items():
        value = os.environ.get(env_name)
        if not value:
            raise ActiveExecutionError("Required secret header environment variable is missing: " + env_name)
        if "\r" in value or "\n" in value:
            raise ActiveExecutionError("Secret header environment value contains a line break")
        headers[header_name] = value
    headers["Accept-Encoding"] = "identity"
    return headers


def _check_window(rules):
    window = rules.get("testing_window") or {}
    start, end = window.get("start"), window.get("end")
    if not start and not end:
        return
    if not start or not end:
        raise ActiveExecutionError("Testing window must define both start and end")
    try:
        now = datetime.now(timezone.utc)
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ActiveExecutionError("Testing window timestamps must be ISO-8601 with timezone") from exc
    if start_dt.tzinfo is None or end_dt.tzinfo is None or not start_dt <= now <= end_dt:
        raise ActiveExecutionError("Current time is outside the authorized testing window")


def _acquire_slot(connection, engagement_id, requests_per_second, lease_seconds=30):
    interval = 1.0 / float(requests_per_second)
    token = uuid.uuid4().hex
    while True:
        now = time.time()
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT last_started_epoch,lock_token,lock_expires_epoch FROM active_execution_state WHERE engagement_id=?",
            (engagement_id,),
        ).fetchone()
        if row and row["lock_token"] and row["lock_expires_epoch"] > now:
            connection.rollback()
            time.sleep(0.1)
            continue
        wait = max(0.0, interval - (now - (row["last_started_epoch"] if row else 0.0)))
        if wait > 0:
            connection.rollback()
            time.sleep(min(wait, 0.25))
            continue
        connection.execute(
            """INSERT INTO active_execution_state(engagement_id,last_started_epoch,lock_token,lock_expires_epoch)
               VALUES(?,?,?,?) ON CONFLICT(engagement_id) DO UPDATE SET
               last_started_epoch=excluded.last_started_epoch,lock_token=excluded.lock_token,
               lock_expires_epoch=excluded.lock_expires_epoch""",
            (engagement_id, now, token, now + lease_seconds),
        )
        connection.commit()
        return token


def _release_slot(connection, engagement_id, token):
    with connection:
        connection.execute(
            "UPDATE active_execution_state SET lock_token=NULL,lock_expires_epoch=0 WHERE engagement_id=? AND lock_token=?",
            (engagement_id, token),
        )


def _send_once(url, method, headers, body, timeout, max_response_bytes, pinned_ip):
    parsed = urlsplit(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    context = ssl.create_default_context() if parsed.scheme == "https" else None
    connection = _PinnedHTTPConnection(host, port, pinned_ip, min(timeout, 3), context)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        deadline = time.monotonic() + timeout
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        chunks = []
        total = 0
        while total <= max_response_bytes:
            if time.monotonic() > deadline:
                raise TimeoutError("HTTP response exceeded the total request timeout")
            chunk = response.read1(min(8192, max_response_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
        truncated = len(payload) > max_response_bytes
        payload = payload[:max_response_bytes]
        response_headers = {key: value for key, value in response.getheaders()}
        content_type = next((value for key, value in response_headers.items() if key.lower() == "content-type"), "")
        content_encoding = next((value for key, value in response_headers.items() if key.lower() == "content-encoding"), "identity")
        text_body = None
        if content_encoding.lower() in {"", "identity"} and any(kind in content_type.lower() for kind in ("text/", "json", "xml", "javascript", "x-www-form-urlencoded")):
            text_body = _redact_text(payload.decode("utf-8", errors="replace"))
        return response.status, response_headers, text_body, truncated, response.getheader("Location")
    finally:
        connection.close()


class ActiveHTTPExecutor:
    def __init__(self, workflow, project_root=ROOT):
        self.workflow = workflow
        self.project_root = Path(project_root).resolve()
        self.vault = EvidenceVault(workflow.store, self.project_root)

    def execute_request_file(self, engagement_id, task_id, request_file):
        task_row = self.workflow.store.connection.execute(
            """SELECT t.agent,t.status,t.input_json,e.status AS engagement_status,
                      e.scope_json,e.rules_json,e.authorization_reference
               FROM tasks t JOIN engagements e ON e.engagement_id=t.engagement_id
               WHERE t.task_id=? AND t.engagement_id=?""",
            (task_id, engagement_id),
        ).fetchone()
        if task_row is None:
            raise ActiveExecutionError("Task does not belong to the requested engagement")
        allowed_agents = {"active-testing-agent", "exploitation-agent", "validation-agent", "recon-agent", "enumeration-agent", "vulnerability-agent"}
        if task_row["agent"] not in allowed_agents or task_row["status"] != "running":
            raise ActiveExecutionError("Only a running scoped assessment specialist can invoke the broker")
        task = json.loads(task_row["input_json"])
        if task.get("active_testing") is not True:
            raise ActiveExecutionError("Task is not marked for active testing")
        rules = json.loads(task_row["rules_json"])
        if (
            task_row["engagement_status"] != "active"
            or rules.get("execution_mode", "active") != "active"
            or rules.get("execution_enabled") is not True
            or rules.get("authorization_verified") is not True
            or not task_row["authorization_reference"]
            or "REQUIRED" in task_row["authorization_reference"].upper()
        ):
            raise ActiveExecutionError("Engagement is not explicitly approved for active execution")
        try:
            _, rps, request_budget = validate_execution_limits(rules)
        except ValueError as exc:
            raise ActiveExecutionError(str(exc)) from exc
        executed_count = self.workflow.store.connection.execute(
            "SELECT COUNT(*) FROM active_request_log WHERE engagement_id=?", (engagement_id,)
        ).fetchone()[0]
        if executed_count >= request_budget:
            raise ActiveExecutionError("Engagement active HTTP request budget has been exhausted")
        _check_window(rules)

        request_path = Path(request_file)
        if request_path.is_absolute() or ".." in request_path.parts or request_path.parts[:2] != (".local", "requests"):
            raise ActiveExecutionError("Request files must be confined to .local/requests/")
        candidate = self.project_root / request_path
        if candidate.is_symlink():
            raise ActiveExecutionError("Request file must not be a symlink")
        resolved = candidate.resolve(strict=True)
        local_root = self.project_root / ".local"
        if local_root.is_symlink() or (self.project_root / ".local" / "requests").is_symlink():
            raise ActiveExecutionError(".local and .local/requests must not be symlinks")
        requests_root = (self.project_root / ".local" / "requests").resolve(strict=True)
        if not requests_root.is_relative_to(self.project_root) or not resolved.is_file() or not resolved.is_relative_to(requests_root):
            raise ActiveExecutionError("Request file is not a regular file inside .local/requests/")
        if resolved.stat().st_size > 65536:
            raise ActiveExecutionError("Request manifest exceeds 64 KiB")
        relative = request_path.as_posix()
        pinned = next(
            (item for item in task.get("request_files", []) + task.get("generated_request_files", [])
             if item.get("path") == relative),
            None,
        )
        if not pinned:
            raise ActiveExecutionError("Request file was not pinned in the approved plan or generated by the bounded discovery tool")
        raw_manifest = resolved.read_bytes()
        digest = hashlib.sha256(raw_manifest).hexdigest()
        if digest != pinned.get("sha256"):
            raise ActiveExecutionError("Request file changed after the plan was approved")
        try:
            request = json.loads(raw_manifest)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ActiveExecutionError("Request file must contain valid UTF-8 JSON") from exc
        method = _validate_request(request)

        scope = json.loads(task_row["scope_json"])
        rules_classes = set(rules.get("allowed_test_classes", []))
        if method == "POST":
            if "state-changing-http" not in rules_classes or rules.get("human_approval_required_for_state_changes") is not True:
                raise ActiveExecutionError("State-changing HTTP is not authorized by engagement rules")
        elif "http-read-only" not in rules_classes:
            raise ActiveExecutionError("http-read-only is not an allowed test class")

        task_scope = task.get("scope_subset", [])
        url = request["url"]
        request_id = request["request_id"]
        host, port, pinned_ip, parsed = _resolve_and_authorize(url, scope, task_scope)
        existing = self.workflow.store.connection.execute(
            "SELECT 1 FROM active_request_log WHERE engagement_id=? AND request_id=?",
            (engagement_id, request_id),
        ).fetchone()
        if existing:
            raise ActiveExecutionError("Request ID has already been executed; create a new reviewed manifest")

        connection = self.workflow.store.connection
        token = _acquire_slot(connection, engagement_id, rps, lease_seconds=max(30, request.get("timeout_seconds", 8) + 10))
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            with connection:
                current_count = connection.execute(
                    "SELECT COUNT(*) FROM active_request_log WHERE engagement_id=?", (engagement_id,)
                ).fetchone()[0]
                if current_count >= request_budget:
                    raise ActiveExecutionError("Engagement active HTTP request budget has been exhausted")
                connection.execute(
                    """INSERT INTO active_request_log
                       (execution_id,engagement_id,task_id,request_id,target_host,method,started_at,outcome,evidence_refs_json)
                       VALUES(?,?,?,?,?,?,?,'running','[]')""",
                    (uuid.uuid4().hex, engagement_id, task_id, request_id, host, method, started_at),
                )
        except Exception:
            _release_slot(connection, engagement_id, token)
            raise
        try:
            headers = _resolve_request_headers(request)
            headers.setdefault("User-Agent", "PentestAgentFramework/0.1 (+authorized-security-testing)")
            body = request.get("body")
            current_url = url
            redirects = 0
            while True:
                status, response_headers, response_body, truncated, location = _send_once(
                    current_url, method, headers, body,
                    request.get("timeout_seconds", 8),
                    request.get("max_response_bytes", 131072),
                    pinned_ip,
                )
                if status not in {301, 302, 303, 307, 308} or not location or not request.get("follow_redirects", True):
                    break
                if method == "POST":
                    raise ActiveExecutionError("POST redirects are disabled")
                if redirects >= 2:
                    raise ActiveExecutionError("Redirect limit exceeded")
                next_url = urljoin(current_url, location)
                next_host, next_port, next_ip, next_parsed = _resolve_and_authorize(next_url, scope, task_scope)
                if parsed.scheme == "https" and next_parsed.scheme != "https":
                    raise ActiveExecutionError("HTTPS-to-HTTP redirect downgrade blocked")
                previous_origin = (parsed.scheme, host, port)
                next_origin = (next_parsed.scheme, next_host, next_port)
                if next_parsed.scheme == "http" and parsed.scheme == "https":
                    raise ActiveExecutionError("HTTPS-to-HTTP redirect downgrade blocked")
                if next_origin != previous_origin:
                    headers = {key: value for key, value in headers.items() if not _is_sensitive_name(key)}
                    next_url = _strip_sensitive_query(next_url)
                current_url, host, port, pinned_ip, parsed = next_url, next_host, next_port, next_ip, next_parsed
                redirects += 1

            safe_request = {
                "request_id": request_id, "method": method, "url": _safe_url(url),
                "headers": _safe_headers(headers),
                "body": _redact_text(body) if isinstance(body, str) else None,
            }
            safe_response = {
                "url": _safe_url(current_url), "status": status,
                "headers": _safe_headers(response_headers),
                "cookie_security_flags": _cookie_security_flags(response_headers),
                "body": response_body, "body_truncated": truncated,
                "note": "Text body and sensitive headers were best-effort redacted before evidence storage.",
            }
            request_artifact = self.vault.capture(
                engagement_id, "http_request", request_id + "-request.json",
                json.dumps(safe_request, ensure_ascii=False, indent=2).encode(),
                task_row["agent"], redacted=True,
            )
            response_artifact = self.vault.capture(
                engagement_id, "http_response", request_id + "-response.json",
                json.dumps(safe_response, ensure_ascii=False, indent=2).encode(),
                task_row["agent"], redacted=True,
            )
            evidence_refs = [request_artifact["evidence_id"], response_artifact["evidence_id"]]
            finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with connection:
                connection.execute(
                    """UPDATE active_request_log SET status_code=?,finished_at=?,outcome='completed',evidence_refs_json=?
                       WHERE engagement_id=? AND request_id=?""",
                    (status, finished_at, json.dumps(evidence_refs), engagement_id, request_id),
                )
                self.workflow.store.append_audit(
                    engagement_id, task_row["agent"], "active_http.request_completed",
                    {"task_id": task_id, "request_id": request_id, "method": method,
                     "target_host": host, "status_code": status, "evidence_refs": evidence_refs,
                     "request_manifest_sha256": digest},
                )
            return {
                "request_id": request_id, "method": method, "target": host,
                "status_code": status, "redirects": redirects,
                "response_headers": _safe_headers(response_headers),
                "cookie_security_flags": _cookie_security_flags(response_headers),
                "response_excerpt": (response_body or "")[:65536],
                "response_body_truncated": truncated,
                "evidence_refs": evidence_refs,
            }
        except Exception as exc:
            with connection:
                connection.execute(
                    "UPDATE active_request_log SET finished_at=?,outcome='failed' WHERE engagement_id=? AND request_id=?",
                    (datetime.now(timezone.utc).isoformat(timespec="seconds"), engagement_id, request_id),
                )
                self.workflow.store.append_audit(
                    engagement_id, task_row["agent"], "active_http.request_failed",
                    {"task_id": task_id, "request_id": request_id, "target_host": host,
                     "reason": str(exc)[:300]},
                )
            raise
        finally:
            _release_slot(connection, engagement_id, token)
