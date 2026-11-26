"""Scope guard for browser interaction.

This reuses the HTTP broker's deterministic, DNS-free allowlist check
(``core.active_executor._validate_request_scope``) so the browser engine and the broker
share a single scope policy. There is intentionally no second policy engine here.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from core.active_executor import ActiveExecutionError, _validate_request_scope


def _origin(url: str) -> str:
    parsed = urlsplit(str(url))
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme.lower()}://{host}:{port}"


class OriginScope:
    """Deterministic in-scope check backed by the engagement's broker allowlists."""

    def __init__(self, scope: dict, task_scope) -> None:
        self.scope = scope or {}
        self.task_scope = list(task_scope or [])

    def check(self, url: str) -> tuple[bool, str | None]:
        """Return ``(allowed, reason)``; ``reason`` is the rejection cause when blocked.

        A client-side routing fragment (hash route) is legitimate in a browser and is
        stripped before the server-oriented broker allowlist check, which rejects
        fragments for real HTTP requests.
        """
        try:
            parsed = urlsplit(str(url))
            probe = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
            _validate_request_scope(probe, self.scope, self.task_scope)
            return True, None
        except ActiveExecutionError as exc:
            return False, str(exc)
        except Exception as exc:  # malformed URL from untrusted content
            return False, "unparseable or non-HTTP URL: " + type(exc).__name__

    def allows(self, url: str) -> bool:
        return self.check(url)[0]

    def origin(self, url: str) -> str:
        return _origin(url)
