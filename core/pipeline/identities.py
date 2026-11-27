"""Credentials for identities, expressed only as *environment references*.

The pipeline never sees a secret. For each graph identity the operator declares which request
header carries its credential and which environment variable holds the value; the broker resolves
the variable at send time (exactly as for hand-written manifests) and redacts it from evidence.
"""
from __future__ import annotations

import re

_ENV = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_FORBIDDEN = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer",
              "proxy-authorization", "proxy-connection", "accept-encoding"}


class IdentityDirectoryError(ValueError):
    pass


class IdentityDirectory:
    def __init__(self, mapping: dict):
        self._mapping: dict[str, dict[str, str]] = {}
        for identity, headers in (mapping or {}).items():
            if not isinstance(identity, str) or not identity.strip() or not isinstance(headers, dict) or not headers:
                raise IdentityDirectoryError("Each identity needs a non-empty header -> environment-variable mapping")
            checked = {}
            for header, env_name in headers.items():
                if not _HEADER.fullmatch(str(header)) or str(header).lower() in _FORBIDDEN:
                    raise IdentityDirectoryError("Invalid or forbidden credential header: " + str(header))
                if not isinstance(env_name, str) or not _ENV.fullmatch(env_name):
                    raise IdentityDirectoryError(
                        "Credentials are referenced by environment-variable NAME only (never a literal value)")
                checked[str(header)] = env_name
            self._mapping[identity] = checked

    def known(self) -> set:
        return set(self._mapping)

    def secret_headers(self, identity: str) -> dict | None:
        headers = self._mapping.get(identity)
        return dict(headers) if headers else None

    def distinct(self, first: str, second: str) -> bool:
        """Two identities must not share a credential reference, or the comparison compares nothing."""
        a, b = self._mapping.get(first), self._mapping.get(second)
        return bool(a and b) and not (set(a.values()) & set(b.values()))
