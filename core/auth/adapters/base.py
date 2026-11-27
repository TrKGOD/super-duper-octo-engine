"""Adapter contract: callbacks must use the engagement broker or explicit operator input."""
import re
from abc import ABC, abstractmethod

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
# Headers an authentication adapter may never set: they control framing/routing, so a
# poisoned configuration could otherwise smuggle or redirect the request.
FORBIDDEN_AUTH_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer",
    "proxy-authorization", "proxy-connection", "accept-encoding"})


def reject_unsafe_header_value(value, label):
    """Reject CR, LF and NUL in a secret that will become an HTTP header value.

    The previous checks compared against the two-character strings backslash-r / backslash-n
    and therefore never fired on a real line break.
    """
    if not isinstance(value, str) or not value or any(ch in value for ch in "\r\n\x00"):
        raise RuntimeError("Invalid " + label)
    return value


def validate_header_name(name):
    if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name) or name.lower() in FORBIDDEN_AUTH_HEADERS:
        raise RuntimeError("Invalid or forbidden authentication header name")
    return name

class AuthAdapter(ABC):
    name = "base"
    @abstractmethod
    def authenticate(self, config, secret_resolver, transport=None):
        raise NotImplementedError
    def refresh(self, material, config, secret_resolver, transport=None):
        return None
    def validate(self, material, config, transport=None):
        # Absence of a validator is not evidence that a session is valid.
        return None
    def headers(self, material, config):
        return dict(material.get("headers", {}))
