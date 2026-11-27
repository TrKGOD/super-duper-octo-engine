"""Single source of truth for secret redaction.

Redaction used to be implemented in several places that had drifted apart: the HTTP broker
had three regexes, the redaction helper script had a broader set (AWS keys, JWTs, private
keys, ...), and structured values (dicts/lists) were only redacted at string leaves, so
``{"password": "hunter2"}`` leaked because the string ``"hunter2"`` carries no context.
Everything now goes through this module:

* :func:`redact` / :func:`redact_with_counts` — free text (evidence bodies, tool output,
  exception messages, report text).
* :func:`redact_value` — structured data; additionally redacts by *key name*.
* :func:`is_sensitive_name` — header / query-parameter / field names that must never be
  persisted or echoed.

Redaction is **best effort**: a pattern set cannot recognise every secret. It is a safety
net layered on top of "secrets are never put there in the first place" (credentials are
resolved from environment references and handed to the broker out-of-band).
"""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# (name, compiled pattern, keep_prefix). When ``keep_prefix`` is true group(1) is the
# non-secret prefix (header name, key name, URL scheme) that is retained.
_SECRET_PATTERNS = (
    ("private_key", re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
        r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", re.S), False),
    ("authorization_header", re.compile(
        r"(?i)(\bauthorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token|negotiate|digest)\s+)"
        r"[^\s,;\"'}]+"), True),
    ("cookie_header", re.compile(r"(?im)^(\s*(?:set-cookie|cookie)\s*:\s*).+$"), True),
    ("inline_set_cookie", re.compile(r"(?i)(set-cookie\s*[:=]\s*)[^;\r\n]+"), True),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), False),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"), False),
    ("github_token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b"), False),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), False),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), False),
    ("provider_secret_key", re.compile(
        r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b|\bsk-[A-Za-z0-9_-]{20,}\b"), False),
    ("url_credentials", re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@", re.I), True),
    ("credential_assignment", re.compile(
        r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
        r"|session[_-]?id|jsessionid|phpsessid)[\"']?\s*[:=]\s*[\"']?)[^\"'\s&,;}]+"), True),
)

_PII_PATTERNS = (
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), False),
)


def redact_with_counts(text, *, pii: bool = False) -> tuple[str, dict]:
    """Redact ``text`` and return ``(clean_text, {pattern_name: replacements})``."""
    result = text if isinstance(text, str) else str(text)
    counts: dict = {}
    for name, pattern, keep_prefix in _SECRET_PATTERNS + (_PII_PATTERNS if pii else ()):
        if keep_prefix:
            result, count = pattern.subn(lambda m: m.group(1) + REDACTED, result)
        else:
            result, count = pattern.subn(REDACTED, result)
        if count:
            counts[name] = count
    return result, counts


def redact(text, *, pii: bool = False) -> str:
    """Redact secrets (and, with ``pii=True``, e-mail addresses) from free text."""
    return redact_with_counts(text, pii=pii)[0]


# --- names -----------------------------------------------------------------------------

_SENSITIVE_NAME_TERMS = (
    "authorization", "authtoken", "token", "secret", "password", "passwd", "apikey",
    "accesskey", "privatekey", "cookie", "session", "oauthcode",
)
# NB: "credential" is deliberately absent. It would flag the non-secret CORS header
# ``Access-Control-Allow-Credentials: true`` and erase the evidence of a CORS finding.
# Identifier-like names that merely *mention* a sensitive word (``session_id``,
# ``token_endpoint``) must stay visible so audit trails remain traceable.
_IDENTIFIER_SUFFIXES = ("id", "ids", "count", "endpoint", "url", "uri", "type", "name",
                        "state", "ref", "reference", "hash", "sha256", "length", "path")


def is_sensitive_name(name) -> bool:
    """True for header / parameter / field names whose *value* must never be kept.

    This is the strict form used for HTTP headers and URL parameters (``session`` alone is
    sensitive there). Use :func:`is_secret_field` for structured audit/observation data.
    """
    normalized = re.sub(r"[^a-z0-9]", "", str(name).lower())
    return any(term in normalized for term in _SENSITIVE_NAME_TERMS)


def is_secret_field(name) -> bool:
    """True for structured-data keys that hold a secret (not merely an identifier of one)."""
    lowered = str(name).lower()
    normalized = re.sub(r"[^a-z0-9]", "", lowered)
    if not any(term in normalized for term in _SENSITIVE_NAME_TERMS):
        return False
    tokens = [t for t in re.split(r"[^a-z0-9]+", lowered) if t]
    if tokens and tokens[-1] in _IDENTIFIER_SUFFIXES:
        return False
    return True


def redact_value(value, *, pii: bool = False):
    """Recursively redact structured data by key name *and* by value pattern."""
    if isinstance(value, str):
        return redact(value, pii=pii)
    if isinstance(value, dict):
        cleaned = {}
        for key, child in value.items():
            if is_secret_field(key) and isinstance(child, (str, bytes, int, float)) \
                    and not isinstance(child, bool):
                cleaned[key] = REDACTED
            else:
                cleaned[key] = redact_value(child, pii=pii)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact_value(item, pii=pii) for item in value]
    return value
