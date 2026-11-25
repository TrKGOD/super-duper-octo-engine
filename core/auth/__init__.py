"""Engagement-scoped authentication lifecycle for the active HTTP broker."""
from core.auth.manager import AuthenticationManager, AuthState, AuthPolicy, AuthError
from core.auth.session_store import SessionStore
from core.auth.adapters import (
    AuthAdapter, FormAuthAdapter, OAuth2Adapter, OIDCAdapter,
    CookieSessionAdapter, JWTAdapter, APIKeyAdapter, BrowserAuthAdapter,
)

__all__ = [
    "AuthenticationManager", "AuthState", "AuthPolicy", "AuthError", "SessionStore",
    "AuthAdapter", "FormAuthAdapter", "OAuth2Adapter", "OIDCAdapter",
    "CookieSessionAdapter", "JWTAdapter", "APIKeyAdapter", "BrowserAuthAdapter",
]
