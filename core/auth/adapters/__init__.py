"""Authentication adapters. Network I/O is injected by the broker/operator, never implicit."""
from core.auth.adapters.base import AuthAdapter
from core.auth.adapters.form import FormAuthAdapter
from core.auth.adapters.oauth2 import OAuth2Adapter
from core.auth.adapters.oidc import OIDCAdapter
from core.auth.adapters.cookie import CookieSessionAdapter
from core.auth.adapters.jwt import JWTAdapter
from core.auth.adapters.api_key import APIKeyAdapter
from core.auth.adapters.browser import BrowserAuthAdapter
__all__ = ["AuthAdapter", "FormAuthAdapter", "OAuth2Adapter", "OIDCAdapter",
           "CookieSessionAdapter", "JWTAdapter", "APIKeyAdapter", "BrowserAuthAdapter"]
