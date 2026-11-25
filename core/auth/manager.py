"""Session lifecycle and safe reauthentication orchestration."""
import os
import time
import uuid
from dataclasses import dataclass
from enum import Enum

from core.auth.adapters import (FormAuthAdapter, OAuth2Adapter, OIDCAdapter,
    CookieSessionAdapter, JWTAdapter, APIKeyAdapter, BrowserAuthAdapter)
from core.auth.session_store import SessionStoreError

class AuthError(RuntimeError): pass
class AuthState(str, Enum):
    UNAUTHENTICATED="UNAUTHENTICATED"
    AUTHENTICATING="AUTHENTICATING"
    AUTHENTICATED="AUTHENTICATED"
    EXPIRING="EXPIRING"
    EXPIRED="EXPIRED"
    REVOKED="REVOKED"
    CHALLENGE_REQUIRED="CHALLENGE_REQUIRED"
    RECOVERY_FAILED="RECOVERY_FAILED"

@dataclass(frozen=True)
class AuthPolicy:
    refresh_skew_seconds: int = 60
    automatic_reauth: bool = True
    retry_read_only_once: bool = True

class AuthenticationManager:
    ADAPTERS = {item.name:item for item in (FormAuthAdapter(),OAuth2Adapter(),OIDCAdapter(),
        CookieSessionAdapter(),JWTAdapter(),APIKeyAdapter(),BrowserAuthAdapter())}
    def __init__(self, store, engagement_id, policy=None, secret_resolver=None, audit=None,
                 transport=None, browser_runner=None):
        self.store, self.engagement_id = store, engagement_id
        self.policy = policy or AuthPolicy()
        self.secret_resolver = secret_resolver or self._env_secret
        self.audit = audit or (lambda event, details: None)
        self.transport = transport
        self.adapters = dict(self.ADAPTERS)
        self.adapters["browser"] = BrowserAuthAdapter(browser_runner)

    @staticmethod
    def _env_secret(name):
        value=os.environ.get(name)
        if not value: raise AuthError("Required credential environment variable is unavailable: "+str(name))
        return value

    def register_identity(self, identity_id, adapter, config):
        if adapter not in self.adapters: raise AuthError("Unsupported authentication adapter")
        self.store.register_identity(self.engagement_id, identity_id, adapter, config)
        self.audit("auth.identity_registered", {"identity_id":identity_id,"adapter":adapter})

    def authenticate(self, identity_id, transport=None):
        identity=self.store.identity(self.engagement_id, identity_id)
        adapter=self.adapters[identity["adapter"]]
        result=adapter.authenticate(identity["config"], self.secret_resolver, transport or self.transport)
        if result.get("challenge_required"):
            self.audit("auth.challenge_required", {"identity_id":identity_id,"adapter":identity["adapter"]})
            raise AuthError("Human authentication step required (MFA/CAPTCHA/passkey/approval); automation paused")
        session_id="sess_"+uuid.uuid4().hex
        expires_at=result.get("expires_at")
        if isinstance(expires_at, str):
            try: expires_at=float(expires_at)
            except ValueError: expires_at=None
        self.store.put(session_id,self.engagement_id,identity_id,AuthState.AUTHENTICATED.value,result,expires_at)
        self.audit("auth.session_authenticated", {"identity_id":identity_id,"session_id":session_id,"adapter":identity["adapter"]})
        return session_id

    def _recover(self, session_id, identity_id, transport=None):
        identity=self.store.identity(self.engagement_id, identity_id)
        current=self.store.get(session_id,self.engagement_id,identity_id)
        adapter=self.adapters[identity["adapter"]]
        self.store.set_state(session_id,self.engagement_id,identity_id,AuthState.EXPIRING.value)
        result=adapter.refresh(current["material"],identity["config"],self.secret_resolver,transport or self.transport)
        if result is None and self.policy.automatic_reauth:
            result=adapter.authenticate(identity["config"],self.secret_resolver,transport or self.transport)
        if not result or result.get("challenge_required"):
            self.store.set_state(session_id,self.engagement_id,identity_id,AuthState.CHALLENGE_REQUIRED.value if result and result.get("challenge_required") else AuthState.RECOVERY_FAILED.value)
            raise AuthError("Session recovery requires operator action")
        expires_at=result.get("expires_at")
        if isinstance(expires_at,str):
            try: expires_at=float(expires_at)
            except ValueError: expires_at=None
        self.store.put(session_id,self.engagement_id,identity_id,AuthState.AUTHENTICATED.value,result,expires_at)
        self.audit("auth.session_recovered", {"identity_id":identity_id,"session_id":session_id,"method":"refresh_or_login"})
        return result

    def material_for_broker(self, session_id, identity_id, transport=None):
        """Internal broker-only method. Never serialize its return value to an agent."""
        current=self.store.get(session_id,self.engagement_id,identity_id)
        expires=current["expires_at"]
        if expires is not None and expires <= time.time()+self.policy.refresh_skew_seconds:
            self._recover(session_id,identity_id,transport)
            current=self.store.get(session_id,self.engagement_id,identity_id)
        identity=self.store.identity(self.engagement_id,identity_id)
        adapter=self.adapters[identity["adapter"]]
        return adapter.headers(current["material"],identity["config"])

    def handle_response(self, session_id, identity_id, status_code, method, transport=None):
        # 403 is authorization denial, not proof of expiry. Only 401 triggers recovery.
        if status_code != 401: return {"retry":False,"reason":"not_auth_expired_or_access_denied"}
        if method.upper() not in {"GET","HEAD","OPTIONS"}:
            self.audit("auth.recovery_blocked_state_change", {"identity_id":identity_id,"method":method.upper()})
            return {"retry":False,"reason":"state_changing_request_never_retried"}
        if not self.policy.retry_read_only_once:
            return {"retry":False,"reason":"automatic_retry_disabled"}
        self._recover(session_id,identity_id,transport)
        return {"retry":True,"reason":"reauthenticated_read_only_request_once"}

    def revoke(self, session_id, identity_id):
        self.store.revoke(session_id,self.engagement_id,identity_id)
        self.audit("auth.session_revoked", {"identity_id":identity_id,"session_id":session_id})
