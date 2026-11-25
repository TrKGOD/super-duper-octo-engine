"""Optional Playwright adapter. Human challenges are surfaced, never bypassed."""
from core.auth.adapters.base import AuthAdapter

class BrowserAuthAdapter(AuthAdapter):
    name = "browser"
    def __init__(self, runner=None):
        self.runner = runner
    def authenticate(self, config, secret_resolver, transport=None):
        runner = self.runner
        if runner is None:
            raise RuntimeError("Browser auth requires an isolated Playwright runner injected by the operator")
        result = runner(config=config, secret_resolver=secret_resolver)
        if result.get("challenge_required") or result.get("mfa_required") or result.get("captcha_required"):
            return {"challenge_required": True}
        if not result.get("session_headers"):
            raise RuntimeError("Browser flow did not produce a session")
        return {"headers": result["session_headers"], "expires_at": result.get("expires_at")}
