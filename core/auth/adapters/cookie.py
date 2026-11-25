from core.auth.adapters.base import AuthAdapter

class CookieSessionAdapter(AuthAdapter):
    name = "cookie"
    def authenticate(self, config, secret_resolver, transport=None):
        env_name = config.get("cookie_env")
        if not env_name:
            raise RuntimeError("Cookie adapter requires cookie_env")
        value = secret_resolver(env_name)
        if not value or "\\r" in value or "\\n" in value:
            raise RuntimeError("Invalid cookie secret")
        return {"headers": {"Cookie": value}}
