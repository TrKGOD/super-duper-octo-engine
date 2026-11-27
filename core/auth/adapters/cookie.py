from core.auth.adapters.base import AuthAdapter, reject_unsafe_header_value

class CookieSessionAdapter(AuthAdapter):
    name = "cookie"
    def authenticate(self, config, secret_resolver, transport=None):
        env_name = config.get("cookie_env")
        if not env_name:
            raise RuntimeError("Cookie adapter requires cookie_env")
        value = secret_resolver(env_name)
        reject_unsafe_header_value(value, "cookie secret")
        return {"headers": {"Cookie": value}}
