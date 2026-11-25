from core.auth.adapters.base import AuthAdapter

class JWTAdapter(AuthAdapter):
    name = "jwt"
    def authenticate(self, config, secret_resolver, transport=None):
        value = secret_resolver(config["token_env"])
        if not value or "\\r" in value or "\\n" in value:
            raise RuntimeError("Invalid JWT secret")
        return {"headers": {"Authorization": "Bearer " + value}, "access_token": value,
                "expires_at": config.get("expires_at")}
