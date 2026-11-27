from core.auth.adapters.base import AuthAdapter, reject_unsafe_header_value

class JWTAdapter(AuthAdapter):
    name = "jwt"
    def authenticate(self, config, secret_resolver, transport=None):
        value = secret_resolver(config["token_env"])
        reject_unsafe_header_value(value, "JWT secret")
        return {"headers": {"Authorization": "Bearer " + value}, "access_token": value,
                "expires_at": config.get("expires_at")}
