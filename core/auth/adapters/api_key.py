from core.auth.adapters.base import AuthAdapter

class APIKeyAdapter(AuthAdapter):
    name = "api_key"
    def authenticate(self, config, secret_resolver, transport=None):
        value = secret_resolver(config["key_env"])
        if not value or "\\r" in value or "\\n" in value:
            raise RuntimeError("Invalid API key")
        return {"headers": {config.get("header_name", "X-API-Key"): value}}
