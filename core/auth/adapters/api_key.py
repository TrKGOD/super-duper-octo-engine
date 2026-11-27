from core.auth.adapters.base import AuthAdapter, reject_unsafe_header_value, validate_header_name

class APIKeyAdapter(AuthAdapter):
    name = "api_key"
    def authenticate(self, config, secret_resolver, transport=None):
        value = secret_resolver(config["key_env"])
        reject_unsafe_header_value(value, "API key")
        header_name = validate_header_name(config.get("header_name", "X-API-Key"))
        return {"headers": {header_name: value}}
