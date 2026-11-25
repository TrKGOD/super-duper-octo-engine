from core.auth.adapters.base import AuthAdapter

class FormAuthAdapter(AuthAdapter):
    name = "form"
    def authenticate(self, config, secret_resolver, transport=None):
        if transport is None:
            raise RuntimeError("Form authentication requires an injected broker transport")
        fields = dict(config.get("fields", {}))
        for field, env_name in config.get("secret_fields", {}).items():
            fields[field] = secret_resolver(env_name)
        result = transport("POST", config["login_path"], fields=fields, purpose="operator-authorized form login")
        if result.get("challenge_required"):
            return {"challenge_required": True}
        return {"headers": result.get("session_headers", {}), "expires_at": result.get("expires_at")}
