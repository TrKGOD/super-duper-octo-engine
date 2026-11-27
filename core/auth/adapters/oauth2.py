from core.auth.adapters.base import AuthAdapter

class OAuth2Adapter(AuthAdapter):
    name = "oauth2"
    def authenticate(self, config, secret_resolver, transport=None):
        if transport is None:
            raise RuntimeError("OAuth2 requires an injected broker token transport")
        payload = {"grant_type": config.get("grant_type", "client_credentials"),
                   "client_id": config["client_id"]}
        if config.get("client_secret_env"):
            payload["client_secret"] = secret_resolver(config["client_secret_env"])
        if config.get("scope"):
            payload["scope"] = config["scope"]
        response = transport("POST", config["token_path"], fields=payload, purpose="OAuth2 token exchange")
        return self._material(response)
    def refresh(self, material, config, secret_resolver, transport=None):
        refresh_token = material.get("refresh_token")
        if not refresh_token or transport is None:
            return None
        response = transport("POST", config["token_path"], fields={
            "grant_type": "refresh_token", "refresh_token": refresh_token,
            "client_id": config["client_id"]}, purpose="OAuth2 refresh token exchange")
        return self._material(response)
    @staticmethod
    def _material(response):
        if response.get("challenge_required"):
            return {"challenge_required": True}
        if not response.get("access_token"):
            raise RuntimeError("OAuth2 response did not contain an access token")
        return {"headers": {"Authorization": "Bearer " + response["access_token"]},
                "access_token": response["access_token"], "refresh_token": response.get("refresh_token"),
                "expires_at": response.get("expires_at"), "expires_in": response.get("expires_in"), "token_type": response.get("token_type", "Bearer")}
