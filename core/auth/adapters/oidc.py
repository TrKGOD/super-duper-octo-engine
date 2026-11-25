from core.auth.adapters.oauth2 import OAuth2Adapter

class OIDCAdapter(OAuth2Adapter):
    name = "oidc"
    def authenticate(self, config, secret_resolver, transport=None):
        if not config.get("issuer") or not config.get("client_id"):
            raise RuntimeError("OIDC requires an explicit issuer and client_id")
        # Discovery metadata must be operator-supplied or fetched through the scoped broker.
        if config.get("discovery_document"):
            issuer = config["discovery_document"].get("issuer")
            if issuer != config["issuer"]:
                raise RuntimeError("OIDC discovery issuer mismatch")
        return super().authenticate(config, secret_resolver, transport)
