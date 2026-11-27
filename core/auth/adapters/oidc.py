"""OIDC authorization-code/client-credentials adapter with strict ID-token checks.

The token and JWKS exchanges must be supplied by the engagement-scoped broker.
Only RS256 and ES256 are accepted; unsigned and algorithm-confusion tokens fail closed.
"""
import base64
import json
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from core.auth.adapters.base import AuthAdapter


def _b64url(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _json_segment(value):
    try:
        parsed = json.loads(_b64url(value))
    except Exception as exc:
        raise RuntimeError("Malformed OIDC JWT segment") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("OIDC JWT segment must be an object")
    return parsed


def _verify_signature(alg, signing_input, signature, jwk):
    if jwk.get("use", "sig") != "sig" or jwk.get("alg", alg) != alg:
        raise RuntimeError("OIDC JWKS key is not valid for signing")
    if alg == "RS256" and jwk.get("kty") == "RSA":
        key = rsa.RSAPublicNumbers(
            int.from_bytes(_b64url(jwk["e"]), "big"),
            int.from_bytes(_b64url(jwk["n"]), "big"),
        ).public_key()
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return
    if alg == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64url(jwk["x"]), "big"),
            int.from_bytes(_b64url(jwk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        if len(signature) != 64:
            raise RuntimeError("Invalid ES256 signature length")
        der = encode_dss_signature(
            int.from_bytes(signature[:32], "big"),
            int.from_bytes(signature[32:], "big"),
        )
        key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        return
    raise RuntimeError("Unsupported OIDC signing algorithm or key type")


class OIDCAdapter(AuthAdapter):
    name = "oidc"

    def authenticate(self, config, secret_resolver, transport=None):
        if transport is None:
            raise RuntimeError("OIDC requires an engagement-scoped broker transport")
        issuer = str(config.get("issuer", "")).rstrip("/")
        client_id = config.get("client_id")
        token_path = config.get("token_path")
        expected_nonce = config.get("expected_nonce")
        if not issuer or not client_id or not token_path or not expected_nonce:
            raise RuntimeError("OIDC requires issuer, client_id, token_path and expected_nonce")
        parsed_issuer = urlsplit(issuer)
        if parsed_issuer.scheme != "https" and parsed_issuer.hostname not in {"localhost", "127.0.0.1"}:
            raise RuntimeError("OIDC issuer must use HTTPS outside localhost labs")

        discovery = config.get("discovery_document")
        if discovery is None:
            discovery_path = config.get("discovery_path", "/.well-known/openid-configuration")
            discovery = transport("GET", discovery_path, fields={}, purpose="OIDC discovery")
        if not isinstance(discovery, dict) or discovery.get("issuer", "").rstrip("/") != issuer:
            raise RuntimeError("OIDC discovery issuer mismatch")
        jwks_uri = discovery.get("jwks_uri")
        jwks_path = config.get("jwks_path")
        if not jwks_path or not jwks_uri:
            raise RuntimeError("OIDC requires an explicitly broker-routed jwks_path and discovery jwks_uri")
        parsed_jwks = urlsplit(jwks_uri)
        issuer_port = parsed_issuer.port or (443 if parsed_issuer.scheme == "https" else 80)
        jwks_port = parsed_jwks.port or (443 if parsed_jwks.scheme == "https" else 80)
        if (parsed_jwks.scheme, parsed_jwks.hostname, jwks_port) != (
                parsed_issuer.scheme, parsed_issuer.hostname, issuer_port):
            raise RuntimeError("OIDC JWKS endpoint must share the configured issuer origin")

        fields = {"grant_type": config.get("grant_type", "authorization_code"),
                  "client_id": client_id}
        for key in ("code", "redirect_uri", "code_verifier", "scope"):
            if config.get(key):
                fields[key] = config[key]
        if config.get("client_secret_env"):
            fields["client_secret"] = secret_resolver(config["client_secret_env"])
        token_response = transport("POST", token_path, fields=fields, purpose="OIDC token exchange")
        if token_response.get("challenge_required"):
            return {"challenge_required": True}
        id_token = token_response.get("id_token")
        access_token = token_response.get("access_token")
        if not id_token or not access_token:
            raise RuntimeError("OIDC token response must contain id_token and access_token")

        parts = id_token.split(".")
        if len(parts) != 3:
            raise RuntimeError("OIDC ID Token must be a compact signed JWT")
        header, claims = _json_segment(parts[0]), _json_segment(parts[1])
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in {"RS256", "ES256"} or not kid:
            raise RuntimeError("OIDC ID Token requires RS256/ES256 and a key id")
        jwks = transport("GET", jwks_path, fields={}, purpose="OIDC JWKS")
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
        matching = [key for key in keys if key.get("kid") == kid]
        if len(matching) != 1:
            raise RuntimeError("OIDC signing key is missing or ambiguous")
        try:
            _verify_signature(alg, (parts[0] + "." + parts[1]).encode("ascii"),
                              _b64url(parts[2]), matching[0])
        except Exception as exc:
            raise RuntimeError("OIDC ID Token signature validation failed") from exc

        now = int(time.time())
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        token_issuer = claims.get("iss")
        if not isinstance(token_issuer, str) or token_issuer.rstrip("/") != issuer:
            raise RuntimeError("OIDC ID Token issuer mismatch")
        if not audiences or any(not isinstance(item, str) for item in audiences) or client_id not in audiences:
            raise RuntimeError("OIDC ID Token audience mismatch")
        if (len(audiences) > 1 or claims.get("azp") is not None) and claims.get("azp") != client_id:
            raise RuntimeError("OIDC ID Token authorized-party mismatch")
        if claims.get("nonce") != expected_nonce:
            raise RuntimeError("OIDC ID Token nonce mismatch")
        if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
            raise RuntimeError("OIDC ID Token is expired or has no valid exp")
        if not isinstance(claims.get("iat"), (int, float)) or claims["iat"] > now + 60:
            raise RuntimeError("OIDC ID Token has an invalid iat")
        if claims.get("nbf") is not None:
            if not isinstance(claims["nbf"], (int, float)) or claims["nbf"] > now + 60:
                raise RuntimeError("OIDC ID Token is not yet valid")

        return {"headers": {"Authorization": "Bearer " + access_token},
                "access_token": access_token,
                "refresh_token": token_response.get("refresh_token"),
                "id_token": id_token, "expires_at": token_response.get("expires_at"),
                "expires_in": token_response.get("expires_in"),
                "token_type": token_response.get("token_type", "Bearer")}

    def refresh(self, material, config, secret_resolver, transport=None):
        refresh_token = material.get("refresh_token")
        if not refresh_token or transport is None:
            return None
        fields = {"grant_type": "refresh_token", "refresh_token": refresh_token,
                  "client_id": config["client_id"]}
        if config.get("client_secret_env"):
            fields["client_secret"] = secret_resolver(config["client_secret_env"])
        response = transport("POST", config["token_path"], fields=fields,
                             purpose="OIDC refresh token exchange")
        if response.get("challenge_required"):
            return {"challenge_required": True}
        access_token = response.get("access_token")
        if not access_token:
            raise RuntimeError("OIDC refresh response did not contain an access token")
        return {"headers": {"Authorization": "Bearer " + access_token},
                "access_token": access_token,
                "refresh_token": response.get("refresh_token", refresh_token),
                "expires_at": response.get("expires_at"), "expires_in": response.get("expires_in"),
                "token_type": response.get("token_type", "Bearer")}
