import base64
import json
import time
import unittest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from core.auth.adapters.oidc import OIDCAdapter


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class OIDCValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = cls.private.public_key().public_numbers()
        cls.jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "lab-key",
                   "n": b64(numbers.n.to_bytes((numbers.n.bit_length()+7)//8, "big")),
                   "e": b64(numbers.e.to_bytes((numbers.e.bit_length()+7)//8, "big"))}

    def token(self, **overrides):
        now = int(time.time())
        claims = {"iss": "https://issuer.example.test", "sub": "synthetic-user",
                  "aud": "synthetic-client", "exp": now + 300, "iat": now,
                  "nonce": "operator-nonce"}
        claims.update(overrides)
        header = {"alg": "RS256", "kid": "lab-key", "typ": "JWT"}
        signing = b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())
        signature = self.private.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
        return signing + "." + b64(signature)

    def run_adapter(self, token):
        calls = []
        def transport(method, path, fields=None, purpose=None):
            calls.append((method, path, purpose))
            if path == "/oauth/token":
                return {"access_token": "synthetic-access", "id_token": token, "expires_at": time.time()+300}
            if path == "/jwks":
                return {"keys": [self.jwk]}
            raise AssertionError("unexpected path")
        result = OIDCAdapter().authenticate({
            "issuer": "https://issuer.example.test", "client_id": "synthetic-client",
            "token_path": "/oauth/token", "jwks_path": "/jwks",
            "discovery_document": {"issuer": "https://issuer.example.test",
                "jwks_uri": "https://issuer.example.test/.well-known/jwks.json"},
            "expected_nonce": "operator-nonce",
        }, lambda _: "unused", transport)
        return result, calls

    def test_valid_signed_id_token_and_jwks(self):
        result, calls = self.run_adapter(self.token())
        self.assertEqual(result["headers"]["Authorization"], "Bearer synthetic-access")
        self.assertEqual([item[1] for item in calls], ["/oauth/token", "/jwks"])

    def test_rejects_wrong_issuer_audience_nonce_and_expiry(self):
        for claims, message in [
            ({"iss": "https://evil.example"}, "issuer mismatch"),
            ({"aud": "other-client"}, "audience mismatch"),
            ({"nonce": "wrong"}, "nonce mismatch"),
            ({"exp": int(time.time()) - 1}, "expired"),
        ]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, message):
                    self.run_adapter(self.token(**claims))

    def test_rejects_bad_signature(self):
        token = self.token()
        parts = token.split(".")
        forged = parts[0] + "." + parts[1] + "." + b64(b"not-a-signature")
        with self.assertRaisesRegex(RuntimeError, "signature validation failed"):
            self.run_adapter(forged)

    def test_rejects_issuer_mismatch_in_discovery(self):
        with self.assertRaisesRegex(RuntimeError, "discovery issuer mismatch"):
            OIDCAdapter().authenticate({
                "issuer": "https://issuer.example.test", "client_id": "synthetic-client",
                "token_path": "/oauth/token", "expected_nonce": "n",
                "discovery_document": {"issuer": "https://attacker.example", "jwks_uri": "https://issuer.example.test/jwks"},
                "jwks_path": "/jwks",
            }, lambda _: "unused", lambda *a, **k: {})


if __name__ == "__main__":
    unittest.main()
