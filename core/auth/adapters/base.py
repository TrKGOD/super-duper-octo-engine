"""Adapter contract: callbacks must use the engagement broker or explicit operator input."""
from abc import ABC, abstractmethod

class AuthAdapter(ABC):
    name = "base"
    @abstractmethod
    def authenticate(self, config, secret_resolver, transport=None):
        raise NotImplementedError
    def refresh(self, material, config, secret_resolver, transport=None):
        return None
    def validate(self, material, config, transport=None):
        # Absence of a validator is not evidence that a session is valid.
        return None
    def headers(self, material, config):
        return dict(material.get("headers", {}))
