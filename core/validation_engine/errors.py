"""Validation engine exceptions (kept separate so every module can import them without cycles)."""


class ValidationError(ValueError):
    pass


class EvidenceResolutionError(ValidationError):
    """A referenced piece of evidence is unknown, foreign, malformed or failed its integrity check."""
