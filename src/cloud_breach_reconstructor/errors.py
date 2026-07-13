class EvidenceError(ValueError):
    """Raised when evidence is malformed or ambiguous enough to fail closed."""


class InputLimitError(EvidenceError):
    """Raised when an input exceeds a documented resource limit."""
