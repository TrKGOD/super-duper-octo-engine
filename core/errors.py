"""Failure taxonomy shared by the execution ledger, the pipeline and the reports.

Broad ``except Exception`` blocks used to collapse every failure into one undifferentiated
"failed". The classes below make the *kind* of failure an explicit, recorded fact, because
each demands a different reaction:

``invalid_input``         the request was malformed; fix the input, nothing ran.
``authorization_denied``  a deterministic policy refused it; do not retry, do not widen.
``security_violation``    the request tried to cross a boundary (scope, path, network).
``tool_error``            the tool ran and reported failure; an expected operational outcome.
``timeout``               a bound was hit; the outcome of the external action is uncertain.
``infrastructure``        the platform failed (disk, DB, runtime); retry may help, ask first.
``programming_error``     a bug; never retried, always surfaced.
"""
from __future__ import annotations

FAILURE_CLASSES = ("invalid_input", "authorization_denied", "security_violation",
                   "tool_error", "timeout", "infrastructure", "programming_error")


def classify_exception(exc: BaseException) -> str:
    """Map an exception to one of :data:`FAILURE_CLASSES` (imports are local to avoid cycles)."""
    from core.netpolicy import DestinationDenied
    from core.pathsafe import PathSafetyError

    if isinstance(exc, (DestinationDenied, PathSafetyError)):
        return "security_violation"
    if isinstance(exc, TimeoutError) or type(exc).__name__ == "TimeoutExpired":
        return "timeout"
    try:
        from core.active_executor import ActiveExecutionError
        if isinstance(exc, ActiveExecutionError):
            return "authorization_denied"
    except ImportError:  # pragma: no cover
        pass
    try:
        from core.workers.manager import WorkerError
        from core.workers.resources import ResourceError
        from core.workers.tools import ToolError
        if isinstance(exc, (ToolError, ResourceError)):
            return "invalid_input"
        if isinstance(exc, WorkerError):
            return "authorization_denied"
    except ImportError:  # pragma: no cover
        pass
    if isinstance(exc, (OSError, ConnectionError)):
        return "infrastructure"
    if isinstance(exc, (ValueError, KeyError)):
        return "invalid_input"
    if isinstance(exc, (TypeError, AttributeError, AssertionError, NameError, IndexError, ZeroDivisionError)):
        return "programming_error"
    return "programming_error"
