"""Small runtime helpers shared by the dispatchers and CLI entry points.

These exist so that behaviour which must be identical everywhere (locating an external
executable, decoding its output) is implemented once instead of being copy-pasted into every
caller, where the copies had already diverged from the intended semantics.
"""
from __future__ import annotations

import shutil

# Explicit text encoding for every child-process pipe. ``subprocess.run(..., text=True)``
# alone uses the *locale* code page (cp1252 on most Windows installs), so a prompt or CLI
# reply containing a non-cp1252 character would raise or be silently corrupted.
CHILD_TEXT_ENCODING = {"encoding": "utf-8", "errors": "replace"}


def resolve_executable(command: str) -> str | None:
    """Resolve ``command`` to an executable file, or return ``None``.

    ``command`` is either a bare program name (searched on ``PATH``) or an explicit path.
    The previous call sites decided "is this a path?" with ``"/" in value``. That
    misclassified Windows paths (``C:\\tools\\claude``) as bare names, and for anything
    containing ``/`` it skipped *every* check and returned the value unverified.
    ``shutil.which`` handles both correctly: for a value with a directory component it checks
    exactly that path (honouring ``PATHEXT`` on Windows), otherwise it searches ``PATH``; it
    only returns a file the OS would actually execute.
    """
    if not isinstance(command, str) or not command.strip() or "\x00" in command:
        return None
    return shutil.which(command)
