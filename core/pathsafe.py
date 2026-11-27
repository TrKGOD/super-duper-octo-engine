"""Path-safety primitives shared by every module that confines file access.

``Path.is_symlink()`` is not enough on Windows: an NTFS *junction* is a directory redirect
that ``is_symlink()`` reports as ``False`` and that any user can create without special
privileges (``mklink /J``). Every "must not be a symlink" guard in the framework therefore
uses :func:`is_link_like`, and every "must stay inside this directory" guard uses
:func:`resolve_within`, so the confinement rules are implemented once.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

# NTFS reparse tags. Only these two redirect path resolution. Other reparse points (OneDrive
# "Files On-Demand" placeholders, dedup, WOF compression) are ordinary files/directories and
# must NOT be rejected: this repository is commonly synced by OneDrive.
_IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003   # directory junction
_IO_REPARSE_TAG_SYMLINK = 0xA000000C


class PathSafetyError(ValueError):
    """A path escaped, or was redirected out of, the directory it must stay inside."""


def is_link_like(path) -> bool:
    """True if ``path`` is a symbolic link *or* a Windows directory junction."""
    candidate = Path(path)
    try:
        if candidate.is_symlink():
            return True
        if os.name == "nt":
            info = os.lstat(candidate)
            if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return getattr(info, "st_reparse_tag", 0) in (
                    _IO_REPARSE_TAG_MOUNT_POINT, _IO_REPARSE_TAG_SYMLINK)
        return False
    except OSError:
        return False


_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def safe_component(value, label: str = "path component") -> str:
    """Validate one path component taken from data (an engagement id, a worker id, ...).

    Rejects separators, traversal, drive letters, NUL, leading dots/hyphens and anything
    outside a conservative character set, so the value can be joined to a base directory
    without any chance of escaping it.
    """
    if not isinstance(value, str) or not _SAFE_COMPONENT.fullmatch(value) or ".." in value:
        raise PathSafetyError(f"{label} contains unsafe characters")
    return value


def resolve_within(base, *parts: str) -> Path:
    """Join ``parts`` onto ``base`` and prove the result stays inside ``base``.

    Every component must be a plain name; the final path is canonicalised and must resolve
    inside the canonical ``base``; and no existing component between ``base`` and the result
    may be a symlink or junction (so a link planted inside the tree cannot redirect it).
    """
    base_path = Path(base)
    base_real = base_path.resolve()
    current = base_path
    for part in parts:
        safe_component(part)
        current = current / part
        if current.exists() and is_link_like(current):
            raise PathSafetyError("path component is a symlink or junction: " + str(part))
    resolved = current.resolve()
    if resolved != base_real and not resolved.is_relative_to(base_real):
        raise PathSafetyError("path escapes its base directory")
    return current
