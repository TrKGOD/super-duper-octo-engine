"""Loading of operator-reviewed request manifests — the single implementation.

Three modules used to carry their own copy of this routine (with slightly different checks and
messages). It lives here once: the manifest must be a regular JSON file inside
``<project>/.local/requests/``, reached without a symlink or junction anywhere on the path, and no
larger than 64 KiB. Loading a manifest proves nothing about its *content*; scope, approval and the
SHA-256 pin are enforced by the broker (``ActiveHTTPExecutor.execute_request_file``).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.active_executor import ActiveExecutionError
from core.pathsafe import is_link_like

MAX_MANIFEST_BYTES = 65536


def load_request_manifest(project_root, relative_path: str, *, label: str = "Request") -> dict[str, Any]:
    path = Path(relative_path)
    if path.is_absolute() or ".." in path.parts or path.parts[:2] != (".local", "requests"):
        raise ActiveExecutionError(f"{label} manifests must be confined to .local/requests/")
    root = Path(project_root)
    local_root = root / ".local"
    requests_dir = local_root / "requests"
    candidate = root / path
    if is_link_like(local_root) or is_link_like(requests_dir) or is_link_like(candidate):
        raise ActiveExecutionError(f"{label} manifest path must not use symlinks or junctions")
    resolved = candidate.resolve(strict=True)
    base = requests_dir.resolve(strict=True)
    if not resolved.is_file() or not resolved.is_relative_to(base):
        raise ActiveExecutionError(f"{label} manifest is outside the requests directory")
    with open(resolved, "rb") as handle:
        raw = handle.read(MAX_MANIFEST_BYTES + 1)          # never read an unbounded file
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ActiveExecutionError(f"{label} manifest exceeds 64 KiB")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActiveExecutionError(f"{label} manifest must be valid UTF-8 JSON") from exc
    if not isinstance(data, dict):
        raise ActiveExecutionError(f"{label} manifest must be a JSON object")
    return data
