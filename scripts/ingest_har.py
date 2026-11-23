#!/usr/bin/env python3
"""Offline, scope-filtered HAR importer. Never sends network requests."""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.active_executor import _host_matches
from core.orchestration import Workflow

SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-csrf-token"}
SECRET_NAME = re.compile(r"(?:token|secret|password|passwd|authorization|cookie|session|api[_-]?key|csrf)", re.I)
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
NUMERIC = re.compile(r"^\d+$")
OBJECT_ID_KEYS = {"user_id", "account_id", "tenant_id", "listing_id", "item_id", "order_id", "resource_id", "id"}


def normalize_path(path):
    parts = []
    for part in (path or "/").split("/"):
        if not part:
            continue
        parts.append("{id}" if NUMERIC.fullmatch(part) or GUID.fullmatch(part) else part)
    return "/" + "/".join(parts)


def _json_names(value, prefix=""):
    names = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if not SECRET_NAME.search(str(key)):
                names.add((prefix + str(key))[:160])
            names.update(_json_names(child, prefix + str(key) + "."))
    elif isinstance(value, list):
        for child in value[:100]:
            names.update(_json_names(child, prefix))
    return names


def _ids(value, key=""):
    found = set()
    if isinstance(value, dict):
        for name, child in value.items():
            lname = str(name).lower()
            if lname in OBJECT_ID_KEYS or lname.endswith("_id") or lname.endswith("_uuid"):
                if isinstance(child, (str, int)) and not SECRET_NAME.search(lname):
                    found.add((lname, str(child)[:200]))
            found.update(_ids(child, lname))
    elif isinstance(value, list):
        for child in value[:100]:
            found.update(_ids(child, key))
    return found


def _body_names(text, mime):
    if not text:
        return set()
    if "json" in mime.lower():
        try:
            return _json_names(json.loads(text))
        except (ValueError, TypeError):
            return set()
    if "x-www-form-urlencoded" in mime.lower() or "multipart/form-data" in mime.lower():
        return {k for k, _ in parse_qsl(text, keep_blank_values=True) if not SECRET_NAME.search(k)}
    return set()


def _in_scope(host, scope):
    return any(_host_matches(host, item) for item in scope.get("allowed_domains", []))


def ingest_har(db, engagement_id, har_path, scope_host=None, project_root=ROOT):
    with Workflow(db, project_root=project_root) as workflow:
        row = workflow.store.connection.execute(
            "SELECT scope_json FROM engagements WHERE engagement_id=?", (engagement_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown engagement: " + engagement_id)
        scope = json.loads(row["scope_json"])
        source = Path(har_path)
        if source.stat().st_size > 50 * 1024 * 1024:
            raise ValueError("HAR exceeds the 50 MiB input limit")
        data = json.loads(source.read_text(encoding="utf-8"))
        entries = data.get("log", {}).get("entries", []) if isinstance(data, dict) else []
        if not isinstance(entries, list):
            raise ValueError("HAR log.entries must be an array")
        operations, ids = {}, set()
        skipped = 0
        for entry in entries:
            try:
                req = entry["request"]
                parsed = urlsplit(req["url"])
                host = (parsed.hostname or "").lower().rstrip(".")
                if parsed.scheme not in {"http", "https"} or not _in_scope(host, scope):
                    skipped += 1
                    continue
                if scope_host and host != scope_host.lower().rstrip("."):
                    skipped += 1
                    continue
                method = str(req.get("method", "GET")).upper()
                path = normalize_path(parsed.path)
                query_names = {k for k, _ in parse_qsl(parsed.query, keep_blank_values=True) if not SECRET_NAME.search(k)}
                post = req.get("postData") or {}
                params = set()
                for item in post.get("params", []) if isinstance(post.get("params"), list) else []:
                    name = str(item.get("name", ""))
                    if name and not SECRET_NAME.search(name):
                        params.add(name)
                params.update(_body_names(post.get("text", ""), post.get("mimeType", "")))
                headers = set()
                for h in req.get("headers", []):
                    name = str(h.get("name", "")).lower()
                    if name and re.fullmatch(r"[!#$%&'*+.^_|~0-9a-z-]{1,64}", name):
                        headers.add(name)
                key = (method, host, path)
                item = operations.setdefault(key, {"method": method, "host": host, "path": path,
                    "status_codes": set(), "query_parameters": set(), "body_parameters": set(),
                    "header_names": set(), "secret_header_names": set(), "source": "browser_har"})
                item["query_parameters"].update(query_names)
                item["body_parameters"].update(params)
                item["header_names"].update(headers)
                item["secret_header_names"].update(headers & SECRET_HEADERS)
                response = entry.get("response") or {}
                if isinstance(response.get("status"), int):
                    item["status_codes"].add(response["status"])
                for candidate in (req.get("url", ""),):
                    for segment in urlsplit(candidate).path.split("/"):
                        if NUMERIC.fullmatch(segment) or GUID.fullmatch(segment):
                            ids.add(("path_id", segment))
                content = (response.get("content") or {}).get("text", "")
                mime = (response.get("content") or {}).get("mimeType", "")
                if "json" in mime.lower() and content:
                    try:
                        ids.update(_ids(json.loads(content)))
                    except (ValueError, TypeError):
                        pass
            except (KeyError, TypeError, ValueError):
                skipped += 1
        endpoint_rows = []
        for item in operations.values():
            endpoint_rows.append({k: sorted(v) if isinstance(v, set) else v for k, v in item.items()})
        endpoint_rows.sort(key=lambda x: (x["host"], x["path"], x["method"]))
        id_rows = [{"kind": k, "value": v} for k, v in sorted(ids)]
        outdir = Path(project_root) / ".local" / "engagements" / engagement_id
        outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name, payload in (
            ("endpoint-inventory.json", {"engagement_id": engagement_id, "endpoints": endpoint_rows, "skipped_entries": skipped}),
            ("id-inventory.json", {"engagement_id": engagement_id, "identifiers": id_rows}),
        ):
            target = outdir / name
            target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8")
            target.chmod(0o600)
        return {"engagement_id": engagement_id, "entries_seen": len(entries),
                "endpoints": len(endpoint_rows), "identifiers": len(id_rows),
                "skipped_entries": skipped, "output_directory": str(outdir)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--har", required=True)
    parser.add_argument("--scope-host")
    args = parser.parse_args()
    print(json.dumps(ingest_har(args.db, args.engagement_id, args.har, args.scope_host),
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
