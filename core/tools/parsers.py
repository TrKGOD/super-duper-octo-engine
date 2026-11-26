"""Parsers for real security-tool output.

Each parser turns a tool's actual output format into normalized observations. Tool output is
**untrusted data**: parsers extract structured fields only, never execute or trust embedded
content, tolerate malformed lines, and label vulnerability signals as `CANDIDATE` — a scanner
alert is never a confirmed finding (confirmation is the validation engine's job).
"""
from __future__ import annotations

import json


def _jsonl(raw: str):
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            yield value


def _lines(raw: str):
    for line in str(raw or "").splitlines():
        line = line.strip()
        if line:
            yield line


def parse_subfinder(raw: str) -> list[dict]:
    seen, out = set(), []
    for host in _lines(raw):
        if host not in seen and "." in host:
            seen.add(host)
            out.append({"type": "subdomain", "host": host})
    return out


def parse_dnsx(raw: str) -> list[dict]:
    out = []
    for row in _jsonl(raw):
        host = row.get("host")
        if host:
            out.append({"type": "dns_record", "host": host,
                        "a_records": row.get("a", []), "status": row.get("status_code")})
    return out


def parse_httpx(raw: str) -> list[dict]:
    out = []
    for row in _jsonl(raw):
        url = row.get("url") or row.get("input")
        if url:
            out.append({"type": "http_service", "url": url, "status": row.get("status_code"),
                        "title": row.get("title"),
                        "technologies": row.get("tech") or row.get("technologies") or []})
    return out


def parse_katana(raw: str) -> list[dict]:
    seen, out = set(), []
    for line in _lines(raw):
        url = line.split()[0]
        if url.startswith(("http://", "https://")) and url not in seen:
            seen.add(url)
            out.append({"type": "route", "url": url})
    return out


def parse_nuclei(raw: str) -> list[dict]:
    out = []
    for row in _jsonl(raw):
        template = row.get("template-id") or row.get("templateID")
        info = row.get("info") or {}
        if template:
            out.append({"type": "vulnerability_candidate", "template": template,
                        "severity": info.get("severity"), "name": info.get("name"),
                        "matched_at": row.get("matched-at") or row.get("host"),
                        "disposition": "CANDIDATE",
                        "note": "Scanner candidate; not a confirmed finding — requires independent validation."})
    return out


def parse_dalfox(raw: str) -> list[dict]:
    out = []
    try:
        data = json.loads(raw) if str(raw).strip().startswith("[") else list(_jsonl(raw))
    except json.JSONDecodeError:
        data = list(_jsonl(raw))
    for row in data if isinstance(data, list) else []:
        if not isinstance(row, dict):
            continue
        out.append({"type": "xss_candidate", "inject_type": row.get("inject_type") or row.get("type"),
                    "poc": row.get("poc") or row.get("data"), "severity": row.get("severity"),
                    "cwe": row.get("cwe"), "disposition": "CANDIDATE",
                    "note": "XSS candidate; not a confirmed finding — requires independent validation."})
    return out


def parse_ffuf(raw: str) -> list[dict]:
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return []
    out = []
    for result in (document.get("results", []) if isinstance(document, dict) else []):
        if isinstance(result, dict) and result.get("url"):
            out.append({"type": "content", "url": result["url"], "status": result.get("status"),
                        "length": result.get("length")})
    return out


def passthrough(raw: str) -> list[dict]:
    text = str(raw or "")
    return [{"type": "raw_output", "text": text[:2000], "truncated": len(text) > 2000}]


PARSERS = {
    "subfinder": parse_subfinder, "dnsx": parse_dnsx, "httpx": parse_httpx,
    "katana": parse_katana, "nuclei": parse_nuclei, "dalfox": parse_dalfox,
    "ffuf": parse_ffuf, "passthrough": passthrough,
}


def get_parser(parser_id: str):
    return PARSERS.get(parser_id, passthrough)
