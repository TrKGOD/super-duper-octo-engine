"""Multi-format knowledge ingestion.

Extends the existing Markdown/text Knowledge Base (`scripts/knowledge_base.py`) to HTML,
JSON, JSONL and XML, enriches each document with extracted taxonomy references
(CWE/CVE/OWASP/CAPEC/ATT&CK), and persists them through the KB's existing validation,
sanitization, dedup and FTS indexing. All extracted content is treated as untrusted and
passed through the KB's `sanitize_content` (which neutralizes prompt-injection directives).
XML and HTML are parsed by tag-stripping only — no DTD/entity resolution — so untrusted
markup cannot trigger entity-expansion or XXE.
"""
from __future__ import annotations

import hashlib
import json
from html.parser import HTMLParser

from scripts.knowledge_base import (_index_document, now, sanitize_content, validate_meta)
from core.knowledge.taxonomy import extract_references, flatten_references, merge_references


class IngestError(ValueError):
    pass


class _TextExtractor(HTMLParser):
    """Collects visible text from HTML/XML by stripping tags; no entity resolution."""

    _SKIP = {"script", "style"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in self._SKIP and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0 and data.strip():
            self._chunks.append(data.strip())

    def text(self) -> str:
        return "\n".join(self._chunks)


def _strip_markup(value: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(value)
    except Exception:  # untrusted markup must never crash extraction
        return value
    return parser.text()


def _flatten_json(value, out: list):
    if isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            _flatten_json(item, out)
    elif isinstance(value, list):
        for item in value:
            _flatten_json(item, out)
    elif value is not None:
        out.append(str(value))


def _normalize_media_type(media_type: str | None) -> str:
    if not media_type:
        return "text/plain"
    return str(media_type).split(";")[0].strip().lower()


def extract_text(raw, media_type: str | None) -> str:
    """Extract sanitized plain text from supported formats. Raises for unsupported ones."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IngestError("Document is not valid UTF-8") from exc
    raw = str(raw)
    media = _normalize_media_type(media_type)

    if media in ("text/plain", "text/markdown", "text/x-markdown"):
        text = raw
    elif media in ("text/html", "application/xhtml+xml", "application/xml", "text/xml", "image/svg+xml"):
        text = _strip_markup(raw)
    elif media == "application/json":
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise IngestError("Invalid JSON document") from exc
        chunks: list[str] = []
        _flatten_json(parsed, chunks)
        text = "\n".join(chunks)
    elif media in ("application/jsonl", "application/x-ndjson", "application/x-jsonlines"):
        chunks = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                _flatten_json(json.loads(line), chunks)
            except json.JSONDecodeError as exc:
                raise IngestError("Invalid JSONL line") from exc
        text = "\n".join(chunks)
    elif media == "application/pdf":
        raise IngestError("PDF extraction requires an optional extractor; convert to text first "
                          "or install a PDF backend (not bundled, not used in CI)")
    else:
        raise IngestError("Unsupported media type: " + media)

    return sanitize_content(text)


def ensure_tables(db) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS kb_references("
               "document_id TEXT NOT NULL, ref_type TEXT NOT NULL, ref_value TEXT NOT NULL, "
               "PRIMARY KEY(document_id, ref_type, ref_value))")
    db.execute("CREATE TABLE IF NOT EXISTS kb_embeddings("
               "document_id TEXT PRIMARY KEY, dim INTEGER NOT NULL, vector_json TEXT NOT NULL)")


def record_references(db, document_id: str, references: dict) -> None:
    ensure_tables(db)
    for ref_type, value in flatten_references(references):
        db.execute("INSERT OR IGNORE INTO kb_references VALUES(?,?,?)", (document_id, ref_type, value))


def references_for(db, document_id: str) -> dict:
    rows = db.execute("SELECT ref_type, ref_value FROM kb_references WHERE document_id=? ORDER BY ref_type, ref_value",
                      (document_id,)).fetchall()
    result: dict[str, list] = {}
    for row in rows:
        result.setdefault(row["ref_type"], []).append(row["ref_value"])
    return result


def documents_with_reference(db, ref_type: str, ref_value: str) -> list[str]:
    rows = db.execute("SELECT document_id FROM kb_references WHERE ref_type=? AND ref_value=?",
                      (ref_type, str(ref_value).upper())).fetchall()
    return [row["document_id"] for row in rows]


def store_embedding(db, document_id: str, vector) -> None:
    ensure_tables(db)
    vec = [round(float(x), 6) for x in vector]
    db.execute("INSERT OR REPLACE INTO kb_embeddings VALUES(?,?,?)",
               (document_id, len(vec), json.dumps(vec)))


def ingest_content(db, raw, media_type, metadata, *, embedder=None) -> str:
    """Extract, enrich with taxonomy references, and persist one document into the KB.

    Returns the document id. Deduplicates on the sanitized content hash; a duplicate still
    records any newly-extracted references. ``embedder`` (optional) is a callable
    text -> vector used to populate the semantic index; without it the FTS baseline is used.
    """
    text = extract_text(raw, media_type)
    if not text.strip():
        raise IngestError("Empty document after extraction")
    meta = dict(metadata or {})
    validate_meta(meta)
    references = merge_references(meta.get("references") or {}, extract_references(text))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    ensure_tables(db)

    existing = db.execute("SELECT document_id FROM kb_documents WHERE content_sha256=?", (digest,)).fetchone()
    if existing:
        record_references(db, existing["document_id"], references)
        db.commit()
        return existing["document_id"]

    document_id = "KB-" + digest[:16].upper()
    values = (document_id, meta["title"], meta["platform"], meta["source_url"], "public",
              meta["rights_basis"], meta["collected_at"], meta.get("published_at"), meta["content_type"],
              json.dumps(meta.get("vulnerability_types", [])), json.dumps(meta.get("technologies", [])),
              json.dumps(meta.get("asset_types", [])), json.dumps(meta.get("tags", [])),
              meta.get("author"), meta.get("license"), meta.get("notes"), text, digest, now())
    db.execute("INSERT INTO kb_documents VALUES(" + ",".join("?" for _ in values) + ")", values)
    _index_document(db, document_id, meta["title"], text, meta.get("tags", []),
                    meta.get("vulnerability_types", []), meta.get("technologies", []))
    record_references(db, document_id, references)
    if embedder is not None:
        store_embedding(db, document_id, embedder(text))
    db.commit()
    return document_id
