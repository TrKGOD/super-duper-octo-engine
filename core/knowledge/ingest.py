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
import math
from html.parser import HTMLParser

from scripts.knowledge_base import MAX_BYTES, _index_document, now, sanitize_content, validate_meta
from core.knowledge.taxonomy import extract_references, flatten_references

# Resource bounds. Imported documents are untrusted input: without them one oversized, deeply nested or
# value-heavy document exhausts memory or bloats the database, and a deeply nested JSON document used to
# escape as a bare RecursionError instead of an IngestError.
MAX_DOCUMENT_BYTES = MAX_BYTES          # the same 2 MB ceiling the Markdown/text path already enforces
MAX_METADATA_BYTES = 64_000
MAX_JSON_NODES = 200_000
MAX_JSON_DEPTH = 100
MAX_EMBEDDING_DIM = 4096


class IngestError(ValueError):
    pass


class _TextExtractor(HTMLParser):
    """Collects visible text from HTML/XML by stripping tags; no entity resolution.

    ``template`` and ``noscript`` are skipped with ``script``/``style``: their content is inert or hidden
    from a human reviewer but would otherwise reach an agent as ordinary text.
    """

    _SKIP = {"script", "style", "template", "noscript"}

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
    except Exception as exc:
        # Fail closed: returning the raw markup on a parser fault would store unstripped script/markup.
        raise IngestError("Markup could not be parsed safely") from exc
    return parser.text()


def _flatten_json(value, out: list, counter: list | None = None) -> None:
    """Append every key and scalar of ``value`` to ``out`` in document order (iterative and bounded)."""
    counter = counter if counter is not None else [0]
    stack = [("visit", value, 0)]
    while stack:
        kind, item, depth = stack.pop()
        counter[0] += 1
        if counter[0] > MAX_JSON_NODES:
            raise IngestError("JSON document has too many values")
        if kind == "emit":
            out.append(item)
            continue
        if depth > MAX_JSON_DEPTH:
            raise IngestError("JSON nesting is too deep")
        if isinstance(item, dict):
            for key, child in reversed(list(item.items())):          # LIFO: keep document order
                stack.append(("visit", child, depth + 1))
                stack.append(("emit", str(key), depth + 1))
        elif isinstance(item, list):
            for child in reversed(item):
                stack.append(("visit", child, depth + 1))
        elif item is not None:
            out.append(str(item))


def _loads(raw: str, what: str):
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IngestError(f"Invalid {what}") from exc
    except RecursionError as exc:
        raise IngestError("JSON nesting is too deep") from exc


def _enforce_size(raw) -> None:
    """Reject an oversized document before any parsing (characters never outnumber bytes)."""
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise IngestError(f"Document exceeds {MAX_DOCUMENT_BYTES} bytes")
    if isinstance(raw, str):
        try:
            size = len(raw.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise IngestError("Document is not valid UTF-8 text") from exc
        if size > MAX_DOCUMENT_BYTES:
            raise IngestError(f"Document exceeds {MAX_DOCUMENT_BYTES} bytes")


def _normalize_media_type(media_type: str | None) -> str:
    if not media_type:
        return "text/plain"
    return str(media_type).split(";")[0].strip().lower()


def extract_text(raw, media_type: str | None) -> str:
    """Extract sanitized plain text from supported formats. Raises for unsupported ones."""
    if not isinstance(raw, (bytes, str)):
        raise IngestError("Document must be bytes or text")
    _enforce_size(raw)
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IngestError("Document is not valid UTF-8") from exc
    media = _normalize_media_type(media_type)

    if media in ("text/plain", "text/markdown", "text/x-markdown"):
        text = raw
    elif media in ("text/html", "application/xhtml+xml", "application/xml", "text/xml", "image/svg+xml"):
        text = _strip_markup(raw)
    elif media == "application/json":
        chunks: list[str] = []
        _flatten_json(_loads(raw, "JSON document"), chunks)
        text = "\n".join(chunks)
    elif media in ("application/jsonl", "application/x-ndjson", "application/x-jsonlines"):
        chunks, counter = [], [0]                                    # one value budget for the whole file
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            _flatten_json(_loads(line, "JSONL line"), chunks, counter)
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


def validated_embedding(vector) -> list:
    """An embedder is an external callable, so its output is validated: a non-finite value would make
    every similarity score NaN and silently corrupt ranking."""
    try:
        vec = [round(float(x), 6) for x in list(vector)]
    except (TypeError, ValueError, OverflowError) as exc:
        raise IngestError("Embedding must be a sequence of numbers") from exc
    if not vec or len(vec) > MAX_EMBEDDING_DIM:
        raise IngestError(f"Embedding must have between 1 and {MAX_EMBEDDING_DIM} dimensions")
    if not all(math.isfinite(x) for x in vec):
        raise IngestError("Embedding contains a non-finite value")
    return vec


def store_embedding(db, document_id: str, vector) -> None:
    vec = validated_embedding(vector)
    ensure_tables(db)
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
    if len(json.dumps(meta, default=str)) > MAX_METADATA_BYTES:
        raise IngestError(f"Document metadata exceeds {MAX_METADATA_BYTES} bytes")
    validate_meta(meta)               # public-only, https source, documented rights basis; no extra keys allowed
    references = extract_references(text)    # only well-formed taxonomy ids found in the text are recorded
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    ensure_tables(db)

    existing = db.execute("SELECT document_id FROM kb_documents WHERE content_sha256=?", (digest,)).fetchone()
    if existing:
        record_references(db, existing["document_id"], references)
        db.commit()
        return existing["document_id"]

    # Everything that can fail on external input happens before the first write, and any failure after it
    # rolls the whole document back: ingestion is all-or-nothing, never a document without its index.
    vector = validated_embedding(embedder(text)) if embedder is not None else None
    document_id = "KB-" + digest[:16].upper()
    values = (document_id, meta["title"], meta["platform"], meta["source_url"], "public",
              meta["rights_basis"], meta["collected_at"], meta.get("published_at"), meta["content_type"],
              json.dumps(meta.get("vulnerability_types", [])), json.dumps(meta.get("technologies", [])),
              json.dumps(meta.get("asset_types", [])), json.dumps(meta.get("tags", [])),
              meta.get("author"), meta.get("license"), meta.get("notes"), text, digest, now())
    try:
        db.execute("INSERT INTO kb_documents VALUES(" + ",".join("?" for _ in values) + ")", values)
        _index_document(db, document_id, meta["title"], text, meta.get("tags", []),
                        meta.get("vulnerability_types", []), meta.get("technologies", []))
        record_references(db, document_id, references)
        if vector is not None:
            store_embedding(db, document_id, vector)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return document_id
