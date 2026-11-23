#!/usr/bin/env python3
"""Local public security-writeup knowledge base with provenance and structured patterns."""
from __future__ import annotations
import argparse, hashlib, json, re, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_DB=Path(".local/knowledge-base.sqlite3")
MAX_BYTES=2_000_000
TEXT_EXTS={".md",".txt"}

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")

def connect(path):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(str(path)); db.row_factory=sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def init_db(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS kb_documents(
      document_id TEXT PRIMARY KEY,title TEXT NOT NULL,platform TEXT NOT NULL,source_url TEXT NOT NULL,
      disclosure_status TEXT NOT NULL CHECK(disclosure_status='public'),rights_basis TEXT NOT NULL,
      collected_at TEXT NOT NULL,published_at TEXT,content_type TEXT NOT NULL,
      vulnerability_types TEXT NOT NULL,technologies TEXT NOT NULL,asset_types TEXT NOT NULL,tags TEXT NOT NULL,
      author TEXT,license TEXT,notes TEXT,content TEXT NOT NULL,content_sha256 TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS kb_patterns(
      pattern_id TEXT PRIMARY KEY,document_id TEXT NOT NULL REFERENCES kb_documents(document_id),
      vulnerability_type TEXT NOT NULL,root_cause TEXT NOT NULL,preconditions TEXT NOT NULL,
      reproduction_summary TEXT NOT NULL,evidence_summary TEXT NOT NULL,impact TEXT NOT NULL,
      remediation TEXT NOT NULL,false_positives TEXT NOT NULL,confidence TEXT NOT NULL,
      source_spans TEXT NOT NULL,created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_kb_patterns_type ON kb_patterns(vulnerability_type);
    """)
    try:
        db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS kb_search USING fts5(document_id UNINDEXED,title,content,tags,vulnerability_types,technologies,tokenize='unicode61')")
        db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS kb_pattern_search USING fts5(pattern_id UNINDEXED,vulnerability_type,root_cause,preconditions,reproduction_summary,evidence_summary,impact,remediation,false_positives,tokenize='unicode61')")
    except sqlite3.OperationalError:
        pass
    db.commit()

def validate_meta(meta):
    schema=json.loads((ROOT/"templates/knowledge-document.schema.json").read_text(encoding="utf-8"))
    try:
        from jsonschema import Draft202012Validator,FormatChecker
        Draft202012Validator(schema,format_checker=FormatChecker()).validate(meta)
    except ImportError:
        required=set(schema["required"])
        if required-set(meta): raise ValueError("Missing required metadata fields.")
    if meta.get("disclosure_status")!="public": raise ValueError("Only explicitly public material is accepted.")
    u=urlparse(meta.get("source_url",""))
    if u.scheme!="https" or not u.netloc: raise ValueError("source_url must be HTTPS.")
    if len(meta.get("rights_basis","").strip())<8: raise ValueError("Documented rights_basis is required.")

def ingest(db,file,metadata):
    file=Path(file); metadata=Path(metadata)
    if file.suffix.lower() not in TEXT_EXTS: raise ValueError("Only Markdown and text are supported.")
    raw=file.read_bytes()
    if len(raw)>MAX_BYTES: raise ValueError("Document exceeds 2 MB.")
    content=raw.decode("utf-8").replace("\r\n","\n").strip()
    if not content: raise ValueError("Empty document.")
    meta=json.loads(metadata.read_text(encoding="utf-8")); validate_meta(meta)
    digest=hashlib.sha256(content.encode()).hexdigest()
    old=db.execute("SELECT document_id FROM kb_documents WHERE content_sha256=?",(digest,)).fetchone()
    if old: return old["document_id"]
    doc_id="KB-"+digest[:16].upper()
    values=(doc_id,meta["title"],meta["platform"],meta["source_url"],"public",meta["rights_basis"],meta["collected_at"],meta.get("published_at"),meta["content_type"],json.dumps(meta.get("vulnerability_types",[])),json.dumps(meta.get("technologies",[])),json.dumps(meta.get("asset_types",[])),json.dumps(meta.get("tags",[])),meta.get("author"),meta.get("license"),meta.get("notes"),content,digest,now())
    db.execute("INSERT INTO kb_documents VALUES("+",".join("?" for _ in values)+")",values)
    try:
        db.execute("INSERT INTO kb_search VALUES(?,?,?,?,?,?)",(doc_id,meta["title"],content,json.dumps(meta.get("tags",[])),json.dumps(meta.get("vulnerability_types",[])),json.dumps(meta.get("technologies",[]))))
    except sqlite3.OperationalError: pass
    db.commit(); return doc_id

def search(db,query,limit=5):
    if not query.strip(): raise ValueError("Query is empty.")
    limit=max(1,min(int(limit),20))
    try:
        return db.execute("""SELECT d.document_id,d.title,d.platform,d.source_url,d.content_type,
          snippet(kb_search,2,'[',']',' … ',18) excerpt
          FROM kb_search JOIN kb_documents d USING(document_id)
          WHERE kb_search MATCH ? ORDER BY rank LIMIT ?""",(query,limit)).fetchall()
    except sqlite3.OperationalError:
        terms=re.findall(r"[\w.-]+",query)[:8]
        where=" AND ".join("(content LIKE ? OR title LIKE ? OR tags LIKE ? OR vulnerability_types LIKE ? OR technologies LIKE ?)" for _ in terms)
        args=[]
        for term in terms: args.extend(["%"+term+"%"]*5)
        return db.execute(f"SELECT document_id,title,platform,source_url,content_type,substr(content,1,500) excerpt FROM kb_documents WHERE {where} LIMIT ?",(*args,limit)).fetchall()

def import_pattern(db,path):
    p=json.loads(Path(path).read_text(encoding="utf-8"))
    schema=json.loads((ROOT/"templates/knowledge-pattern.schema.json").read_text(encoding="utf-8"))
    from jsonschema import Draft202012Validator
    Draft202012Validator(schema).validate(p)
    if not db.execute("SELECT 1 FROM kb_documents WHERE document_id=? AND disclosure_status='public'",(p["document_id"],)).fetchone():
        raise ValueError("Pattern must reference an ingested public document.")
    fields=("pattern_id","document_id","vulnerability_type","root_cause","preconditions","reproduction_summary","evidence_summary","impact","remediation","false_positives","confidence","source_spans")
    vals=[p[k] if k in {"pattern_id","document_id","vulnerability_type","root_cause","reproduction_summary","evidence_summary","impact","remediation","confidence"} else json.dumps(p[k],ensure_ascii=False) for k in fields]
    db.execute("INSERT OR REPLACE INTO kb_patterns VALUES("+",".join("?" for _ in fields)+",?)",(*vals,now()))
    try:
        db.execute("INSERT OR REPLACE INTO kb_pattern_search VALUES(?,?,?,?,?,?,?,?,?)",(p["pattern_id"],p["vulnerability_type"],p["root_cause"],json.dumps(p["preconditions"]),p["reproduction_summary"],p["evidence_summary"],p["impact"],p["remediation"],json.dumps(p["false_positives"])))
    except sqlite3.OperationalError: pass
    db.commit(); return p["pattern_id"]

def search_patterns(db,query,limit=5):
    limit=max(1,min(int(limit),20))
    try:
        return db.execute("""SELECT p.pattern_id,p.document_id,p.vulnerability_type,p.root_cause,p.preconditions,
        p.reproduction_summary,p.evidence_summary,p.impact,p.remediation,p.false_positives,p.confidence,
        d.title,d.platform,d.source_url FROM kb_pattern_search s JOIN kb_patterns p USING(pattern_id)
        JOIN kb_documents d USING(document_id) WHERE kb_pattern_search MATCH ? ORDER BY rank LIMIT ?""",(query,limit)).fetchall()
    except sqlite3.OperationalError:
        like="%"+query+"%"
        return db.execute("""SELECT p.*,d.title,d.platform,d.source_url FROM kb_patterns p JOIN kb_documents d USING(document_id)
        WHERE p.vulnerability_type LIKE ? OR p.root_cause LIKE ? OR p.reproduction_summary LIKE ? LIMIT ?""",(like,like,like,limit)).fetchall()

def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("--db",type=Path,default=DEFAULT_DB)
    sp=ap.add_subparsers(dest="cmd",required=True)
    sp.add_parser("init")
    a=sp.add_parser("ingest"); a.add_argument("--file",required=True); a.add_argument("--metadata",required=True)
    a=sp.add_parser("search"); a.add_argument("--query",required=True); a.add_argument("--limit",type=int,default=5)
    a=sp.add_parser("import-pattern"); a.add_argument("--file",required=True)
    a=sp.add_parser("search-patterns"); a.add_argument("--query",required=True); a.add_argument("--limit",type=int,default=5)
    a=sp.add_parser("make-pattern-template"); a.add_argument("--document-id",required=True); a.add_argument("--output",required=True)
    args=ap.parse_args()
    try:
        db=connect(args.db); init_db(db)
        if args.cmd=="init": out={"status":"initialized","db":str(args.db)}
        elif args.cmd=="ingest": out={"document_id":ingest(db,args.file,args.metadata)}
        elif args.cmd=="search": out={"results":[dict(x) for x in search(db,args.query,args.limit)]}
        elif args.cmd=="import-pattern": out={"pattern_id":import_pattern(db,args.file)}
        elif args.cmd=="search-patterns": out={"results":[dict(x) for x in search_patterns(db,args.query,args.limit)]}
        else:
            doc=db.execute("SELECT document_id,title,source_url FROM kb_documents WHERE document_id=? AND disclosure_status='public'",(args.document_id,)).fetchone()
            if not doc: raise ValueError("Public source document not found.")
            template={"pattern_id":"PATTERN-REPLACE-ME","document_id":doc["document_id"],"vulnerability_type":"","root_cause":"","preconditions":[],"reproduction_summary":"","evidence_summary":"","impact":"","remediation":"","false_positives":[],"confidence":"low","source_spans":[]}
            Path(args.output).parent.mkdir(parents=True,exist_ok=True); Path(args.output).write_text(json.dumps(template,indent=2),encoding="utf-8")
            out={"template":args.output,"source_title":doc["title"],"source_url":doc["source_url"]}
        print(json.dumps(out,ensure_ascii=False,indent=2)); return 0
    except Exception as exc:
        print(json.dumps({"error":str(exc)},ensure_ascii=False),file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
