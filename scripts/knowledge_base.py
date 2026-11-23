#!/usr/bin/env python3
"""Local public security research KB with seed import, provenance and structured patterns."""
from __future__ import annotations
import argparse, hashlib, json, re, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_DB=Path(".local/knowledge-base.sqlite3")
MAX_BYTES=2_000_000
TEXT_EXTS={".md",".txt"}
DOMAIN_BY_PREFIX={"WEB":"web","MOB":"mobile","CLOUD":"cloud","AD":"active_directory"}

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")

def connect(path):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(str(path)); db.row_factory=sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def _columns(db, table):
    return {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}

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
    cols=_columns(db,"kb_patterns")
    if "domain" not in cols: db.execute("ALTER TABLE kb_patterns ADD COLUMN domain TEXT NOT NULL DEFAULT 'other'")
    if "tags" not in cols: db.execute("ALTER TABLE kb_patterns ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'")
    try:
        db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS kb_search USING fts5(document_id UNINDEXED,title,content,tags,vulnerability_types,technologies,tokenize='unicode61')")
        db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS kb_pattern_search_v2 USING fts5(pattern_id UNINDEXED,domain UNINDEXED,tags,vulnerability_type,root_cause,preconditions,reproduction_summary,evidence_summary,impact,remediation,false_positives,tokenize='unicode61')")
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

def _index_document(db, doc_id, title, content, tags, vuln_types, technologies):
    try:
        db.execute("DELETE FROM kb_search WHERE document_id=?",(doc_id,))
        db.execute("INSERT INTO kb_search VALUES(?,?,?,?,?,?)",(doc_id,title,content,json.dumps(tags),json.dumps(vuln_types),json.dumps(technologies)))
    except sqlite3.OperationalError:
        pass

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
    _index_document(db,doc_id,meta["title"],content,meta.get("tags",[]),meta.get("vulnerability_types",[]),meta.get("technologies",[]))
    db.commit(); return doc_id

def _fts_query(query):
    terms=re.findall(r"[\w.-]+",query,flags=re.UNICODE)[:12]
    if not terms: raise ValueError("Query must contain searchable terms.")
    return " OR ".join('"'+term.replace('"','""')+'"' for term in terms)

def search(db,query,limit=5):
    if not query.strip(): raise ValueError("Query is empty.")
    limit=max(1,min(int(limit),20))
    try:
        return db.execute("""SELECT d.document_id,d.title,d.platform,d.source_url,d.content_type,
          snippet(kb_search,2,'[',']',' … ',18) excerpt
          FROM kb_search JOIN kb_documents d USING(document_id)
          WHERE kb_search MATCH ? ORDER BY rank LIMIT ?""",(_fts_query(query),limit)).fetchall()
    except sqlite3.OperationalError:
        terms=re.findall(r"[\w.-]+",query)[:8]
        if not terms: return []
        where=" OR ".join("(content LIKE ? OR title LIKE ? OR tags LIKE ? OR vulnerability_types LIKE ? OR technologies LIKE ?)" for _ in terms)
        args=[]
        for term in terms: args.extend(["%"+term+"%"]*5)
        return db.execute(f"SELECT document_id,title,platform,source_url,content_type,substr(content,1,500) excerpt FROM kb_documents WHERE {where} LIMIT ?",(*args,limit)).fetchall()

def _pattern_values(p):
    domain=p.get("domain","other")
    tags=p.get("tags",[])
    fields=("pattern_id","document_id","vulnerability_type","root_cause","preconditions","reproduction_summary","evidence_summary","impact","remediation","false_positives","confidence","source_spans")
    vals=[p[k] if k in {"pattern_id","document_id","vulnerability_type","root_cause","reproduction_summary","evidence_summary","impact","remediation","confidence"} else json.dumps(p[k],ensure_ascii=False) for k in fields]
    return vals,domain,tags

def _index_pattern(db,p,domain,tags):
    try:
        db.execute("DELETE FROM kb_pattern_search_v2 WHERE pattern_id=?",(p["pattern_id"],))
        db.execute("INSERT INTO kb_pattern_search_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)",(
          p["pattern_id"],domain," ".join(tags),p["vulnerability_type"],p["root_cause"],
          " ".join(p["preconditions"]),p["reproduction_summary"],p["evidence_summary"],
          p["impact"],p["remediation"]," ".join(p["false_positives"])))
    except sqlite3.OperationalError:
        pass

def import_pattern(db,path):
    p=json.loads(Path(path).read_text(encoding="utf-8"))
    schema=json.loads((ROOT/"templates/knowledge-pattern.schema.json").read_text(encoding="utf-8"))
    from jsonschema import Draft202012Validator
    Draft202012Validator(schema).validate(p)
    if not db.execute("SELECT 1 FROM kb_documents WHERE document_id=? AND disclosure_status='public'",(p["document_id"],)).fetchone():
        raise ValueError("Pattern must reference an ingested public document.")
    vals,domain,tags=_pattern_values(p)
    db.execute("""INSERT INTO kb_patterns
      (pattern_id,document_id,vulnerability_type,root_cause,preconditions,reproduction_summary,evidence_summary,
       impact,remediation,false_positives,confidence,source_spans,created_at,domain,tags)
      VALUES("""+",".join("?" for _ in range(15))+""")
      ON CONFLICT(pattern_id) DO UPDATE SET
       document_id=excluded.document_id,vulnerability_type=excluded.vulnerability_type,
       root_cause=excluded.root_cause,preconditions=excluded.preconditions,
       reproduction_summary=excluded.reproduction_summary,evidence_summary=excluded.evidence_summary,
       impact=excluded.impact,remediation=excluded.remediation,false_positives=excluded.false_positives,
       confidence=excluded.confidence,source_spans=excluded.source_spans,created_at=excluded.created_at,
       domain=excluded.domain,tags=excluded.tags""",(*vals,now(),domain,json.dumps(tags)))
    _index_pattern(db,p,domain,tags)
    db.commit(); return p["pattern_id"]

def _parse_seed_card(block):
    lines=block.splitlines()
    match=re.match(r"##\s+([A-Z]+-\d+)\s+—\s+(.+)",lines[0].strip())
    if not match: return None
    pattern_id,title=match.groups()
    fields={}
    current=None
    for line in lines[1:]:
        m=re.match(r"-\s+\*\*([^*]+):\*\*\s*(.*)",line.strip())
        if m:
            current=m.group(1).strip().lower().replace(" ","_")
            fields[current]=m.group(2).strip()
        elif current and line.strip() and not line.lstrip().startswith("##"):
            fields[current]+=" "+line.strip()
    refs=[]
    for line in lines:
        if line.strip().startswith(("- **References:**","- **Reference:**","- **Sources:**")) or line.strip().startswith(("**References:**","**Reference:**")):
            refs=re.findall(r"https://[^\s;]+",line)
    if not refs:
        refs=re.findall(r"https://[^\s;]+",block)
    if not refs: raise ValueError(f"{pattern_id} has no HTTPS source reference.")
    required=("root_cause","preconditions","safe_validation","evidence","impact","remediation","false_positives")
    missing=[k for k in required if not fields.get(k)]
    if missing: raise ValueError(f"{pattern_id} is missing fields: {', '.join(missing)}")
    prefix=pattern_id.split("-",1)[0]
    domain=DOMAIN_BY_PREFIX.get(prefix,"other")
    asset_type={"web":["web"],"mobile":["mobile"],"cloud":["cloud"],"active_directory":["active_directory"]}.get(domain,["api"] if "API" in title else ["other"])
    tags=[domain,prefix.lower(),*re.findall(r"[a-z0-9]+",title.lower())[:8]]
    return {"pattern_id":pattern_id,"title":title,"domain":domain,"tags":sorted(set(tags)),
      "vulnerability_type":title,"root_cause":fields["root_cause"],
      "preconditions":[fields["preconditions"]],
      "reproduction_summary":fields["safe_validation"],
      "evidence_summary":fields["evidence"],"impact":fields["impact"],
      "remediation":fields["remediation"],"false_positives":[fields["false_positives"]],
      "confidence":"low","source_spans":[f"Seed card heading: {pattern_id}", "Fields: Root cause, Preconditions, Safe validation, Evidence, Impact, Remediation, False positives", "References: "+", ".join(refs)],
      "source_urls":refs,"content":block.strip(),"asset_types":asset_type}

def import_seed(db,seed_dir):
    seed_dir=Path(seed_dir)
    manifest=json.loads((seed_dir/"manifest.json").read_text(encoding="utf-8"))
    imported=[]
    for filename in sorted({entry["file"] for entry in manifest["domains"].values()}):
        content=(seed_dir/filename).read_text(encoding="utf-8")
        blocks=re.split(r"(?=^##\s+[A-Z]+-\d+\s+—)",content,flags=re.MULTILINE)
        for block in blocks:
            if not re.match(r"##\s+[A-Z]+-\d+\s+—",block.strip()): continue
            card=_parse_seed_card(block)
            if not card: continue
            digest=hashlib.sha256(card["content"].encode()).hexdigest()
            doc_id="KB-"+digest[:16].upper()
            source_url=card["source_urls"][0]
            platform={"web":"OWASP","mobile":"OWASP MAS","cloud":"Cloud provider security guidance","active_directory":"Microsoft and government AD guidance","other":"Public security guidance"}.get(card["domain"],"OWASP API Security")
            meta={"title":card["pattern_id"]+" — "+card["title"],"platform":platform,"source_url":source_url,
              "disclosure_status":"public","rights_basis":"Original analyst-authored summary with source attribution; no third-party report text is redistributed.",
              "collected_at":now(),"published_at":None,"content_type":"research_summary",
              "vulnerability_types":[card["title"]],"technologies":[],"asset_types":card["asset_types"],
              "tags":card["tags"],"author":"Project maintainers","license":"Original project summary; upstream sources linked, not relicensed","notes":"Seed pattern; source links and field spans retained. Reference context only."}
            old=db.execute("SELECT document_id FROM kb_documents WHERE content_sha256=?",(digest,)).fetchone()
            if old: doc_id=old["document_id"]
            else:
                values=(doc_id,meta["title"],meta["platform"],meta["source_url"],"public",meta["rights_basis"],meta["collected_at"],None,meta["content_type"],json.dumps(meta["vulnerability_types"]),json.dumps(meta["technologies"]),json.dumps(meta["asset_types"]),json.dumps(meta["tags"]),meta["author"],meta["license"],meta["notes"],card["content"],digest,now())
                db.execute("INSERT INTO kb_documents VALUES("+",".join("?" for _ in values)+")",values)
                _index_document(db,doc_id,meta["title"],card["content"],meta["tags"],meta["vulnerability_types"],[])
            pattern={"pattern_id":card["pattern_id"],"document_id":doc_id,"vulnerability_type":card["vulnerability_type"],
              "root_cause":card["root_cause"],"preconditions":card["preconditions"],"reproduction_summary":card["reproduction_summary"],
              "evidence_summary":card["evidence_summary"],"impact":card["impact"],"remediation":card["remediation"],
              "false_positives":card["false_positives"],"confidence":card["confidence"],"source_spans":card["source_spans"],
              "domain":card["domain"],"tags":card["tags"]}
            vals,domain,tags=_pattern_values(pattern)
            db.execute("""INSERT INTO kb_patterns
              (pattern_id,document_id,vulnerability_type,root_cause,preconditions,reproduction_summary,evidence_summary,
               impact,remediation,false_positives,confidence,source_spans,created_at,domain,tags)
              VALUES("""+",".join("?" for _ in range(15))+""")
              ON CONFLICT(pattern_id) DO UPDATE SET document_id=excluded.document_id,
               vulnerability_type=excluded.vulnerability_type,root_cause=excluded.root_cause,
               preconditions=excluded.preconditions,reproduction_summary=excluded.reproduction_summary,
               evidence_summary=excluded.evidence_summary,impact=excluded.impact,remediation=excluded.remediation,
               false_positives=excluded.false_positives,confidence=excluded.confidence,
               source_spans=excluded.source_spans,created_at=excluded.created_at,domain=excluded.domain,tags=excluded.tags""",
              (*vals,now(),domain,json.dumps(tags)))
            _index_pattern(db,pattern,domain,tags)
            imported.append(card["pattern_id"])
    db.commit()
    expected=sum(len(v["patterns"]) for v in manifest["domains"].values())
    if len(imported)!=expected:
        raise ValueError(f"Seed manifest expected {expected} domain entries but importer found {len(imported)} cards; found {len(set(imported))} unique patterns.")
    return sorted(set(imported))

def search_patterns(db,query,limit=5,domain=None,tag=None):
    if not query.strip(): raise ValueError("Query is empty.")
    limit=max(1,min(int(limit),50))
    params=[_fts_query(query)]
    filters=[]
    if domain:
        filters.append("p.domain=?"); params.append(domain)
    if tag:
        filters.append("p.tags LIKE ?"); params.append("%"+tag+"%")
    where=" AND ".join(["kb_pattern_search_v2 MATCH ?"]+filters)
    params.append(limit)
    try:
        return db.execute("""SELECT p.pattern_id,p.domain,p.tags,p.document_id,p.vulnerability_type,p.root_cause,p.preconditions,
          p.reproduction_summary,p.evidence_summary,p.impact,p.remediation,p.false_positives,p.confidence,
          d.title,d.platform,d.source_url FROM kb_pattern_search_v2 s JOIN kb_patterns p USING(pattern_id)
          JOIN kb_documents d USING(document_id) WHERE """+where+""" ORDER BY rank LIMIT ?""",params).fetchall()
    except sqlite3.OperationalError:
        terms=re.findall(r"[\w.-]+",query)[:8]
        clauses=[]; args=[]
        for term in terms:
            clauses.append("(p.vulnerability_type LIKE ? OR p.root_cause LIKE ? OR p.reproduction_summary LIKE ? OR p.tags LIKE ?)")
            args.extend(["%"+term+"%"]*4)
        filters=["("+" OR ".join(clauses)+")"]
        if domain: filters.append("p.domain=?"); args.append(domain)
        if tag: filters.append("p.tags LIKE ?"); args.append("%"+tag+"%")
        args.append(limit)
        return db.execute("""SELECT p.pattern_id,p.domain,p.tags,p.document_id,p.vulnerability_type,p.root_cause,p.preconditions,
          p.reproduction_summary,p.evidence_summary,p.impact,p.remediation,p.false_positives,p.confidence,
          d.title,d.platform,d.source_url FROM kb_patterns p JOIN kb_documents d USING(document_id)
          WHERE """+" AND ".join(filters)+""" LIMIT ?""",args).fetchall()

def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("--db",type=Path,default=DEFAULT_DB)
    sp=ap.add_subparsers(dest="cmd",required=True)
    sp.add_parser("init")
    a=sp.add_parser("ingest"); a.add_argument("--file",required=True); a.add_argument("--metadata",required=True)
    a=sp.add_parser("search"); a.add_argument("--query",required=True); a.add_argument("--limit",type=int,default=5)
    a=sp.add_parser("import-pattern"); a.add_argument("--file",required=True)
    a=sp.add_parser("import-seed"); a.add_argument("--seed-dir",type=Path,default=ROOT/"knowledge-base/seed")
    a=sp.add_parser("search-patterns"); a.add_argument("--query",required=True); a.add_argument("--limit",type=int,default=5); a.add_argument("--domain",choices=sorted(set(DOMAIN_BY_PREFIX.values()))+["other"]); a.add_argument("--tag")
    a=sp.add_parser("make-pattern-template"); a.add_argument("--document-id",required=True); a.add_argument("--output",required=True)
    args=ap.parse_args()
    try:
        db=connect(args.db); init_db(db)
        if args.cmd=="init": out={"status":"initialized","db":str(args.db)}
        elif args.cmd=="ingest": out={"document_id":ingest(db,args.file,args.metadata)}
        elif args.cmd=="search": out={"results":[dict(x) for x in search(db,args.query,args.limit)]}
        elif args.cmd=="import-pattern": out={"pattern_id":import_pattern(db,args.file)}
        elif args.cmd=="import-seed":
            ids=import_seed(db,args.seed_dir); out={"imported":len(ids),"pattern_ids":ids,"db":str(args.db)}
        elif args.cmd=="search-patterns": out={"results":[dict(x) for x in search_patterns(db,args.query,args.limit,args.domain,args.tag)]}
        else:
            doc=db.execute("SELECT document_id,title,source_url FROM kb_documents WHERE document_id=? AND disclosure_status='public'",(args.document_id,)).fetchone()
            if not doc: raise ValueError("Public source document not found.")
            template={"pattern_id":"PATTERN-REPLACE-ME","document_id":doc["document_id"],"vulnerability_type":"","root_cause":"","preconditions":[],"reproduction_summary":"","evidence_summary":"","impact":"","remediation":"","false_positives":[],"confidence":"low","source_spans":[]}
            Path(args.output).parent.mkdir(parents=True,exist_ok=True); Path(args.output).write_text(json.dumps(template,indent=2),encoding="utf-8")
            out={"template":args.output,"source_title":doc["title"],"source_url":doc["source_url"]}
        print(json.dumps(out,ensure_ascii=False,indent=2)); return 0
    except Exception as exc:
        print(json.dumps({"error":str(exc)},ensure_ascii=False),file=sys.stderr); return 2
    finally:
        try: db.close()
        except UnboundLocalError: pass

if __name__=="__main__": raise SystemExit(main())
