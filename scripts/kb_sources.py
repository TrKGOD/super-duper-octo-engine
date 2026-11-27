#!/usr/bin/env python3
"""Discover candidate write-ups from explicitly configured public RSS/Atom feeds.

This adapter stores discovery metadata only. It does not download article bodies or
assume that a feed item grants redistribution rights.
"""
import argparse,json,re,sys,urllib.request,xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[1]
CONFIG=ROOT/"config/knowledge-sources.example.json"
MAX_BYTES=1_000_000
# A feed never needs a DTD. Refusing it removes entity-expansion ("billion laughs") from untrusted XML
# before the parser sees it, independently of the expat version in use.
_DTD=re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)",re.I)
ALLOWED_HOSTS={"portswigger.net","www.portswigger.net","blog.projectdiscovery.io","www.microsoft.com","security.googleblog.com","blog.cloudflare.com","www.rapid7.com"}

class AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        parsed=urlparse(newurl)
        if parsed.scheme!="https" or parsed.hostname not in ALLOWED_HOSTS:
            raise ValueError("Feed redirect target is not in the curated HTTPS allowlist.")
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def fetch_feed(url):
    parsed=urlparse(url)
    if parsed.scheme!="https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Feed host is not in the curated HTTPS allowlist.")
    req=urllib.request.Request(url,headers={"User-Agent":"PentestKnowledgeBase/1.0 (public-feed-indexer)"})
    opener=urllib.request.build_opener(AllowlistedRedirectHandler())
    with opener.open(req,timeout=10) as response:
        data=response.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES: raise ValueError("Feed exceeds size limit.")
    return data

def parse_feed(data,source_name):
    raw=data.encode("utf-8","replace") if isinstance(data,str) else data
    if len(raw)>MAX_BYTES: raise ValueError("Feed exceeds size limit.")
    if _DTD.search(raw): raise ValueError("Feed contains a DTD or entity declaration; refusing to parse it.")
    root=ET.fromstring(data); items=[]
    nodes=root.findall(".//item")+root.findall(".//{http://www.w3.org/2005/Atom}entry")
    for node in nodes:
        title=node.findtext("title") or node.findtext("{http://www.w3.org/2005/Atom}title") or ""
        link=node.findtext("link") or ""
        if not link:
            el=node.find("{http://www.w3.org/2005/Atom}link")
            if el is not None: link=el.attrib.get("href","")
        published=node.findtext("pubDate") or node.findtext("{http://www.w3.org/2005/Atom}published") or ""
        if title.strip() and link.startswith("https://"):
            items.append({"title":title.strip(),"url":link.strip(),"published":published,"source":source_name,"disclosure_status":"review_required","content_downloaded":False})
    return items

def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("--config",default=str(CONFIG)); ap.add_argument("--output",default=".local/knowledge-base-inbox/discovered.json")
    args=ap.parse_args()
    try:
        cfg=json.loads(Path(args.config).read_text(encoding="utf-8")); out=[]
        for feed in cfg.get("feeds",[]): out.extend(parse_feed(fetch_feed(feed["url"]),feed["name"]))
        target=Path(args.output); target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding="utf-8")
        print(json.dumps({"discovered":len(out),"output":str(target),"note":"Metadata only; manually verify disclosure and rights before ingesting."}))
        return 0
    except Exception as exc:
        print(json.dumps({"error":str(exc)}),file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
