import contextlib
import io
import json
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from scripts import kb_sources
from scripts.kb_sources import AllowlistedRedirectHandler, fetch_feed, parse_feed


class FeedParserTests(unittest.TestCase):
 def test_rss_metadata_only(self):
  xml=b'<rss><channel><item><title>Research writeup</title><link>https://example.org/post</link><pubDate>Mon, 01 Jan 2026 00:00:00 GMT</pubDate></item></channel></rss>'
  rows=parse_feed(xml,"Example")
  self.assertEqual(len(rows),1); self.assertFalse(rows[0]["content_downloaded"]); self.assertEqual(rows[0]["disclosure_status"],"review_required")
 def test_rejects_non_https_item(self):
  xml=b'<rss><channel><item><title>Bad</title><link>http://example.org/post</link></item></channel></rss>'
  self.assertEqual(parse_feed(xml,"Example"),[])

 def test_a_feed_with_a_dtd_or_entities_is_refused_before_parsing(self):
  bomb=(b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        b'<rss><channel><item><title>&b;</title><link>https://example.org/p</link></item></channel></rss>')
  with self.assertRaisesRegex(ValueError,"DTD or entity"):
   parse_feed(bomb,"Example")
  with self.assertRaisesRegex(ValueError,"DTD or entity"):
   parse_feed(b'<! entity x "y"><rss/>',"Example")             # spacing / case variants
  with self.assertRaisesRegex(ValueError,"DTD or entity"):
   parse_feed(bomb.decode("utf-8"),"Example")                  # text input is checked too

 def test_an_oversized_feed_is_refused(self):
  with self.assertRaisesRegex(ValueError,"size limit"):
   parse_feed(b"<rss>"+b"x"*(kb_sources.MAX_BYTES+1)+b"</rss>","Example")


class _Response:
 def __init__(self,body): self.body=body
 def __enter__(self): return self
 def __exit__(self,*exc): return False
 def read(self,n=-1): return self.body[:n] if n>=0 else self.body


class FetchPolicyTests(unittest.TestCase):
 def test_only_allowlisted_https_hosts_are_fetched(self):
  for url in ("http://portswigger.net/feed","https://example.org/feed","https://portswigger.net.evil.example/feed",
              "https://portswigger.net@evil.example/feed","file:///etc/passwd","ftp://portswigger.net/feed"):
   with self.subTest(url=url):
    with patch.object(urllib.request,"build_opener",side_effect=AssertionError("network opener built")):
     with self.assertRaisesRegex(ValueError,"allowlist"):
      fetch_feed(url)

 def test_a_redirect_off_the_allowlist_is_refused(self):
  handler=AllowlistedRedirectHandler()
  request=urllib.request.Request("https://portswigger.net/feed")
  for target in ("https://evil.example/feed","http://portswigger.net/feed","https://portswigger.net.evil.example/x"):
   with self.subTest(target=target):
    with self.assertRaisesRegex(ValueError,"allowlist"):
     handler.redirect_request(request,None,302,"Found",{},target)
  moved=handler.redirect_request(request,None,302,"Found",{},"https://www.portswigger.net/feed2")
  self.assertEqual(moved.full_url,"https://www.portswigger.net/feed2")

 def test_the_response_size_is_bounded(self):
  class Opener:
   def open(self,request,timeout=None): return _Response(b"x"*(kb_sources.MAX_BYTES+50))
  with patch.object(urllib.request,"build_opener",return_value=Opener()):
   with self.assertRaisesRegex(ValueError,"size limit"):
    fetch_feed("https://portswigger.net/feed")

 def test_a_timeout_is_always_set(self):
  seen={}
  class Opener:
   def open(self,request,timeout=None):
    seen["timeout"]=timeout; return _Response(b"<rss/>")
  with patch.object(urllib.request,"build_opener",return_value=Opener()):
   fetch_feed("https://portswigger.net/feed")
  self.assertTrue(0<seen["timeout"]<=30)


class CommandLineTests(unittest.TestCase):
 def run_main(self,config,output):
  err=io.StringIO(); out=io.StringIO()
  with patch("sys.argv",["kb_sources.py","--config",str(config),"--output",str(output)]):
   with contextlib.redirect_stderr(err),contextlib.redirect_stdout(out):
    code=kb_sources.main()
  return code,out.getvalue(),err.getvalue()

 def test_a_refused_feed_reports_a_json_error_and_exit_code_2(self):
  with tempfile.TemporaryDirectory() as tmp:
   config=Path(tmp)/"c.json"; output=Path(tmp)/"out.json"
   config.write_text(json.dumps({"feeds":[{"name":"x","url":"https://example.org/feed"}]}),encoding="utf-8")
   code,_,err=self.run_main(config,output)
   self.assertEqual(code,2)
   self.assertIn("allowlist",json.loads(err)["error"])
   self.assertFalse(output.exists(),"nothing may be written when a feed is refused")

 def test_discovery_writes_metadata_only(self):
  class Opener:
   def open(self,request,timeout=None):
    return _Response(b'<rss><channel><item><title>T</title><link>https://portswigger.net/p</link></item></channel></rss>')
  with tempfile.TemporaryDirectory() as tmp, patch.object(urllib.request,"build_opener",return_value=Opener()):
   config=Path(tmp)/"c.json"; output=Path(tmp)/"inbox"/"out.json"
   config.write_text(json.dumps({"feeds":[{"name":"ps","url":"https://portswigger.net/feed"}]}),encoding="utf-8")
   code,out,_=self.run_main(config,output)
   self.assertEqual(code,0)
   (row,)=json.loads(output.read_text(encoding="utf-8"))
   self.assertEqual((row["content_downloaded"],row["disclosure_status"]),(False,"review_required"))
   self.assertIn("Metadata only",out)

if __name__=="__main__": unittest.main()
