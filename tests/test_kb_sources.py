import unittest
from scripts.kb_sources import parse_feed

class FeedParserTests(unittest.TestCase):
 def test_rss_metadata_only(self):
  xml=b'<rss><channel><item><title>Research writeup</title><link>https://example.org/post</link><pubDate>Mon, 01 Jan 2026 00:00:00 GMT</pubDate></item></channel></rss>'
  rows=parse_feed(xml,"Example")
  self.assertEqual(len(rows),1); self.assertFalse(rows[0]["content_downloaded"]); self.assertEqual(rows[0]["disclosure_status"],"review_required")
 def test_rejects_non_https_item(self):
  xml=b'<rss><channel><item><title>Bad</title><link>http://example.org/post</link></item></channel></rss>'
  self.assertEqual(parse_feed(xml,"Example"),[])
if __name__=="__main__": unittest.main()
