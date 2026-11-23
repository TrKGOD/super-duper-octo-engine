import unittest
from urllib.parse import urlsplit

from scripts.active_surface import (
    SurfaceParser,
    _analyse_js,
    _canonical,
    _safe_path_url,
    _same_origin,
)


class ActiveSurfaceTests(unittest.TestCase):
    def test_extracts_same_origin_links_scripts_and_form_parameters(self):
        parser = SurfaceParser()
        parser.feed("""
            <a href="/account">Account</a>
            <script src="/assets/app.js"></script>
            <form action="/search" method="GET">
              <input name="q"><input name="category">
            </form>
            <img src="/ignored.png">
        """)
        self.assertEqual(parser.links, ["/account"])
        self.assertEqual(parser.scripts, ["/assets/app.js"])
        self.assertEqual(parser.forms[0]["fields"], ["q", "category"])

    def test_same_origin_filter_rejects_external_and_non_http_links(self):
        base = "https://app.example.test/"
        self.assertEqual(_safe_path_url(base, "/api/users"), "https://app.example.test/api/users")
        self.assertIsNone(_safe_path_url(base, "https://outside.example/"))
        self.assertIsNone(_safe_path_url(base, "javascript:alert(1)"))
        self.assertIsNone(_safe_path_url(base, "/logout"))
        self.assertTrue(_same_origin(base, "https://app.example.test/next"))
        self.assertFalse(_same_origin(base, "http://app.example.test/"))

    def test_static_javascript_analysis_finds_routes_and_sinks_without_execution(self):
        source = """
          fetch('/api/v2/profile');
          const endpoint = '/graphql';
          element.innerHTML = userInput;
          eval(payload);
          window.postMessage(message, '*');
        """
        routes, indicators = _analyse_js(source)
        self.assertIn("/api/v2/profile", routes)
        self.assertIn("/graphql", routes)
        self.assertIn("dom-xss-sink", {item["type"] for item in indicators})
        self.assertIn("dynamic-code-execution", {item["type"] for item in indicators})
        self.assertIn("postmessage-wildcard", {item["type"] for item in indicators})

    def test_canonicalization_drops_fragments_and_normalizes_origin(self):
        self.assertEqual(
            _canonical("HTTPS://APP.EXAMPLE.TEST/path#fragment"),
            "https://app.example.test/path",
        )


if __name__ == "__main__":
    unittest.main()
