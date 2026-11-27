"""core/html_context.py: deterministic classification of where a marker lands in an HTML document.

Every case below was checked interactively against the raw ``html.parser.HTMLParser`` event stream
before being written down here, specifically because this module depends on two easily-missed
stdlib behaviors: (1) a raw, un-escaped "<...>" is tokenized as an actual (unknown) start tag, never
handed to ``handle_data``; (2) ``HTMLParser`` always entity-decodes attribute VALUES regardless of
``convert_charrefs``, so a *properly escaped* attribute (source ``&lt;marker&gt;``) would come back
already decoded if this module trusted ``attrs`` instead of ``get_starttag_text()``.
"""
import html
import unittest

from core.html_context import classify_marker_context

MARKER = "<wh-xss-ab12cd34>"
ESCAPED = html.escape(MARKER)


class PlainTextTests(unittest.TestCase):
    def test_marker_in_ordinary_body_text_is_html_body(self):
        self.assertEqual(classify_marker_context(f"<html><body><p>hi {MARKER}</p></body></html>", MARKER),
                         "html_body")

    def test_marker_as_a_bare_tag_in_the_body_is_html_body(self):
        # A raw "<"/">" pair is tokenized as a start tag, not handed to handle_data at all.
        self.assertEqual(classify_marker_context(f"<html><body>{MARKER} tail</body></html>", MARKER), "html_body")

    def test_marker_not_present_is_unknown(self):
        self.assertEqual(classify_marker_context("<html><body>nothing here</body></html>", MARKER), "unknown")

    def test_properly_escaped_text_is_unknown_not_html_body(self):
        # The raw source contains "&lt;...&gt;", never the literal marker: no hit at all.
        self.assertEqual(classify_marker_context(f"<html><body>{ESCAPED}</body></html>", MARKER), "unknown")

    def test_non_html_plain_text_still_classifies_without_crashing(self):
        self.assertEqual(classify_marker_context(f"plain text {MARKER} no tags", MARKER), "html_body")


class AttributeTests(unittest.TestCase):
    def test_marker_contained_in_one_attribute_value_is_html_attribute(self):
        self.assertEqual(classify_marker_context(f'<input value="{MARKER}">', MARKER), "html_attribute")

    def test_marker_in_an_event_handler_attribute_is_html_attribute(self):
        self.assertEqual(classify_marker_context(f'<input onmouseover="{MARKER}" foo="bar">', MARKER),
                         "html_attribute")

    def test_marker_in_a_self_closing_tags_attribute_is_html_attribute(self):
        self.assertEqual(classify_marker_context(f'<input value="{MARKER}" />', MARKER), "html_attribute")

    def test_properly_escaped_attribute_value_is_unknown_not_html_attribute(self):
        # HTMLParser entity-decodes attrs regardless of convert_charrefs: the decoded value would
        # equal the marker even though the real source escaped it. get_starttag_text() must win.
        self.assertEqual(classify_marker_context(f'<input value="{ESCAPED}">', MARKER), "unknown")

    def test_marker_repeated_in_two_different_attributes_of_one_tag_is_still_html_attribute(self):
        # Two occurrences, but both inside attribute values: still one region, not ambiguous.
        self.assertEqual(classify_marker_context(f'<input value="{MARKER}" title="{MARKER}">', MARKER),
                         "html_attribute")


class ScriptAndInertElementTests(unittest.TestCase):
    def test_marker_inside_script_text_is_script(self):
        self.assertEqual(classify_marker_context(f'<script>var x = "{MARKER}";</script>', MARKER), "script")

    def test_marker_inside_style_is_unknown(self):
        self.assertEqual(classify_marker_context(f"<style>{MARKER}</style>", MARKER), "unknown")

    def test_marker_inside_textarea_is_unknown(self):
        self.assertEqual(classify_marker_context(f"<textarea>{MARKER}</textarea>", MARKER), "unknown")

    def test_marker_inside_title_is_unknown(self):
        self.assertEqual(classify_marker_context(f"<title>{MARKER}</title>", MARKER), "unknown")

    def test_marker_after_script_closes_is_html_body_again(self):
        self.assertEqual(classify_marker_context(f'<script>"no marker here"</script><p>{MARKER}</p>', MARKER),
                         "html_body")


class CommentsAndMalformedHtmlTests(unittest.TestCase):
    def test_marker_inside_a_comment_is_unknown(self):
        self.assertEqual(classify_marker_context(f"<!-- {MARKER} -->", MARKER), "unknown")

    def test_unclosed_tags_do_not_crash_and_still_classify(self):
        self.assertEqual(classify_marker_context(f"<div><p>{MARKER}<br>unclosed", MARKER), "html_body")

    def test_empty_document_is_unknown(self):
        self.assertEqual(classify_marker_context("", MARKER), "unknown")

    def test_non_string_body_is_unknown(self):
        self.assertEqual(classify_marker_context(None, MARKER), "unknown")       # type: ignore[arg-type]


class AmbiguityIsNeverGuessedTests(unittest.TestCase):
    """More than one distinct region must fall back to unknown rather than pick one."""

    def test_marker_in_both_body_text_and_script_is_unknown(self):
        self.assertEqual(classify_marker_context(f'<p>{MARKER}</p><script>"{MARKER}"</script>', MARKER), "unknown")

    def test_marker_in_both_body_text_and_an_attribute_is_unknown(self):
        self.assertEqual(classify_marker_context(f'<p>{MARKER}</p><input value="{MARKER}">', MARKER), "unknown")

    def test_marker_in_two_separate_tags_both_attributes_is_still_html_attribute(self):
        # Same region (attribute) twice, in different tags, is not ambiguous either.
        self.assertEqual(classify_marker_context(f'<a title="{MARKER}"><b title="{MARKER}">', MARKER),
                         "html_attribute")


class MarkerShapeValidationTests(unittest.TestCase):
    """The module is scoped to the one marker shape this codebase constructs; anything else is refused."""

    def test_rejects_a_marker_without_angle_brackets(self):
        with self.assertRaises(ValueError):
            classify_marker_context("irrelevant", "no-brackets")

    def test_rejects_a_marker_that_is_too_short(self):
        with self.assertRaises(ValueError):
            classify_marker_context("irrelevant", "<ab>")

    def test_rejects_a_marker_that_is_too_long(self):
        with self.assertRaises(ValueError):
            classify_marker_context("irrelevant", "<" + "a" * 100 + ">")

    def test_rejects_a_marker_containing_a_space(self):
        with self.assertRaises(ValueError):
            classify_marker_context("irrelevant", "<has space>")

    def test_rejects_a_marker_containing_a_quote(self):
        with self.assertRaises(ValueError):
            classify_marker_context("irrelevant", '<has"quote>')

    def test_rejects_a_marker_with_a_nested_closing_tag(self):
        with self.assertRaises(ValueError):
            classify_marker_context("irrelevant", "<a>b</a>")

    def test_accepts_the_shortest_and_longest_allowed_markers(self):
        short, long_ = "<" + "a" * 4 + ">", "<" + "a" * 95 + ">"
        self.assertEqual(classify_marker_context(f"text {short}", short), "html_body")
        self.assertEqual(classify_marker_context(f"text {long_}", long_), "html_body")


if __name__ == "__main__":
    unittest.main()
