"""Deterministic classification of where a literal marker lands in one HTML document.

This module does not generate, mutate, or try injection payloads, and it does not decide
whether a browser would actually execute anything. Given a response body and a marker the
caller already confirmed is present verbatim (see ``core.validation_engine.oracles.reflected_input``,
which checks presence on the raw string before context is ever consulted), it parses the
document once with the standard library's ``html.parser.HTMLParser`` and reports which
syntactic region contains that marker:

* ``"script"``          - inside the text content of a <script> element
* ``"html_attribute"``  - inside the value of a tag attribute, and nowhere else
* ``"html_body"``       - in ordinary text content, or consumed as tag/attribute SYNTAX
                          itself (e.g. the marker's own "<" and ">" were parsed as a start
                          tag) - either way, unescaped markup reached the body
* ``"unknown"``         - everything this module cannot establish with confidence: the
                          marker is absent, appears in more than one of the regions above,
                          sits inside a comment/declaration/<style>/<textarea>/<title>, or
                          the parse failed

``"unknown"`` is the deliberate fallback for every case this module cannot establish, by
design: a wrong "unknown" only costs a human a confirmation step, while a wrong executable
classification could let a validation oracle treat an inert reflection as a confirmed
finding. This mirrors how ``core/validation_engine/oracles.py`` already treats an
unestablished context as never executable.

Read before trusting a result:
* This reports where the RAW BYTES containing the marker sit in the parse tree, not whether
  a real browser, a client-side framework, or a second decoding pass would execute it. A
  marker inside a <script> element could still sit inside a quoted string literal, a
  comment, or dead code - this module does not parse JavaScript. A marker inside an
  attribute value could still be fully contained within its quotes, never breaking out
  into a new attribute or an event handler - this module does not distinguish that.
* Python's parser is permissive and does not implement a real browser's HTML5
  tree-construction algorithm (foster parenting, the adoption agency algorithm, encoding
  sniffing). A browser could in principle place the same bytes differently.
* It is scoped to markers this codebase actually constructs: a short run of letters,
  digits, hyphens and underscores wrapped in a single pair of angle brackets, with no
  quotes, spaces, or nested "<"/">" of its own. ``classify_marker_context`` raises
  ``ValueError`` for anything else rather than guess at a shape it was not built for.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

_MARKER_SHAPE = re.compile(r"^<[A-Za-z][A-Za-z0-9_-]{3,95}>$")

# HTML "raw text" / "escapable raw text" elements: their content is never tokenized as markup.
_SCRIPT_LIKE = {"script"}
_INERT_RAW_TEXT = {"style", "textarea", "title"}
_RAW_TEXT_ELEMENTS = _SCRIPT_LIKE | _INERT_RAW_TEXT


class _MarkerLocator(HTMLParser):
    """One pass over the document, recording the region of every verbatim occurrence of ``marker``.

    Deliberately reads ``get_starttag_text()`` (the tag's original source) rather than trusting the
    ``attrs`` values the base class hands to ``handle_starttag``: those are always entity-decoded by
    the stdlib parser regardless of ``convert_charrefs``, so a *properly escaped* attribute value
    (source ``&lt;marker&gt;``) would otherwise come back already decoded to the raw marker and be
    misread as an unescaped hit. Gating on the untouched source text first avoids that.
    """

    def __init__(self, marker: str):
        super().__init__(convert_charrefs=False)
        self._marker = marker
        self._stack: list[str] = []
        self._hits: list[str] = []

    def _record(self, region: str) -> None:
        self._hits.append(region)

    def _text_region(self) -> str:
        if not self._stack:
            return "html_body"
        top = self._stack[-1]
        if top in _SCRIPT_LIKE:
            return "script"
        return "unknown"   # style/textarea/title: inert, never asserted executable

    def _handle_tag_open(self, tag: str, attrs: list) -> None:
        raw = self.get_starttag_text() or ""
        if self._marker not in raw:
            return
        marker_in_values = [name for name, value in attrs if value is not None and self._marker in value]
        # Every occurrence of the marker in the raw source sits inside exactly one attribute value,
        # with none left over in the tag's own structure (its name or unquoted syntax): a contained
        # attribute-value reflection. Otherwise some of it reached the tag/attribute syntax itself.
        if marker_in_values and raw.count(self._marker) == sum(
                str(value).count(self._marker) for name, value in attrs if value is not None):
            self._record("html_attribute")
        else:
            self._record("html_body")

    def handle_starttag(self, tag, attrs):
        self._handle_tag_open(tag, attrs)
        tag = tag.lower()
        if tag in _RAW_TEXT_ELEMENTS:
            self._stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self._handle_tag_open(tag, attrs)   # self-closing: no content follows, nothing to push

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()

    def handle_data(self, data):
        if self._marker in data:
            self._record(self._text_region())

    def handle_comment(self, data):
        if self._marker in data:
            self._record("unknown")

    def unknown_decl(self, data):
        if self._marker in data:
            self._record("unknown")

    @property
    def classification(self) -> str:
        distinct = set(self._hits)
        return next(iter(distinct)) if len(distinct) == 1 else "unknown"


def classify_marker_context(html_body: str, marker: str) -> str:
    """Return "script", "html_attribute", "html_body" or "unknown" for one literal marker.

    Raises ``ValueError`` if ``marker`` is not the single-bracket-pair shape this module supports
    (see the module docstring) - a caller passing anything else has stepped outside what this
    deterministic parse was designed and tested for, and should not receive a silent guess.
    """
    if not _MARKER_SHAPE.match(str(marker)):
        raise ValueError("classify_marker_context supports only a '<name>'-shaped marker "
                          "(letters/digits/hyphen/underscore in one bracket pair)")
    if not isinstance(html_body, str) or marker not in html_body:
        return "unknown"
    locator = _MarkerLocator(marker)
    try:
        locator.feed(html_body)
        locator.close()
    except Exception:
        # The stdlib parser is documented to tolerate malformed HTML, but a result from this
        # function can feed a validation oracle, so a parser surprise fails closed, never SUPPORTED.
        return "unknown"
    return locator.classification
