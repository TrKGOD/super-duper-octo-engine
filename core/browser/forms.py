"""Form and input discovery from (untrusted) DOM snapshots.

Parses forms, their inputs and submission metadata, and classifies each form as
state-changing and/or destructive. The engine records forms for the planner; it never
auto-submits them. Destructive/state-changing classification exists precisely so that
later, workflow-aware stages can refuse to submit them without explicit approval.
"""
from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from core.browser.routes import normalize_route
from core.browser.scope import _origin

_INPUT_TAGS = {"input", "select", "textarea", "button"}
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_DESTRUCTIVE_TERMS = (
    "delete", "remove", "destroy", "drop", "erase", "wipe", "purge", "deactivate",
    "close-account", "close_account", "transfer", "withdraw", "pay", "payment",
    "purchase", "checkout", "charge", "refund", "reset", "revoke", "cancel",
)
_VALIDATION_ATTRS = {"required", "pattern", "min", "max", "minlength", "maxlength", "step"}


def _text_signals(value: str) -> bool:
    low = str(value).lower()
    return any(term in low for term in _DESTRUCTIVE_TERMS)


@dataclass(frozen=True)
class DiscoveredForm:
    action_template: str
    method: str
    origin: str
    fields: tuple          # tuple of {"name","type","required"} dicts (as tuples of items)
    hidden_field_names: tuple
    has_file_input: bool
    has_password_input: bool
    client_validation: bool
    state_changing: bool
    destructive: bool
    source_route: str | None = None

    def to_dict(self) -> dict:
        return {
            "action_template": self.action_template,
            "method": self.method,
            "origin": self.origin,
            "fields": [dict(item) for item in self.fields],
            "hidden_field_names": list(self.hidden_field_names),
            "has_file_input": self.has_file_input,
            "has_password_input": self.has_password_input,
            "client_validation": self.client_validation,
            "state_changing": self.state_changing,
            "destructive": self.destructive,
            "auto_submit_allowed": not (self.state_changing or self.destructive),
            "source_route": self.source_route,
        }


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = {str(k).lower(): (v if v is not None else "") for k, v in attrs if k}
        if tag == "form":
            self._current = {
                "action": values.get("action", ""),
                "method": (values.get("method") or "GET").upper(),
                "fields": [], "hidden": [], "file": False, "password": False,
                "validation": False, "submit_text": [],
            }
            self.forms.append(self._current)
            return
        if self._current is None or tag not in _INPUT_TAGS:
            return
        itype = (values.get("type") or ("submit" if tag == "button" else "text")).lower()
        name = values.get("name") or values.get("id") or ""
        if itype == "file":
            self._current["file"] = True
        if itype == "password":
            self._current["password"] = True
        if any(attr in values for attr in _VALIDATION_ATTRS):
            self._current["validation"] = True
        if itype == "hidden" and name:
            self._current["hidden"].append(name)
        if itype in {"submit", "button"}:
            self._current["submit_text"].append(values.get("value", ""))
        if name or itype not in {"submit", "button"}:
            self._current["fields"].append({
                "name": name, "type": itype,
                "required": "required" in values,
            })

    def handle_data(self, data):
        if self._current is not None and data.strip():
            # Button label text contributes to destructive-intent signals only.
            self._current["submit_text"].append(data.strip())

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._current = None


def build_form(raw: dict, base_url: str, *, source_route: str | None = None) -> DiscoveredForm:
    action = raw.get("action") or base_url
    absolute = urljoin(base_url, action)
    template, _ = normalize_route(absolute)
    method = str(raw.get("method", "GET")).upper()
    field_tuple = tuple({"name": f.get("name", ""), "type": f.get("type", "text"),
                         "required": bool(f.get("required"))} for f in raw.get("fields", []))
    hidden = tuple(raw.get("hidden", []))
    destructive_signal = _text_signals(action) or any(_text_signals(t) for t in raw.get("submit_text", []))
    state_changing = method in _STATE_CHANGING_METHODS or destructive_signal
    return DiscoveredForm(
        action_template=template,
        method=method,
        origin=_origin(absolute),
        fields=field_tuple,
        hidden_field_names=hidden,
        has_file_input=bool(raw.get("file")),
        has_password_input=bool(raw.get("password")),
        client_validation=bool(raw.get("validation")),
        state_changing=bool(state_changing),
        destructive=bool(destructive_signal),
        source_route=source_route,
    )


def parse_forms_from_html(html: str, base_url: str, *, source_route: str | None = None) -> list[DiscoveredForm]:
    parser = _FormParser()
    try:
        parser.feed(str(html or ""))
    except Exception:
        # Untrusted markup must never crash discovery.
        return []
    return [build_form(raw, base_url, source_route=source_route) for raw in parser.forms]


class FormCatalog:
    """Deduplicates discovered forms by (method, action template, field-name set)."""

    def __init__(self) -> None:
        self._forms: dict[tuple, DiscoveredForm] = {}

    def add(self, form: DiscoveredForm) -> None:
        key = (form.method, form.action_template,
               tuple(sorted(f["name"] for f in form.fields if f.get("name"))))
        self._forms.setdefault(key, form)

    def add_many(self, forms) -> None:
        for form in forms:
            self.add(form)

    def __len__(self) -> int:
        return len(self._forms)

    def action_templates(self) -> set[str]:
        return {form.action_template for form in self._forms.values()}

    def normalized(self) -> list[dict]:
        return sorted((form.to_dict() for form in self._forms.values()),
                      key=lambda item: (item["origin"], item["action_template"], item["method"]))
