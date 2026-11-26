"""Initial tool catalog (Component E).

A small, prioritized set of real tool adapters across recon, enumeration, web and content
discovery. Each entry is a **real** adapter: a real command template with injection-safe
parameters, the correct execution profile, and a real, tested output parser. None is
fabricated — the binaries are not bundled, so each is registered with status
`adapter_implemented` and reports `requires_operator_configuration` until the operator
installs it. The end-to-end path is proven with a synthetic stand-in in the tests.
"""
from __future__ import annotations

from core.tools.adapter import BrokeredCommandAdapter
from core.tools.parsers import get_parser
from core.tools.profiles import ACTIVE_CONTROLLED, PASSIVE, SAFE
from core.tools.registry import ToolDefinition, ToolRegistry
from core.workers.tools import ToolParam, ToolSpec

_DOMAIN = ToolParam("domain", pattern=r"[A-Za-z0-9._-]{1,253}")
_URL = ToolParam("url", pattern=r"https?://[A-Za-z0-9._~:/?#%@!$&'()*+,;=\-]{1,2000}")
_WORDLIST = ToolParam("wordlist", pattern=r"[A-Za-z0-9._/\\-]{1,1000}")


def _spec(tool_id, command, params=(), *, risk="medium", timeout=120):
    return ToolSpec(tool_id, tool_id, "operator-provided", "authorized security tool",
                    command=tuple(command), params=tuple(params), network="egress_allowlist",
                    risk=risk, timeout_seconds=timeout, max_output_bytes=2_000_000)


def _tool(tool_id, *, name, category, profile, capabilities, parser, command, params=(),
          vulnerability_classes=(), state_changing=False, risk="medium", description=""):
    return ToolDefinition(
        tool_id=tool_id, name=name, category=category, version="operator-provided",
        spec=_spec(tool_id, command, params, risk=risk),
        capabilities=tuple(capabilities), vulnerability_classes=tuple(vulnerability_classes),
        execution_profile=profile, state_changing=state_changing, risk=risk,
        network="egress_allowlist", binary=tool_id, adapter="brokered-command", parser=parser,
        status="adapter_implemented", description=description)


CATALOG = [
    _tool("subfinder", name="Subfinder", category="recon", profile=PASSIVE,
          capabilities=("subdomain_discovery", "asset_discovery"), parser="subfinder",
          command=("subfinder", "-silent", "-d", "{domain}"), params=(_DOMAIN,), risk="low",
          description="Passive subdomain discovery from public sources."),
    _tool("dnsx", name="dnsx", category="recon", profile=SAFE,
          capabilities=("dns_resolution",), parser="dnsx",
          command=("dnsx", "-json", "-silent", "-d", "{domain}"), params=(_DOMAIN,), risk="low",
          description="DNS resolution and record enumeration."),
    _tool("httpx", name="httpx", category="recon", profile=SAFE,
          capabilities=("http_probing", "technology_fingerprinting"), parser="httpx",
          command=("httpx", "-json", "-silent", "-u", "{url}"), params=(_URL,), risk="low",
          description="Non-destructive HTTP probing and fingerprinting."),
    _tool("katana", name="Katana", category="enumeration", profile=SAFE,
          capabilities=("crawling", "route_discovery"), parser="katana",
          command=("katana", "-silent", "-u", "{url}"), params=(_URL,), risk="low",
          description="Same-origin crawling and route discovery."),
    _tool("ffuf", name="ffuf", category="enumeration", profile=ACTIVE_CONTROLLED,
          capabilities=("content_discovery", "parameter_discovery"), parser="ffuf",
          command=("ffuf", "-of", "json", "-o", "-", "-u", "{url}", "-w", "{wordlist}"),
          params=(_URL, _WORDLIST), risk="medium",
          description="Content and parameter discovery (bounded, authorized)."),
    _tool("nuclei", name="Nuclei", category="web", profile=ACTIVE_CONTROLLED,
          capabilities=("vulnerability_scanning",),
          vulnerability_classes=("misconfiguration", "cve", "exposure"), parser="nuclei",
          command=("nuclei", "-jsonl", "-silent", "-u", "{url}"), params=(_URL,), risk="medium",
          description="Template-based vulnerability detection; produces candidates, not confirmations."),
    _tool("dalfox", name="Dalfox", category="web", profile=ACTIVE_CONTROLLED,
          capabilities=("xss_testing",), vulnerability_classes=("xss",), parser="dalfox",
          command=("dalfox", "url", "{url}", "--format", "json"), params=(_URL,), risk="medium",
          description="XSS investigation; produces candidates, not confirmations."),
]


def build_default_catalog() -> ToolRegistry:
    registry = ToolRegistry()
    for definition in CATALOG:
        registry.register(definition)
    return registry


def adapter_for(definition: ToolDefinition) -> BrokeredCommandAdapter:
    """Return a brokered adapter wired with the tool's real output parser."""
    return BrokeredCommandAdapter(parser=get_parser(definition.parser))
