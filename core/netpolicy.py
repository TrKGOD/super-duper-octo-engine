"""Deterministic network-destination policy.

One implementation of "may this process connect to that address?" shared by the HTTP broker
(`core/active_executor.py`), the browser guard (`core/auth/playwright_runner.py`) and the worker
network layer (`core/workers/`). It is *deterministic* (no LLM, no heuristics) and *default
deny*: a destination is permitted only if every address it resolves to is globally routable
(or is explicitly allow-listed by the operator's lab policy) and is not a cloud
metadata service.

What this module is, and is not
-------------------------------
It classifies destinations and validates resolution results. It does **not** by itself stop a
hostile process from opening a socket: that needs an operating-system or container network
control (see ``docs/ISOLATED_EXECUTION.md`` and :func:`render_egress_firewall`). Application
level checks are the first layer; they are never presented as the only one.

Design points
-------------
* A fixed table of blocked networks rather than ``ipaddress.is_global``: the stdlib
  classification changed between Python releases, and security decisions must not depend on
  the interpreter version.
* IPv4-mapped (``::ffff:a.b.c.d``), NAT64 (``64:ff9b::/96``), 6to4 (``2002::/16``) and
  IPv4-compatible addresses are unwrapped and the *embedded* IPv4 is classified too.
* Non-canonical IPv4 notation (``2130706433``, ``0x7f.1``, ``0177.0.0.1``, ``127.1``) is
  rejected outright: getaddrinfo(3) accepts all of them as ``127.0.0.1`` while naive string
  checks do not, which is a classic SSRF filter bypass.
* The caller must connect to the *validated* address (pinning), never re-resolve the name.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class DestinationDenied(ValueError):
    """The destination is not permitted. ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


_BLOCKED_V4 = (
    ("0.0.0.0/8", "unspecified"), ("10.0.0.0/8", "private"), ("100.64.0.0/10", "shared_cgnat"),
    ("127.0.0.0/8", "loopback"), ("169.254.0.0/16", "link_local"), ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "ietf_protocol"), ("192.0.2.0/24", "documentation"),
    ("192.88.99.0/24", "6to4_relay"), ("192.168.0.0/16", "private"), ("198.18.0.0/15", "benchmarking"),
    ("198.51.100.0/24", "documentation"), ("203.0.113.0/24", "documentation"),
    ("224.0.0.0/4", "multicast"), ("240.0.0.0/4", "reserved"), ("255.255.255.255/32", "broadcast"),
)
_BLOCKED_V6 = (
    ("::/128", "unspecified"), ("::1/128", "loopback"), ("100::/64", "discard"),
    ("2001::/23", "ietf_protocol"), ("2001:db8::/32", "documentation"),
    ("fc00::/7", "unique_local"), ("fe80::/10", "link_local"), ("fec0::/10", "site_local"),
    ("ff00::/8", "multicast"),
)
# IPv6 transition mechanisms that carry an IPv4 address. The wrapped IPv4 is classified; a
# wrapped *public* address is still refused ("transition_address"): no authorized target is
# ever addressed this way, and the stdlib disagrees across versions on whether it is global.
_V6_WRAPPERS = (
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped
    ipaddress.ip_network("64:ff9b::/96"),     # NAT64
    ipaddress.ip_network("2002::/16"),        # 6to4
    ipaddress.ip_network("::/96"),            # IPv4-compatible (deprecated)
)
# Cloud metadata / control endpoints. Some sit in otherwise-public space (Azure wire server,
# Alibaba), so a "is it private?" test alone would let them through.
_METADATA = frozenset(ipaddress.ip_address(a) for a in (
    "169.254.169.254", "169.254.170.2", "169.254.169.123", "100.100.100.200",
    "192.0.0.192", "168.63.129.16", "fd00:ec2::254",
))

# Most-specific network first, so 255.255.255.255 is "broadcast" (not the enclosing
# 240.0.0.0/4 "reserved") and ::1 is "loopback" (not part of the ::/96 compat range).
_BLOCKED = tuple(sorted(
    ((ipaddress.ip_network(cidr), name) for cidr, name in _BLOCKED_V4 + _BLOCKED_V6),
    key=lambda item: -item[0].prefixlen))


def _embedded_ipv4(address: ipaddress.IPv6Address):
    packed = address.packed
    for network in _V6_WRAPPERS:
        if address in network:
            if network.prefixlen == 16:                       # 6to4: IPv4 follows the 2002 prefix
                return ipaddress.IPv4Address(packed[2:6])
            return ipaddress.IPv4Address(packed[12:16])       # mapped / NAT64 / compatible
    return None


def classify(address) -> str | None:
    """Return the denial category for a non-public address, or ``None`` if it is public."""
    ip = address if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)) \
        else ipaddress.ip_address(str(address))
    if ip in _METADATA:
        return "metadata_service"
    for network, name in _BLOCKED:                 # specific entries first (::1, ::, 255.255.255.255)
        if ip.version == network.version and ip in network:
            return name
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            inner = classify(embedded)
            return ("wrapped_" + inner) if inner else "transition_address"
    return None


def parse_host(host: str):
    """Classify a URL host as ``("ip", address)`` or ``("dns", name)``.

    Raises :class:`DestinationDenied` for non-canonical numeric notations, which every
    resolver would turn into an address the allow-list never saw.
    """
    if not isinstance(host, str) or not host or "\x00" in host or any(c.isspace() for c in host):
        raise DestinationDenied("invalid_host", "empty or malformed host")
    bare = host.strip("[]")
    if "%" in bare:                                           # IPv6 zone id: link-local selector
        raise DestinationDenied("zone_identifier", "scoped IPv6 literals are not permitted")
    try:
        return "ip", ipaddress.ip_address(bare)
    except ValueError:
        pass
    labels = bare.rstrip(".").split(".")
    # A host made only of numbers/hex/octal-looking labels would be read as an IPv4 address
    # by inet_aton(3) even though ipaddress rejected it above.
    if all(label and (label.isdigit() or label.lower().startswith("0x")) for label in labels):
        raise DestinationDenied("non_canonical_ip_notation", host)
    return "dns", bare.rstrip(".").lower()


@dataclass(frozen=True)
class EgressPolicy:
    """Operator-declared lab exceptions to the default-deny rule.

    ``allow_networks`` are CIDRs/addresses explicitly authorised even though they are not
    public (a loopback lab target, a documentation-range host). Metadata endpoints are only
    ever allowed by an *exact* single-address entry, never by a covering CIDR.
    """
    allow_networks: tuple = ()

    @classmethod
    def from_scope(cls, scope: dict) -> "EgressPolicy":
        entries = list((scope or {}).get("allowed_ips", [])) + list((scope or {}).get("allowed_cidrs", []))
        networks = []
        for item in entries:
            try:
                networks.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError:
                continue
        return cls(tuple(networks))

    def _explicitly_allowed(self, ip: IPAddress, category: str) -> bool:
        for network in self.allow_networks:
            if network.version != ip.version or ip not in network:
                continue
            if category.endswith("metadata_service") and network.num_addresses != 1:
                continue
            return True
        return False

    def check_address(self, address) -> IPAddress:
        ip = ipaddress.ip_address(str(address))
        category = classify(ip)
        if category is None and not ip.is_global:
            # Belt and braces: anything the stdlib calls non-global is denied too. The
            # allowed set is the *intersection* of both classifiers, so a newer or older
            # Python can only ever make the decision stricter, never looser.
            category = "not_globally_routable"
        if category is not None and not self._explicitly_allowed(ip, category):
            raise DestinationDenied(category, str(ip))
        return ip

    def check_resolved(self, addresses) -> list:
        """Every resolved address must pass; one bad record (DNS rebinding / split answers)
        rejects the whole destination."""
        addresses = list(addresses)
        if not addresses:
            raise DestinationDenied("unresolvable", "no addresses")
        return [self.check_address(a) for a in addresses]


def resolve_all(host: str, port: int, resolver=socket.getaddrinfo) -> list[str]:
    """Resolve once and return every distinct address (sorted for determinism)."""
    try:
        answers = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise DestinationDenied("unresolvable", str(exc)) from exc
    return sorted({answer[4][0].split("%", 1)[0] for answer in answers})


def render_egress_firewall(allowed_destinations, *, chain: str = "WITHERHOARD-EGRESS",
                           container_cidr: str) -> str:
    """Render an nftables-compatible *default-deny* egress ruleset for worker containers.

    This is a deployment artefact: the framework cannot install it for you (it needs
    privileges on the container host). ``docs/ISOLATED_EXECUTION.md`` lists it as an explicit
    deployment prerequisite whenever a tool is allowed any network access.
    """
    lines = [f"table inet witherhoard {{", f"  chain {chain} {{",
             "    type filter hook forward priority 0; policy accept;"]
    lines.append(f"    ip saddr {container_cidr} ct state established,related accept")
    for destination in allowed_destinations:
        network = ipaddress.ip_network(str(destination), strict=False)
        family = "ip" if network.version == 4 else "ip6"
        lines.append(f"    {family} saddr {container_cidr} {family} daddr {network} accept")
    lines.append(f"    ip saddr {container_cidr} drop")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"
