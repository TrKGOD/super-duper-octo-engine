import ipaddress
import unittest

from core.netpolicy import (DestinationDenied, EgressPolicy, classify, parse_host,
                            render_egress_firewall, resolve_all)


class ClassificationTests(unittest.TestCase):
    def test_public_addresses_are_not_classified(self):
        for address in ("8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "1.1.1.1"):
            self.assertIsNone(classify(address), address)

    def test_non_public_ipv4_ranges_are_classified(self):
        expected = {
            "127.0.0.1": "loopback", "10.1.2.3": "private", "172.16.0.9": "private",
            "192.168.1.1": "private", "169.254.10.10": "link_local", "100.64.0.1": "shared_cgnat",
            "0.0.0.0": "unspecified", "224.0.0.1": "multicast", "255.255.255.255": "broadcast",
            "198.18.0.1": "benchmarking", "192.0.2.5": "documentation",
        }
        for address, category in expected.items():
            self.assertEqual(classify(address), category, address)

    def test_non_public_ipv6_ranges_are_classified(self):
        expected = {"::1": "loopback", "fe80::1": "link_local", "fc00::1": "unique_local",
                    "fd12:3456::1": "unique_local", "ff02::1": "multicast", "::": "unspecified",
                    "2001:db8::1": "documentation"}
        for address, category in expected.items():
            self.assertEqual(classify(address), category, address)

    def test_cloud_metadata_endpoints_are_always_flagged_even_in_public_space(self):
        for address in ("169.254.169.254", "168.63.129.16", "100.100.100.200", "fd00:ec2::254"):
            self.assertEqual(classify(address), "metadata_service", address)

    def test_ipv4_wrapped_in_ipv6_is_classified_by_the_embedded_address(self):
        # Mapped / NAT64 / 6to4 forms of loopback and metadata must not slip through.
        self.assertEqual(classify("::ffff:127.0.0.1"), "wrapped_loopback")
        self.assertEqual(classify("::ffff:169.254.169.254"), "wrapped_metadata_service")
        self.assertEqual(classify("64:ff9b::7f00:1"), "wrapped_loopback")      # NAT64 of 127.0.0.1
        self.assertEqual(classify("2002:7f00:1::"), "wrapped_loopback")        # 6to4 of 127.0.0.1
        self.assertEqual(classify("::2"), "wrapped_unspecified")               # IPv4-compatible
        # A wrapped *public* address is refused too: transition forms are never an authorized
        # target, and the stdlib is_global result for them differs between Python versions.
        self.assertEqual(classify("::ffff:8.8.8.8"), "transition_address")


class HostParsingTests(unittest.TestCase):
    def test_canonical_hosts_are_accepted(self):
        self.assertEqual(parse_host("app.example.test"), ("dns", "app.example.test"))
        self.assertEqual(parse_host("APP.Example.Test."), ("dns", "app.example.test"))
        self.assertEqual(parse_host("93.184.216.34")[0], "ip")
        self.assertEqual(parse_host("[2606:4700:4700::1111]")[0], "ip")

    def test_non_canonical_ipv4_notations_are_rejected(self):
        # Every one of these is 127.0.0.1 to getaddrinfo(3) and a plain hostname to a string filter.
        for host in ("2130706433", "0x7f000001", "0x7f.1", "0177.0.0.1", "127.1", "0300.0250.0.1"):
            with self.assertRaises(DestinationDenied, msg=host) as raised:
                parse_host(host)
            self.assertEqual(raised.exception.reason, "non_canonical_ip_notation", host)

    def test_scoped_ipv6_and_malformed_hosts_are_rejected(self):
        for host in ("fe80::1%eth0", "", "a b", "bad\x00host", None):
            with self.assertRaises(DestinationDenied, msg=repr(host)):
                parse_host(host)

    def test_ordinary_names_containing_digits_are_still_dns_names(self):
        self.assertEqual(parse_host("1password.example")[0], "dns")
        self.assertEqual(parse_host("api2.example.test")[0], "dns")


class EgressPolicyTests(unittest.TestCase):
    def test_default_policy_denies_everything_non_public(self):
        policy = EgressPolicy()
        policy.check_address("8.8.8.8")
        for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:10.0.0.1"):
            with self.assertRaises(DestinationDenied, msg=address):
                policy.check_address(address)

    def test_explicit_lab_allowance_is_honoured_for_that_address_only(self):
        policy = EgressPolicy.from_scope({"allowed_ips": ["127.0.0.1"], "allowed_cidrs": ["10.9.0.0/16"]})
        policy.check_address("127.0.0.1")
        policy.check_address("10.9.1.1")
        with self.assertRaises(DestinationDenied):
            policy.check_address("127.0.0.2")
        with self.assertRaises(DestinationDenied):
            policy.check_address("10.8.0.1")

    def test_a_broad_cidr_never_unlocks_metadata_endpoints(self):
        broad = EgressPolicy.from_scope({"allowed_cidrs": ["169.254.0.0/16"]})
        with self.assertRaises(DestinationDenied):
            broad.check_address("169.254.169.254")
        exact = EgressPolicy.from_scope({"allowed_ips": ["169.254.169.254"]})
        exact.check_address("169.254.169.254")   # only an exact, deliberate entry allows it

    def test_one_bad_record_rejects_the_whole_answer(self):
        # DNS-rebinding / split-answer defence: [public, private] must fail, not "pick the public one".
        with self.assertRaises(DestinationDenied):
            EgressPolicy().check_resolved(["93.184.216.34", "10.0.0.5"])
        with self.assertRaises(DestinationDenied):
            EgressPolicy().check_resolved([])
        EgressPolicy().check_resolved(["93.184.216.34", "2606:4700:4700::1111"])

    def test_resolve_all_returns_sorted_distinct_addresses_and_strips_zone(self):
        def fake(host, port, type=0):
            return [(2, 1, 6, "", ("93.184.216.34", port)), (2, 1, 6, "", ("93.184.216.34", port)),
                    (10, 1, 6, "", ("fe80::1%eth0", port, 0, 2))]
        self.assertEqual(resolve_all("x.test", 80, resolver=fake), ["93.184.216.34", "fe80::1"])

    def test_resolution_failure_is_a_denial(self):
        def failing(*_a, **_k):
            raise OSError("nxdomain")
        with self.assertRaises(DestinationDenied):
            resolve_all("nope.test", 80, resolver=failing)


class FirewallTemplateTests(unittest.TestCase):
    def test_ruleset_is_default_deny_for_the_container_network(self):
        rules = render_egress_firewall(["93.184.216.34", "203.0.113.0/24"], container_cidr="172.30.0.0/24")
        self.assertIn("ip saddr 172.30.0.0/24 drop", rules)
        self.assertIn("ip daddr 93.184.216.34/32 accept", rules)
        self.assertIn("ip daddr 203.0.113.0/24 accept", rules)
        # the drop must come after every accept so it is the default for unlisted destinations
        self.assertGreater(rules.index("drop"), rules.rindex("accept"))

    def test_ipv6_destinations_use_the_ip6_family(self):
        rules = render_egress_firewall(["2606:4700:4700::1111"], container_cidr="172.30.0.0/24")
        self.assertIn("ip6 daddr 2606:4700:4700::1111/128 accept", rules)


if __name__ == "__main__":
    unittest.main()
