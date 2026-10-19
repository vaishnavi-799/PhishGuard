import ipaddress
import struct
import unittest

from analysis.dns_client import DnsClient
from analysis.dns_wire import DnsError, build_query, parse_response
from tests._servers import start_dns


def name_wire(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\x00"


def make_response(req: bytes, answers, rcode=0, tc=False, qid=None):
    """answers: [(rtype, ttl, rdata_bytes)] for the question's name (uses a compression pointer to offset 12)."""
    rid = req[:2] if qid is None else struct.pack("!H", qid)
    flags = 0x8180 | rcode | (0x0200 if tc else 0)
    out = rid + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0) + req[12:]
    for rtype, ttl, rd in answers:
        out += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rd)) + rd
    return out


A = lambda ip: (1, 60, ipaddress.IPv4Address(ip).packed)


class WireTests(unittest.TestCase):
    def test_build_query_layout(self):
        q = build_query("example.com", "A", 0xABCD)
        self.assertEqual(q[:2], b"\xab\xcd")
        self.assertEqual(struct.unpack("!HHHHH", q[2:12]), (0x0100, 1, 0, 0, 0))
        self.assertTrue(q.endswith(name_wire("example.com") + struct.pack("!HH", 1, 1)))
        self.assertIn(b"xn--", build_query("münchen.de", "A", 1))  # IDN names are punycoded

    def test_build_query_rejects_bad_names(self):
        for bad in ["", "a" * 64 + ".com", "a..com", ("a" * 60 + ".") * 5 + "com"]:
            with self.assertRaises(DnsError):
                build_query(bad, "A", 1)

    def test_parse_each_record_type(self):
        req = build_query("example.com", "A", 7)
        ns = name_wire("ns1.example.org")
        mx = struct.pack("!H", 10) + name_wire("mail.example.com")
        txt = bytes([5]) + b"v=spf" + bytes([2]) + b"1 "
        aaaa = ipaddress.IPv6Address("2001:db8::1").packed
        r = parse_response(make_response(req, [A("93.184.216.34"), (2, 300, ns), (15, 300, mx), (16, 60, txt), (28, 60, aaaa), (5, 60, ns)]))
        self.assertEqual((r.id, r.rcode_name, r.truncated), (7, "NOERROR", False))
        self.assertEqual(r.of_type("A")[0].data, "93.184.216.34")
        self.assertEqual(r.of_type("NS")[0].data, "ns1.example.org")
        self.assertEqual(r.of_type("MX")[0].data, {"preference": 10, "exchange": "mail.example.com"})
        self.assertEqual(r.of_type("TXT")[0].data, "v=spf1 ")
        self.assertEqual(r.of_type("AAAA")[0].data, "2001:db8::1")
        self.assertEqual(r.of_type("CNAME")[0].ttl, 60)
        self.assertEqual(r.answers[0].name, "example.com")

    def test_nxdomain_and_truncation_flags(self):
        req = build_query("nope.example", "A", 1)
        self.assertEqual(parse_response(make_response(req, [], rcode=3)).rcode_name, "NXDOMAIN")
        self.assertTrue(parse_response(make_response(req, [], tc=True)).truncated)

    def test_malformed_packets_raise_dns_error(self):
        req = build_query("example.com", "A", 1)
        good = make_response(req, [A("1.2.3.4")])
        for bad in [b"", b"\x00" * 5, good[:20], good[:-2], req]:  # last one is a query, not a response
            with self.assertRaises(DnsError):
                parse_response(bad)
        loop = req[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + name_wire("a.com") + struct.pack("!HH", 1, 1) + b"\xc0\x1c" + struct.pack("!HHIH", 1, 1, 1, 4) + b"\x01\x02\x03\x04"
        loop = loop[:12 + len(name_wire("a.com")) + 4] + b"\xc0" + bytes([12 + len(name_wire("a.com")) + 4]) + loop[12 + len(name_wire("a.com")) + 6:]
        with self.assertRaises(DnsError):
            parse_response(loop)  # pointer pointing at itself must not hang


class ClientTests(unittest.TestCase):
    def test_udp_query_and_spoofed_datagrams_ignored(self):
        def handler(req, proto):
            wrong = make_response(req, [A("6.6.6.6")], qid=(struct.unpack("!H", req[:2])[0] + 1) % 65536)  # attacker guess: wrong ID
            return [wrong, make_response(req, [A("93.184.216.34")])]
        port, stop = start_dns(handler)
        try:
            r = DnsClient([("127.0.0.1", port)], timeout=1.0).query("example.com", "A")
            self.assertEqual([a.data for a in r.of_type("A")], ["93.184.216.34"])
        finally:
            stop()

    def test_truncated_udp_falls_back_to_tcp(self):
        def handler(req, proto):
            return [make_response(req, [], tc=True)] if proto == "udp" else [make_response(req, [A("10.9.8.7")])]
        port, stop = start_dns(handler, tcp=True)
        try:
            r = DnsClient([("127.0.0.1", port)], timeout=1.0).query("example.com", "A")
            self.assertEqual(r.of_type("A")[0].data, "10.9.8.7")
        finally:
            stop()

    def test_timeout_raises_quickly(self):
        port, stop = start_dns(lambda req, proto: [])  # never answers
        try:
            import time
            t = time.monotonic()
            with self.assertRaises(DnsError):
                DnsClient([("127.0.0.1", port)], timeout=0.3, tries=1).query("example.com", "A")
            self.assertLess(time.monotonic() - t, 2.0)
        finally:
            stop()

    def test_second_resolver_is_used_when_first_fails(self):
        dead, stop_dead = start_dns(lambda req, proto: [])
        live, stop_live = start_dns(lambda req, proto: [make_response(req, [A("1.1.1.1")])])
        try:
            r = DnsClient([("127.0.0.1", dead), ("127.0.0.1", live)], timeout=0.3, tries=1).query("example.com", "A")
            self.assertEqual(r.of_type("A")[0].data, "1.1.1.1")
        finally:
            stop_dead(); stop_live()


if __name__ == "__main__":
    unittest.main()
