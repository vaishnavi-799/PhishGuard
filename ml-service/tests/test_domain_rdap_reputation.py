import unittest
from datetime import datetime, timezone

from analysis.dns_wire import DnsError, DnsResponse, Record
from analysis.domain_analysis import analyze_dns, analyze_domain
from analysis.rdap import BOOTSTRAP_URL, RdapClient, parse_rdap, pick_server
from analysis.reputation import assess_reputation, load_blocklist

NOW = datetime(2026, 1, 31, tzinfo=timezone.utc)
RDAP_DOC = {"events": [{"eventAction": "registration", "eventDate": "2026-01-21T10:00:00Z"}, {"eventAction": "expiration", "eventDate": "2027-01-21T10:00:00Z"}, {"eventAction": "last changed", "eventDate": "2026-01-22T00:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar LLC"]]]}, {"roles": ["registrant"], "remarks": [{"title": "REDACTED FOR PRIVACY"}]}],
            "status": ["client transfer prohibited"], "nameservers": [{"ldhName": "NS2.EXAMPLE.NET"}, {"ldhName": "ns1.example.net"}]}
BOOTSTRAP = {"services": [[["com", "net"], ["http://insecure.example/", "https://rdap.verisign.com/com/v1"]], [["io"], ["https://rdap.nic.io/"]]]}


class FakeDns:
    def __init__(self, table):
        self.table, self.calls = table, []

    def query(self, name, qtype):
        self.calls.append((name, qtype))
        v = self.table.get((name, qtype), DnsResponse(1, 0, False))
        if isinstance(v, Exception):
            raise v
        return v


def resp(rcode=0, *records):
    return DnsResponse(1, rcode, False, list(records))


class RdapTests(unittest.TestCase):
    def test_parse_rdap(self):
        r = parse_rdap(RDAP_DOC, NOW)
        self.assertEqual((r["age_days"], r["registrar"], r["privacy_redacted"]), (9, "Example Registrar LLC", True))
        self.assertEqual(r["nameservers"], ["ns1.example.net", "ns2.example.net"])
        self.assertTrue(r["registered_at"].startswith("2026-01-21") and r["expires_at"].startswith("2027-01-21"))

    def test_parse_rdap_missing_fields(self):
        r = parse_rdap({}, NOW)
        self.assertEqual((r["age_days"], r["registrar"], r["privacy_redacted"], r["nameservers"]), (None, None, None, []))
        self.assertEqual(parse_rdap({"events": [{"eventAction": "registration", "eventDate": "garbage"}]}, NOW)["age_days"], None)

    def test_pick_server_prefers_https_and_normalises_slash(self):
        self.assertEqual(pick_server(BOOTSTRAP, "COM"), "https://rdap.verisign.com/com/v1/")
        self.assertEqual(pick_server(BOOTSTRAP, "io"), "https://rdap.nic.io/")
        self.assertIsNone(pick_server(BOOTSTRAP, "zz"))

    def test_client_lookup_and_caching(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return BOOTSTRAP if url == BOOTSTRAP_URL else RDAP_DOC
        c = RdapClient(fetch)
        r = c.lookup("example.com")
        self.assertTrue(r["available"])
        self.assertEqual(r["registrar"], "Example Registrar LLC")
        self.assertIn("https://rdap.verisign.com/com/v1/domain/example.com", calls)
        n = len(calls)
        c.lookup("example.com")
        self.assertEqual(len(calls), n)  # served from cache

    def test_client_degrades_gracefully(self):
        self.assertEqual(RdapClient(lambda u: BOOTSTRAP).lookup("example.zz")["error"], "no_rdap_server_for_tld")
        self.assertEqual(RdapClient(lambda u: BOOTSTRAP if u == BOOTSTRAP_URL else None).lookup("example.com")["error"], "rdap_unavailable")

        def boom(url):
            raise OSError("network down")
        self.assertEqual(RdapClient(boom).lookup("example.com")["error"], "rdap_failed")


class DnsAnalysisTests(unittest.TestCase):
    def test_resolving_domain(self):
        dns = FakeDns({("example.com", "A"): resp(0, Record("example.com", "A", 3600, "93.184.216.34")), ("example.com", "NS"): resp(0, Record("example.com", "NS", 1, "A.IANA-SERVERS.NET"), Record("example.com", "NS", 1, "b.iana-servers.net")),
                       ("example.com", "MX"): resp(0, Record("example.com", "MX", 1, {"preference": 10, "exchange": "mx.example.com"}))})
        d = analyze_dns(dns, "example.com", "example.com")
        self.assertTrue(d["resolves"])
        self.assertEqual((d["nameservers"], d["mx_count"], d["min_ttl"], d["findings"]), (["a.iana-servers.net", "b.iana-servers.net"], 1, 3600, []))

    def test_nxdomain(self):
        d = analyze_dns(FakeDns({("gone.example", "A"): resp(3)}), "gone.example", "gone.example")
        self.assertIs(d["resolves"], False)
        self.assertIn("dns_not_resolving", [f["id"] for f in d["findings"]])

    def test_private_ip_and_fast_flux(self):
        recs = [Record("x.com", "A", 60, f"198.51.100.{i}") for i in range(1, 7)]
        self.assertTrue(analyze_dns(FakeDns({("x.com", "A"): resp(0, *recs)}), "x.com", "x.com")["fast_flux_suspected"])
        d = analyze_dns(FakeDns({("x.com", "A"): resp(0, Record("x.com", "A", 3600, "10.0.0.5"))}), "x.com", "x.com")
        self.assertTrue(d["resolves_to_private_ip"])
        self.assertIn("private_ip_resolution", [f["id"] for f in d["findings"]])

    def test_resolver_failures_are_recorded_not_raised(self):
        d = analyze_dns(FakeDns({("x.com", "A"): DnsError("timeout")}), "x.com", "x.com")
        self.assertIsNone(d["resolves"])
        self.assertTrue(d["errors"])

    def test_analyze_domain_statuses(self):
        self.assertEqual(analyze_domain("1.2.3.4", "1.2.3.4", is_ip=True)["status"], "skipped")
        dns = FakeDns({("example.com", "A"): resp(0, Record("example.com", "A", 3600, "93.184.216.34"))})
        full = analyze_domain("example.com", "example.com", is_ip=False, dns=dns, rdap=RdapClient(lambda u: BOOTSTRAP if u == BOOTSTRAP_URL else RDAP_DOC))
        self.assertEqual(full["status"], "ok")
        self.assertTrue(full["registration"]["available"])
        partial = analyze_domain("example.com", "example.com", is_ip=False, dns=dns, rdap=RdapClient(lambda u: None))
        self.assertEqual(partial["status"], "partial")


class ReputationTests(unittest.TestCase):
    def kw(self, **o):
        base = dict(host="example.com", registered_domain="example.com", tld_risky=False, is_shortener=False, age_days=2000, dns_resolves=True)
        return {**base, **o}

    def test_established_domain_is_good(self):
        r = assess_reputation(**self.kw())
        self.assertEqual(r["rating"], "Good")
        self.assertEqual(r["providers"][0]["provider"], "LocalHeuristics")
        self.assertEqual(r["providers"][0]["reputation"], "Clean")

    def test_new_domain_is_poor(self):
        r = assess_reputation(**self.kw(age_days=3))
        self.assertEqual(r["rating"], "Poor")
        self.assertIn("domain_very_new", [i["id"] for i in r["indicators"]])
        self.assertEqual(r["providers"][0]["reputation"], "Suspicious")
        self.assertIn("domain_new", [i["id"] for i in assess_reputation(**self.kw(age_days=20))["indicators"]])
        self.assertIn("domain_recent", [i["id"] for i in assess_reputation(**self.kw(age_days=60))["indicators"]])

    def test_free_hosting_dynamic_dns_shortener_risky_tld(self):
        ids = lambda **k: {i["id"] for i in assess_reputation(**self.kw(**k))["indicators"]}
        self.assertIn("free_hosting", ids(host="x.weebly.com", registered_domain="weebly.com"))
        self.assertIn("free_hosting", ids(host="a.b.pages.dev", registered_domain="pages.dev"))
        self.assertIn("dynamic_dns", ids(host="x.duckdns.org", registered_domain="duckdns.org"))
        self.assertIn("url_shortener", ids(is_shortener=True))
        self.assertIn("risky_tld", ids(tld_risky=True))
        self.assertIn("no_dns_record", ids(dns_resolves=False))

    def test_unknown_age_gives_unknown_rating(self):
        self.assertEqual(assess_reputation(**self.kw(age_days=None))["rating"], "Unknown")

    def test_blocklist(self):
        r = assess_reputation(**self.kw(registered_domain="evil.example", host="www.evil.example", blocklist={"evil.example"}))
        self.assertEqual(r["rating"], "Poor")
        bl = [p for p in r["providers"] if p["provider"] == "LocalBlocklist"][0]
        self.assertTrue(bl["is_known_malicious"])
        clean = [p for p in assess_reputation(**self.kw(blocklist={"other.example"}))["providers"] if p["provider"] == "LocalBlocklist"][0]
        self.assertFalse(clean["is_known_malicious"])

    def test_load_blocklist_file(self):
        import tempfile, os
        f = os.path.join(tempfile.mkdtemp(), "bl.txt")
        with open(f, "w") as fh:
            fh.write("# comment\nEvil.Example\n\nbad.test\n")
        self.assertEqual(load_blocklist(f), {"evil.example", "bad.test"})
        self.assertEqual(load_blocklist("/nope"), set())
        self.assertEqual(load_blocklist(None), set())

    def test_dnsbl(self):
        listed = FakeDns({("evil.example.dbl.test", "A"): resp(0, Record("x", "A", 1, "127.0.1.2"))})
        r = assess_reputation(**self.kw(registered_domain="evil.example"), dns=listed, dnsbl_zones=("dbl.test",))
        p = [x for x in r["providers"] if x["provider"] == "DNSBL:dbl.test"][0]
        self.assertTrue(p["is_known_malicious"])
        self.assertIn("dnsbl_listed", [i["id"] for i in r["indicators"]])
        refused = FakeDns({("example.com.dbl.test", "A"): resp(0, Record("x", "A", 1, "127.255.255.254"))})  # operator says "query refused"
        p = [x for x in assess_reputation(**self.kw(), dns=refused, dnsbl_zones=("dbl.test",))["providers"] if x["provider"].startswith("DNSBL")][0]
        self.assertEqual((p["reputation"], p["is_known_malicious"]), ("Unknown", False))
        clean = [x for x in assess_reputation(**self.kw(), dns=FakeDns({}), dnsbl_zones=("dbl.test",))["providers"] if x["provider"].startswith("DNSBL")][0]
        self.assertEqual(clean["reputation"], "Clean")
        err = FakeDns({("example.com.dbl.test", "A"): DnsError("x")})
        self.assertEqual([x for x in assess_reputation(**self.kw(), dns=err, dnsbl_zones=("dbl.test",))["providers"] if x["provider"].startswith("DNSBL")][0]["reputation"], "Unknown")


if __name__ == "__main__":
    unittest.main()
