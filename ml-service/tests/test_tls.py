import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from analysis.config import AnalysisConfig
from analysis.netsafe import Resolved
from analysis.tls_analysis import TlsProbe, analyze_tls, evaluate_certificate, hostname_matches, probe
from tests._certs import der, make_cert, write_pair
from tests._servers import start_tls_listener


def ids(r):
    return {f["id"] for f in r["findings"]}


def P(**kw):
    return TlsProbe(**{"verified": True, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", **kw})


class HostnameMatchTests(unittest.TestCase):
    def test_rfc6125_rules(self):
        self.assertTrue(hostname_matches("example.com", ["example.com"]))
        self.assertTrue(hostname_matches("EXAMPLE.com.", ["example.com"]))
        self.assertTrue(hostname_matches("www.example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("example.com", ["*.example.com"]))          # wildcard needs a label
        self.assertFalse(hostname_matches("a.b.example.com", ["*.example.com"]))      # wildcard does not span dots
        self.assertFalse(hostname_matches("evilexample.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("www.example.com", ["w*.example.com"]))     # partial wildcards are not honoured
        self.assertFalse(hostname_matches("example.com", []))


class EvaluateTests(unittest.TestCase):
    def test_valid_certificate(self):
        c, _ = make_cert("example.com", ("example.com", "*.example.com"), days_valid=90, start_offset_days=-30)
        r = evaluate_certificate(der(c), "www.example.com", P())
        self.assertTrue(r["certificate_valid"] and r["hostname_match"] and r["chain_trusted"])
        self.assertEqual((r["issuer"]["organization"], r["subject_common_name"], r["san_count"]), ("Test Org", "example.com", 2))
        self.assertTrue(58 <= r["days_until_expiry"] <= 60 and r["age_days"] == 30 and r["validity_days"] == 90)
        self.assertEqual(r["findings"] and [f for f in r["findings"] if f["id"] != "self_signed"], [])

    def test_expired(self):
        c, _ = make_cert("example.com", ("example.com",), days_valid=10, start_offset_days=-40)
        r = evaluate_certificate(der(c), "example.com", P())
        self.assertTrue(r["expired"] and not r["certificate_valid"])
        self.assertIn("cert_expired", ids(r))

    def test_not_yet_valid(self):
        c, _ = make_cert("example.com", ("example.com",), days_valid=30, start_offset_days=5)
        r = evaluate_certificate(der(c), "example.com", P())
        self.assertTrue(r["not_yet_valid"] and not r["certificate_valid"])
        self.assertIn("cert_not_yet_valid", ids(r))

    def test_hostname_mismatch(self):
        c, _ = make_cert("other.com", ("other.com",))
        r = evaluate_certificate(der(c), "example.com", P())
        self.assertFalse(r["hostname_match"] or r["certificate_valid"])
        self.assertIn("hostname_mismatch", ids(r))

    def test_self_signed_and_untrusted_chain(self):
        c, _ = make_cert("example.com", ("example.com",))
        r = evaluate_certificate(der(c), "example.com", P(verified=False, verify_error="self-signed certificate"))
        self.assertTrue(r["self_signed"] and not r["certificate_valid"])
        self.assertIn("self_signed", ids(r))
        self.assertNotIn("untrusted_chain", ids(r))  # not reported twice
        ca, cak = make_cert("Test CA", (), ca=True)
        leaf, _ = make_cert("example.com", ("example.com",), issuer=(ca, cak))
        r = evaluate_certificate(der(leaf), "example.com", P(verified=False, verify_error="unable to get local issuer certificate"))
        self.assertFalse(r["self_signed"])
        self.assertIn("untrusted_chain", ids(r))

    def test_weak_protocol_and_cipher(self):
        c, _ = make_cert("example.com", ("example.com",))
        self.assertIn("weak_tls", ids(evaluate_certificate(der(c), "example.com", P(cipher="RC4-SHA"))))
        self.assertIn("weak_tls", ids(evaluate_certificate(der(c), "example.com", P(version="TLSv1"))))
        self.assertTrue(evaluate_certificate(der(c), "example.com", P())["weak_cipher"] is False)

    def test_cn_fallback_only_without_san(self):
        c, _ = make_cert("example.com", ())
        self.assertTrue(evaluate_certificate(der(c), "example.com", P())["hostname_match"])
        c, _ = make_cert("example.com", ("other.com",))
        self.assertFalse(evaluate_certificate(der(c), "example.com", P())["hostname_match"])  # SAN present: CN is ignored

    def test_brand_new_certificate_flagged(self):
        c, _ = make_cert("example.com", ("example.com",), days_valid=90, start_offset_days=-2)
        self.assertIn("cert_very_new", ids(evaluate_certificate(der(c), "example.com", P())))

    def test_ip_address_san(self):
        c, _ = make_cert("127.0.0.1", (), ip_sans=("127.0.0.1",))
        self.assertTrue(evaluate_certificate(der(c), "127.0.0.1", P())["hostname_match"])
        self.assertFalse(evaluate_certificate(der(c), "127.0.0.2", P())["hostname_match"])

    def test_fixed_clock(self):
        c, _ = make_cert("example.com", ("example.com",), days_valid=30, start_offset_days=0)
        far = datetime(2099, 1, 1, tzinfo=timezone.utc)
        self.assertTrue(evaluate_certificate(der(c), "example.com", P(), now=far)["expired"])


class AnalyzeTlsTests(unittest.TestCase):
    cfg = AnalysisConfig()

    def test_http_url(self):
        r = analyze_tls("http", "example.com", None, cfg=self.cfg, resolver=None)
        self.assertEqual((r["status"], r["https"]), ("ok", False))
        self.assertIn("no_https", ids(r))

    def test_blocked_and_unresolvable_targets(self):
        r = analyze_tls("https", "internal.test", None, cfg=self.cfg, resolver=lambda h, p, a: Resolved(blocked="private_address"))
        self.assertEqual((r["status"], r["error"]), ("failed", "private_address"))
        r = analyze_tls("https", "nx.test", None, cfg=self.cfg, resolver=lambda h, p, a: Resolved(error="dns_failure"))
        self.assertEqual(r["error"], "dns_failure")

    def test_handshake_failure_and_garbage_certificate(self):
        res = lambda h, p, a: Resolved(ips=["203.0.113.1"])
        r = analyze_tls("https", "x.test", None, cfg=self.cfg, resolver=res, prober=lambda *a: TlsProbe(error="timeout"))
        self.assertEqual((r["status"], r["error"]), ("failed", "timeout"))
        self.assertIn("tls_unavailable", ids(r))
        r = analyze_tls("https", "x.test", None, cfg=self.cfg, resolver=res, prober=lambda *a: TlsProbe(der=b"not a certificate", verified=True))
        self.assertEqual((r["status"], r["error"]), ("failed", "certificate_parse_failed"))

    def test_success_path_uses_prober_result_and_pinned_ip(self):
        c, _ = make_cert("x.test", ("x.test",))
        seen = {}

        def prober(host, port, ip, timeout, server_name):
            seen.update(host=host, port=port, ip=ip, sni=server_name)
            return P(der=der(c))
        r = analyze_tls("https", "x.test", 8443, cfg=self.cfg, resolver=lambda h, p, a: Resolved(ips=["203.0.113.9"]), prober=prober)
        self.assertEqual((r["status"], r["https"], r["certificate_valid"]), ("ok", True, True))
        self.assertEqual(seen, {"host": "x.test", "port": 8443, "ip": "203.0.113.9", "sni": "x.test"})


class LiveProbeTests(unittest.TestCase):
    """Real TLS handshakes against a local listener using generated certificates."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.stops = []

    def tearDown(self):
        for s in self.stops:
            s()

    def listen(self, cert, key):
        crt, k = write_pair(self.tmp, cert, key, f"s{len(self.stops)}")
        port, stop = start_tls_listener(crt, k)
        self.stops.append(stop)
        return port

    def test_self_signed_server(self):
        cert, key = make_cert("localhost", ("localhost",))
        port = self.listen(cert, key)
        pr = probe("localhost", port, "127.0.0.1", 3, "localhost")
        self.assertFalse(pr.verified)
        self.assertTrue(pr.verify_error and pr.der and pr.version in ("TLSv1.2", "TLSv1.3"))
        r = evaluate_certificate(pr.der, "localhost", pr)
        self.assertTrue(r["self_signed"] and r["hostname_match"] and not r["certificate_valid"])

    def test_trusted_chain_with_custom_ca(self):
        ca, cak = make_cert("Test CA", (), ca=True)
        leaf, lk = make_cert("localhost", ("localhost",), issuer=(ca, cak))
        port = self.listen(leaf, lk)
        cafile = self.tmp / "ca.pem"
        cafile.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        pr = probe("localhost", port, "127.0.0.1", 3, "localhost", cafile=str(cafile))
        self.assertTrue(pr.verified, pr.verify_error)
        r = evaluate_certificate(pr.der, "localhost", pr)
        self.assertTrue(r["certificate_valid"] and r["chain_trusted"])
        self.assertEqual(r["issuer"]["common_name"], "Test CA")

    def test_name_mismatch_is_detected_by_verification(self):
        ca, cak = make_cert("Test CA", (), ca=True)
        leaf, lk = make_cert("localhost", ("localhost",), issuer=(ca, cak))
        port = self.listen(leaf, lk)
        cafile = self.tmp / "ca.pem"
        cafile.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        pr = probe("other.test", port, "127.0.0.1", 3, "other.test", cafile=str(cafile))
        self.assertFalse(pr.verified)
        self.assertTrue(pr.der)  # certificate still read for reporting
        self.assertFalse(evaluate_certificate(pr.der, "other.test", pr)["hostname_match"])

    def test_closed_port_and_non_tls_server(self):
        self.assertEqual(probe("localhost", 1, "127.0.0.1", 1, "localhost").error, "tls_handshake_failed")
        import socket, threading
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
        def plain_server():
            c, _ = s.accept()
            with c:
                c.sendall(b"HTTP/1.1 400 Bad\r\n\r\n")
        threading.Thread(target=plain_server, daemon=True).start()
        pr = probe("localhost", s.getsockname()[1], "127.0.0.1", 2, "localhost")
        s.close()
        self.assertIsNone(pr.der)
        self.assertTrue(pr.error)


if __name__ == "__main__":
    unittest.main()
