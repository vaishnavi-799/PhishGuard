import dataclasses
import gzip
import tempfile
import threading
import time
import unittest
from pathlib import Path

from analysis.config import AnalysisConfig
from analysis.http_fetch import SafeFetcher
from analysis.netsafe import Resolved, is_public_ip, resolve_public
from tests._certs import make_cert, write_pair
from tests._servers import route_handler, start_http

HTML = {"Content-Type": "text/html; charset=utf-8"}


def cfg_for(port, **kw):
    return dataclasses.replace(AnalysisConfig(), allow_private_targets=True, fetch_ports=(port,), http_timeout=2.0, total_timeout=6.0, **kw)


class Srv:
    def __init__(self, routes, **tls):
        self.hits = []
        wrapped = {k: (v if callable(v[2]) else (v[0], v[1], v[2])) for k, v in routes.items()}
        base = route_handler(wrapped)
        hits = self.hits

        class H(base):
            def do_GET(self):
                hits.append(self.path)
                super().do_GET()
        self.srv, self.port = start_http(H, **tls)
        self.url = lambda p="/": f"http://127.0.0.1:{self.port}{p}"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class NetSafeTests(unittest.TestCase):
    def test_public_vs_private_addresses(self):
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"]:
            self.assertTrue(is_public_ip(ip), ip)
        for ip in ["127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "224.0.0.1", "::ffff:10.0.0.1", "192.0.2.5", "not-an-ip"]:
            self.assertFalse(is_public_ip(ip), ip)

    def test_resolve_public_blocks_loopback_unless_allowed(self):
        r = resolve_public("127.0.0.1", 80)
        self.assertEqual((r.ips, r.blocked), ([], "private_address"))
        self.assertEqual(resolve_public("localhost", 80, allow_private=True).ips[0] in ("127.0.0.1", "::1"), True)
        self.assertEqual(resolve_public("2130706433", 80).blocked, "private_address")      # decimal-encoded 127.0.0.1
        self.assertEqual(resolve_public("0x7f000001", 80).blocked, "private_address")      # hex-encoded
        self.assertEqual(resolve_public("no-such-host.invalid", 80).error, "dns_failure")


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.close()

    def serve(self, routes, **kw):
        s = Srv(routes, **kw)
        self.servers.append(s)
        return s

    def test_plain_html(self):
        s = self.serve({"/": (200, HTML, b"<html><title>Hi</title></html>")})
        r = SafeFetcher(cfg_for(s.port)).fetch(s.url())
        self.assertEqual((r.status, r.content_type, r.body, r.blocked, r.error, r.tls_verified, r.truncated), (200, "text/html", b"<html><title>Hi</title></html>", None, None, None, False))
        self.assertEqual(r.final_url, s.url())

    def test_redirect_chain_is_recorded(self):
        s = self.serve({"/a": (302, {"Location": "/b"}, b""), "/b": (301, {"Location": "/c"}, b""), "/c": (200, HTML, b"done")})
        r = SafeFetcher(cfg_for(s.port)).fetch(s.url("/a"))
        self.assertEqual((r.status, r.body, len(r.redirects), r.final_url), (200, b"done", 2, s.url("/c")))
        self.assertEqual([x["status"] for x in r.redirects], [302, 301])
        self.assertFalse(any(x["cross_domain"] for x in r.redirects))

    def test_cross_domain_redirect_flagged(self):
        landing = self.serve({"/": (200, HTML, b"landing")})
        start = self.serve({"/go": (302, {"Location": f"http://localhost:{landing.port}/"}, b"")})
        cfg = dataclasses.replace(cfg_for(start.port), fetch_ports=(start.port, landing.port))
        r = SafeFetcher(cfg).fetch(start.url("/go"))
        self.assertEqual((r.status, r.body), (200, b"landing"))
        self.assertTrue(r.redirects[0]["cross_domain"])  # 127.0.0.1 -> localhost

    def test_redirect_loop_is_cut_off(self):
        s = self.serve({"/loop": (302, {"Location": "/loop"}, b"")})
        r = SafeFetcher(dataclasses.replace(cfg_for(s.port), max_redirects=3)).fetch(s.url("/loop"))
        self.assertEqual((r.blocked, len(r.redirects)), ("too_many_redirects", 3))
        self.assertEqual(len(s.hits), 4)

    def test_body_is_capped(self):
        s = self.serve({"/": (200, HTML, b"<p>" + b"a" * 200_000)})
        r = SafeFetcher(cfg_for(s.port, max_body_bytes=10_000)).fetch(s.url())
        self.assertEqual((len(r.body), r.truncated), (10_000, True))

    def test_downloads_are_never_read(self):
        s = self.serve({"/z": (200, {"Content-Type": "application/zip"}, b"PK\x03\x04" + b"x" * 100), "/d": (200, {"Content-Type": "text/html", "Content-Disposition": "attachment; filename=a.html"}, b"<html>"),
                        "/x": (200, {"Content-Type": "application/octet-stream"}, b"MZ")})
        f = SafeFetcher(cfg_for(s.port))
        for p in ("/z", "/d", "/x"):
            r = f.fetch(s.url(p))
            self.assertEqual((r.body, r.is_download, r.status), (None, True, 200), p)

    def test_json_is_readable(self):
        s = self.serve({"/j": (200, {"Content-Type": "application/rdap+json"}, b'{"a": 1}')})
        self.assertEqual(SafeFetcher(cfg_for(s.port)).fetch(s.url("/j"), accept="application/json").body, b'{"a": 1}')

    def test_gzip_and_decompression_bomb(self):
        s = self.serve({"/g": (200, {**HTML, "Content-Encoding": "gzip"}, gzip.compress(b"<html>ok</html>")), "/bomb": (200, {**HTML, "Content-Encoding": "gzip"}, gzip.compress(b"0" * 30_000_000)),
                        "/br": (200, {**HTML, "Content-Encoding": "br"}, b"\x00\x01")})
        f = SafeFetcher(cfg_for(s.port, max_body_bytes=10_000))
        self.assertEqual(f.fetch(s.url("/g")).body, b"<html>ok</html>")
        bomb = f.fetch(s.url("/bomb"))
        self.assertLessEqual(len(bomb.body), 10_000)
        self.assertTrue(bomb.truncated)
        self.assertEqual(f.fetch(s.url("/br")).body, b"")  # unsupported encoding: ignored, not guessed

    def test_private_targets_are_blocked_without_connecting(self):
        s = self.serve({"/": (200, HTML, b"secret")})
        r = SafeFetcher(dataclasses.replace(AnalysisConfig(), fetch_ports=(s.port,))).fetch(s.url())
        self.assertEqual((r.blocked, r.status, r.body), ("private_address", None, None))
        self.assertEqual(s.hits, [])  # the server never saw a request

    def test_redirect_into_private_space_is_blocked(self):
        secret = self.serve({"/secret": (200, HTML, b"internal data")})
        start = self.serve({"/r": (302, {"Location": f"http://internal.test:{secret.port}/secret"}, b"")})

        def resolver(host, port, allow):  # public.test "resolves" to a reachable address; internal.test resolves to a private one
            return Resolved(ips=["127.0.0.1"]) if host == "public.test" else Resolved(blocked="private_address")
        cfg = dataclasses.replace(cfg_for(start.port), allow_private_targets=False, fetch_ports=(start.port, secret.port))
        r = SafeFetcher(cfg, resolver=resolver).fetch(f"http://public.test:{start.port}/r")
        self.assertEqual((r.blocked, len(r.redirects)), ("private_address", 1))
        self.assertEqual(secret.hits, [])  # the internal service was never contacted

    def test_disallowed_port_and_scheme(self):
        f = SafeFetcher(AnalysisConfig())
        self.assertEqual(f.fetch("http://example.com:22/").blocked, "port_not_allowed")
        self.assertEqual(f.fetch("http://example.com:6379/").blocked, "port_not_allowed")
        for u in ("ftp://example.com/", "file:///etc/passwd", "gopher://example.com/", "javascript:alert(1)"):
            self.assertEqual(f.fetch(u).blocked, "bad_scheme", u)

    def test_connection_is_pinned_to_the_validated_ip_and_sends_host_header(self):
        s = self.serve({"/": (200, HTML, lambda h: (h.send_response(200), h.send_header("Content-Type", "text/html"), h.send_header("Content-Length", str(len(h.headers["Host"]))), h.end_headers(), h.wfile.write(h.headers["Host"].encode())))})
        r = SafeFetcher(cfg_for(s.port), resolver=lambda h, p, a: Resolved(ips=["127.0.0.1"])).fetch(f"http://pinned.test:{s.port}/")
        self.assertEqual(r.body.decode(), f"pinned.test:{s.port}")

    def test_dns_failure(self):
        r = SafeFetcher(AnalysisConfig(), resolver=lambda h, p, a: Resolved(error="dns_failure")).fetch("http://nx.test/")
        self.assertEqual((r.status, r.error), (None, "dns_failure"))

    def test_slow_server_times_out(self):
        s = self.serve({"/": (200, HTML, lambda h: time.sleep(1.5))})
        t = time.monotonic()
        r = SafeFetcher(dataclasses.replace(cfg_for(s.port), http_timeout=0.3)).fetch(s.url())
        self.assertEqual((r.status, r.error), (None, "timeout"))
        self.assertLess(time.monotonic() - t, 1.4)

    def test_slow_drip_body_cannot_outlive_the_deadline(self):
        def drip(h):
            h.send_response(200); h.send_header("Content-Type", "text/html"); h.send_header("Content-Length", "1000"); h.end_headers()
            for _ in range(50):
                try:
                    h.wfile.write(b"x"); h.wfile.flush(); time.sleep(0.1)
                except OSError:
                    return
        s = self.serve({"/": (200, HTML, drip)})
        t = time.monotonic()
        r = SafeFetcher(cfg_for(s.port)).fetch(s.url(), deadline=time.monotonic() + 0.6)
        self.assertLess(time.monotonic() - t, 2.0)
        self.assertEqual(r.error, "timeout")
        self.assertTrue(0 < len(r.body) < 1000)

    def test_https_with_untrusted_certificate_is_still_inspected(self):
        tmp = Path(tempfile.mkdtemp())
        cert, key = make_cert("localhost", ("localhost",))
        crt, k = write_pair(tmp, cert, key)
        s = self.serve({"/": (200, HTML, b"<title>tls page</title>")}, certfile=crt, keyfile=k)
        r = SafeFetcher(cfg_for(s.port)).fetch(f"https://localhost:{s.port}/")
        self.assertEqual((r.status, r.tls_verified, r.body), (200, False, b"<title>tls page</title>"))


if __name__ == "__main__":
    unittest.main()
