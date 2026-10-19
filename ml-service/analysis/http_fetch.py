"""SSRF-safe, size- and time-limited HTTP(S) fetcher. Pages are only read as bytes: nothing is executed or saved."""
from __future__ import annotations

import http.client
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from features.url_features import split_host

from .config import AnalysisConfig
from .netsafe import Resolved, resolve_public

TEXT_TYPES = ("text/html", "application/xhtml+xml", "text/plain", "application/xml", "text/xml")


@dataclass
class FetchResult:
    url: str
    final_url: str | None = None
    status: int | None = None
    redirects: list = field(default_factory=list)
    content_type: str | None = None
    content_length: int | None = None
    body: bytes | None = None
    truncated: bool = False
    tls_verified: bool | None = None
    is_download: bool = False
    blocked: str | None = None   # private_address | port_not_allowed | bad_scheme | too_many_redirects
    error: str | None = None
    headers: dict = field(default_factory=dict)


class _HTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):  # connect to the pre-validated IP, not to whatever the name resolves to now (defeats DNS rebinding)
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _HTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _ctx(verify: bool) -> ssl.SSLContext:
    c = ssl.create_default_context()
    if not verify:
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
    return c


class SafeFetcher:
    def __init__(self, cfg: AnalysisConfig, resolver=resolve_public):
        self.cfg, self.resolver = cfg, resolver

    def fetch(self, url: str, *, accept: str = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5", max_bytes: int | None = None, deadline: float | None = None) -> FetchResult:
        cfg, cap = self.cfg, max_bytes or self.cfg.max_body_bytes
        deadline = deadline or time.monotonic() + cfg.total_timeout
        res, current = FetchResult(url=url), url
        for hop in range(cfg.max_redirects + 1):
            sp = urlsplit(current)
            host = sp.hostname
            try:
                port = sp.port or (443 if sp.scheme == "https" else 80)
            except ValueError:
                res.blocked = "bad_scheme"
                return res
            if sp.scheme not in ("http", "https") or not host:
                res.blocked = "bad_scheme"
                return res
            if port not in cfg.fetch_ports:
                res.blocked = "port_not_allowed"
                return res
            rs: Resolved = self.resolver(host, port, cfg.allow_private_targets)
            if rs.blocked or rs.error or not rs.ips:
                res.blocked, res.error = rs.blocked, (rs.error if not rs.blocked else None)
                return res
            resp, conn = self._request(sp, host, port, rs.ips, accept, res, deadline)
            if resp is None:
                return res
            res.status, res.final_url = resp.status, current
            res.headers = {k.lower(): v[:200] for k, v in resp.getheaders() if k.lower() in ("content-type", "content-length", "server", "location", "content-disposition", "refresh", "x-powered-by")}
            loc = resp.getheader("Location")
            if resp.status in (301, 302, 303, 307, 308) and loc:
                if hop >= cfg.max_redirects:  # refuse to follow redirect number max_redirects + 1
                    conn.close()
                    res.blocked = "too_many_redirects"
                    return res
                nxt = urljoin(current, loc)
                a, b = split_host(host)[3], split_host(urlsplit(nxt).hostname or "")[3]
                res.redirects.append({"from": current, "to": nxt, "status": resp.status, "cross_domain": a != b})
                conn.close()
                current = nxt
                continue
            self._read_body(resp, res, cap, deadline)
            conn.close()
            return res
        res.blocked = "too_many_redirects"
        return res

    def _request(self, sp, host, port, ips, accept, res, deadline):
        cfg, path = self.cfg, (sp.path or "/") + (("?" + sp.query) if sp.query else "")
        headers = {"User-Agent": cfg.user_agent, "Accept": accept, "Accept-Encoding": "identity", "Connection": "close"}
        last = "connection_failed"
        for ip in ips[:3]:
            if time.monotonic() > deadline:
                res.error = "timeout"
                return None, None
            for verify in ((True, False) if sp.scheme == "https" else (None,)):
                conn = _HTTPS(host, port, ip, cfg.http_timeout, _ctx(verify)) if sp.scheme == "https" else _HTTP(host, port, ip, cfg.http_timeout)
                try:
                    conn.request("GET", path, headers=headers)
                    resp = conn.getresponse()
                    if verify is not None:
                        res.tls_verified = verify
                    return resp, conn
                except ssl.SSLCertVerificationError:
                    conn.close()
                    last = "tls_verification_failed"
                    continue  # retry unverified: we still want to look at the page, we just remember it was untrusted
                except ssl.SSLError:
                    conn.close()
                    last = "tls_error"
                    break
                except socket.timeout:
                    conn.close()
                    last = "timeout"
                    break
                except (OSError, http.client.HTTPException):
                    conn.close()
                    last = "connection_failed"
                    break
        res.error = last
        return None, None

    def _read_body(self, resp, res: FetchResult, cap: int, deadline: float) -> None:
        ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
        res.content_type = ctype or None
        cl = resp.getheader("Content-Length")
        res.content_length = int(cl) if cl and cl.isdigit() else None
        disp = (resp.getheader("Content-Disposition") or "").lower()
        readable = not ctype or ctype in TEXT_TYPES or ctype.endswith("json")
        if "attachment" in disp or not readable:
            res.is_download = "attachment" in disp or ctype.startswith(("application/octet-stream", "application/zip", "application/x-", "application/vnd", "application/msword", "application/java", "application/pdf"))
            return  # never download payloads: only the headers are recorded
        chunks, total = [], 0
        try:
            while total <= cap:
                if time.monotonic() > deadline:
                    res.error = "timeout"
                    break
                chunk = resp.read1(min(8192, cap + 1 - total))  # read1: returns whatever has arrived, so a slow-drip server cannot stall us past the deadline
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except (OSError, http.client.HTTPException):
            res.error = res.error or "read_failed"
        data = b"".join(chunks)
        if len(data) > cap:
            data, res.truncated = data[:cap], True
        enc = (resp.getheader("Content-Encoding") or "identity").lower()
        if enc in ("gzip", "deflate"):  # decompression bomb protection: output is capped too
            try:
                d = zlib.decompressobj(16 + zlib.MAX_WBITS if enc == "gzip" else zlib.MAX_WBITS)
                data = d.decompress(data, cap)
                res.truncated = res.truncated or bool(d.unconsumed_tail)
            except zlib.error:
                data = b""
        elif enc != "identity":
            data = b""
        res.body = data
