"""Tiny stdlib DNS client: UDP with TCP fallback, random IDs, strict reply matching, hard timeouts."""
from __future__ import annotations

import secrets
import socket
import struct
import time

from .dns_wire import DnsError, DnsResponse, build_query, parse_response

DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8")


def system_resolvers() -> list[str]:
    try:
        with open("/etc/resolv.conf") as fh:
            found = [l.split()[1] for l in fh if l.startswith("nameserver") and len(l.split()) > 1]
        return found or list(DEFAULT_RESOLVERS)
    except OSError:
        return list(DEFAULT_RESOLVERS)


class DnsClient:
    def __init__(self, resolvers=None, timeout: float = 3.0, tries: int = 2):
        self.resolvers = [r if isinstance(r, tuple) else (r, 53) for r in (resolvers or system_resolvers())]
        self.timeout, self.tries = timeout, tries

    def query(self, name: str, qtype: str) -> DnsResponse:
        last = "no resolver answered"
        for _ in range(self.tries):
            for host, port in self.resolvers:
                try:
                    qid = secrets.randbelow(65536)
                    pkt = build_query(name, qtype, qid)
                    resp = self._udp(host, port, pkt, qid)
                    if resp.truncated:
                        resp = self._tcp(host, port, pkt, qid)
                    return resp
                except (OSError, DnsError) as e:
                    last = f"{type(e).__name__}: {e}"
        raise DnsError(last)

    def _udp(self, host: str, port: int, pkt: bytes, qid: int) -> DnsResponse:
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(pkt, (host, port))
            deadline = time.monotonic() + self.timeout
            while True:
                s.settimeout(max(0.05, deadline - time.monotonic()))
                data, src = s.recvfrom(4096)
                if src[0] != host or len(data) < 2 or struct.unpack("!H", data[:2])[0] != qid:
                    if time.monotonic() > deadline:
                        raise DnsError("timeout")
                    continue  # ignore spoofed / unrelated datagrams
                return parse_response(data)

    def _tcp(self, host: str, port: int, pkt: bytes, qid: int) -> DnsResponse:
        with socket.create_connection((host, port), self.timeout) as s:
            s.settimeout(self.timeout)
            s.sendall(struct.pack("!H", len(pkt)) + pkt)
            hdr = _recv_exact(s, 2)
            data = _recv_exact(s, struct.unpack("!H", hdr)[0])
        resp = parse_response(data)
        if resp.id != qid:
            raise DnsError("id mismatch")
        return resp


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DnsError("connection closed")
        buf += chunk
    return buf
