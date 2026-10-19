"""Minimal DNS wire-format encoder/decoder (RFC 1035). Pure functions, no I/O."""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DnsError(Exception):
    pass


@dataclass
class Record:
    name: str
    type: str
    ttl: int
    data: object


@dataclass
class DnsResponse:
    id: int
    rcode: int
    truncated: bool
    answers: list = field(default_factory=list)
    authority: list = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, f"RCODE{self.rcode}")

    def of_type(self, t: str) -> list:
        return [r for r in self.answers if r.type == t]


def build_query(name: str, qtype: str, qid: int, recursion: bool = True) -> bytes:
    try:
        labels = name.rstrip(".").encode("idna").decode("ascii").split(".")
    except UnicodeError as e:
        raise DnsError(f"bad name: {e}") from None
    if not name or any(not l or len(l) > 63 for l in labels) or len(name) > 253:
        raise DnsError("bad name")
    q = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100 if recursion else 0, 1, 0, 0, 0) + q + struct.pack("!HH", QTYPES[qtype], 1)


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    labels, jumps, end = [], 0, None
    while True:
        if off >= len(data):
            raise DnsError("truncated name")
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DnsError("truncated pointer")
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            jumps += 1
            if jumps > 20:
                raise DnsError("compression loop")
            continue
        if n & 0xC0:
            raise DnsError("bad label type")
        off += 1
        if off + n > len(data):
            raise DnsError("truncated label")
        labels.append(data[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels), (end if end is not None else off)


def _rdata(data: bytes, off: int, rtype: int, length: int):
    end = off + length
    if end > len(data):
        raise DnsError("truncated rdata")
    if rtype == 1 and length == 4:
        return str(ipaddress.IPv4Address(data[off:end]))
    if rtype == 28 and length == 16:
        return str(ipaddress.IPv6Address(data[off:end]))
    if rtype in (2, 5):
        return _read_name(data, off)[0]
    if rtype == 15:
        return {"preference": struct.unpack("!H", data[off:off + 2])[0], "exchange": _read_name(data, off + 2)[0]}
    if rtype == 16:
        parts, i = [], off
        while i < end:
            n = data[i]
            parts.append(data[i + 1:i + 1 + n].decode("latin-1"))
            i += 1 + n
        return "".join(parts)
    if rtype == 6:
        mname, p = _read_name(data, off)
        rname, p = _read_name(data, p)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[p:p + 20])
        return {"mname": mname, "rname": rname, "serial": serial, "minimum": minimum}
    return data[off:end].hex()


def parse_response(data: bytes) -> DnsResponse:
    if len(data) < 12:
        raise DnsError("short packet")
    qid, flags, qd, an, ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if not flags & 0x8000:
        raise DnsError("not a response")
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    resp = DnsResponse(qid, flags & 0x000F, bool(flags & 0x0200))

    def section(count: int) -> list:
        nonlocal off
        out = []
        for _ in range(count):
            name, off = _read_name(data, off)
            if off + 10 > len(data):
                raise DnsError("truncated record")
            rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            out.append(Record(name, TYPE_NAMES.get(rtype, str(rtype)), ttl, _rdata(data, off, rtype, rdlen)))
            off += rdlen
        return out

    resp.answers = section(an)
    resp.authority = section(ns)
    return resp
