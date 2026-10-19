"""SSRF guard: decide whether an address may be contacted, and resolve hosts to public IPs only."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and not a.is_multicast  # excludes private, loopback, link-local (169.254.x / cloud metadata), CGNAT, reserved, documentation


@dataclass
class Resolved:
    ips: list = field(default_factory=list)      # addresses that are allowed to be contacted
    private_ips: list = field(default_factory=list)
    blocked: str | None = None                   # "private_address" when every address is non-public
    error: str | None = None                     # "dns_failure"


def _numeric_host(host: str) -> str | None:
    """Normalize legacy decimal/hex IPv4 spellings before DNS resolution."""
    h = str(host).strip().lower()
    try:
        if h.startswith("0x"):
            value = int(h, 16)
        elif h.isdigit() and len(h) >= 8:
            value = int(h, 10)
        else:
            return None
        if 0 <= value <= 0xFFFFFFFF:
            return str(ipaddress.IPv4Address(value))
    except (ValueError, ipaddress.AddressValueError):
        pass
    return None


def resolve_public(host: str, port: int, allow_private: bool = False) -> Resolved:
    host = _numeric_host(host) or host
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return Resolved(error="dns_failure")
    seen, ips = set(), []
    for fam, _, _, _, sa in infos:
        ip = sa[0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    public = [i for i in ips if is_public_ip(i)]
    private = [i for i in ips if not is_public_ip(i)]
    if allow_private:
        return Resolved(ips=ips, private_ips=private)
    if not public:
        return Resolved(private_ips=private, blocked="private_address" if private else None, error=None if private else "dns_failure")
    return Resolved(ips=public, private_ips=private)
