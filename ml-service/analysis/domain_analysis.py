"""DNS records + registration data (RDAP) for the host's registered domain."""
from __future__ import annotations

from .dns_wire import DnsError
from .netsafe import is_public_ip

FAST_FLUX_MIN_ADDRESSES, FAST_FLUX_MAX_TTL = 5, 300


def analyze_dns(dns, host: str, registered_domain: str) -> dict:
    out = {"queried": True, "resolves": None, "rcode": None, "a": [], "aaaa": [], "cname": [], "nameservers": [], "mx_count": 0, "min_ttl": None,
           "resolves_to_private_ip": False, "fast_flux_suspected": False, "errors": [], "findings": []}
    try:
        ra = dns.query(host, "A")
        out["rcode"] = ra.rcode_name
        out["a"] = [{"address": r.data, "ttl": r.ttl} for r in ra.of_type("A")]
        out["cname"] = [r.data for r in ra.of_type("CNAME")]
        try:
            out["aaaa"] = [{"address": r.data, "ttl": r.ttl} for r in dns.query(host, "AAAA").of_type("AAAA")]
        except DnsError as e:
            out["errors"].append(f"AAAA: {e}")
        out["resolves"] = bool(out["a"] or out["aaaa"])
        if ra.rcode == 3:
            out["resolves"] = False
    except DnsError as e:
        out["errors"].append(f"A: {e}")
    for rtype, key in (("NS", "nameservers"), ("MX", "mx_count")):
        try:
            rr = dns.query(registered_domain, rtype).of_type(rtype)
            out[key] = sorted({r.data.lower() for r in rr}) if rtype == "NS" else len(rr)
        except DnsError as e:
            out["errors"].append(f"{rtype}: {e}")
    addrs = [r["address"] for r in out["a"] + out["aaaa"]]
    ttls = [r["ttl"] for r in out["a"] + out["aaaa"]]
    out["min_ttl"] = min(ttls) if ttls else None
    out["resolves_to_private_ip"] = any(not is_public_ip(a) for a in addrs)
    out["fast_flux_suspected"] = len(set(addrs)) >= FAST_FLUX_MIN_ADDRESSES and (out["min_ttl"] or 10**9) <= FAST_FLUX_MAX_TTL
    f = out["findings"]
    if out["resolves"] is False:
        f.append({"id": "dns_not_resolving", "severity": "medium", "detail": "Host does not resolve (NXDOMAIN or no address records)"})
    if out["resolves_to_private_ip"]:
        f.append({"id": "private_ip_resolution", "severity": "high", "detail": "Domain resolves to a private/internal address"})
    if out["fast_flux_suspected"]:
        f.append({"id": "fast_flux", "severity": "medium", "detail": f"{len(set(addrs))} addresses with TTL <= {FAST_FLUX_MAX_TTL}s"})
    if registered_domain and not out["nameservers"] and not out["errors"]:
        f.append({"id": "no_nameservers", "severity": "low", "detail": "No NS records found for the registered domain"})
    return out


def analyze_domain(host: str, registered_domain: str, *, is_ip: bool, dns=None, rdap=None) -> dict:
    if is_ip:
        return {"status": "skipped", "reason": "host_is_ip_address", "dns": None, "registration": None, "findings": []}
    res = {"status": "ok", "dns": None, "registration": None, "findings": []}
    if dns is not None:
        res["dns"] = analyze_dns(dns, host, registered_domain)
        res["findings"] += res["dns"]["findings"]
        if res["dns"]["resolves"] is None:
            res["status"] = "partial"
    else:
        res["status"] = "partial"
    if rdap is not None:
        res["registration"] = rdap.lookup(registered_domain)
        if not res["registration"].get("available"):
            res["status"] = "partial"  # age unknown: not an error, but results are less complete
    return res
