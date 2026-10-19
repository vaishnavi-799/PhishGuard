"""Structured lexical analysis of a URL. Pure and offline: no network access."""
from __future__ import annotations

import math
import re
from urllib.parse import parse_qsl, unquote

from features.url_features import (EXEC_EXTENSIONS, KEYWORDS, RISKY_TLDS, SHORTENERS, ParsedUrl, entropy, is_ip_host, parse_url, split_host)

SHORTENER_DOMAINS = SHORTENERS | {"bitly.com", "lnkd.in", "fb.me", "amzn.to", "youtu.be", "s.id", "v.gd", "qr.ae", "tr.im", "x.co", "adf.ly", "bl.ink", "short.io", "t.ly", "rb.gy", "is.gd", "soo.gd", "clck.ru"}
COMMON_WEB_PORTS = {80, 443, 8080, 8443, 8000, 3000}
HIGH_RISK_PORTS = {21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 4444, 5432, 5900, 6667, 31337}
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redir", "next", "return", "returnurl", "goto", "dest", "destination", "continue", "target", "rurl", "link", "u", "r"}
SPECIAL_CHARS = "@!$%^*()+~|;,<>[]{}\\'\""
THRESHOLDS = {"long_url": 100, "very_long_url": 200, "deep_subdomains": 3, "host_hyphens": 3, "many_encoded": 5, "deep_path": 6, "long_path": 100, "long_query": 150, "high_entropy_path": 4.2}
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _ip_format(host: str) -> str | None:
    if not is_ip_host(host):
        return None
    if re.fullmatch(r"0x[0-9a-f]+", host):
        return "hexadecimal"
    if re.fullmatch(r"\d{8,10}", host):
        return "decimal"
    if ":" in host:
        return "ipv6"
    if any(len(p) > 1 and p.startswith("0") for p in host.split(".")):
        return "octal"
    return "dotted_quad"


def analyze_url(raw: str, parsed: ParsedUrl | None = None) -> dict:
    p = parsed or parse_url(raw)
    s, host, path, query = p.raw, p.host, p.path, p.query
    sub, name, suffix, registered = split_host(host)
    ip_fmt = _ip_format(host)
    tld = suffix.rsplit(".", 1)[-1] if suffix else ""
    special = {c: s.count(c) for c in SPECIAL_CHARS if c in s}
    encoded = re.findall(r"%[0-9a-fA-F]{2}", s)
    host_encoded = bool(re.search(r"%[0-9a-fA-F]{2}", p.netloc))
    hex_seqs = re.findall(r"(?:\\x[0-9a-fA-F]{2}|&#x[0-9a-fA-F]+;|\b0x[0-9a-fA-F]{2,})", s)
    kw = [k for k in KEYWORDS if k in s.lower()]
    params = parse_qsl(query, keep_blank_values=True)
    redirect_params = [k for k, v in params if k.lower() in REDIRECT_PARAMS and re.match(r"^(https?:)?//|^https?%3a", unquote(v), re.I) or (k.lower() in REDIRECT_PARAMS and re.match(r"^https?%3a", v, re.I))]
    b64_values = [k for k, v in params if len(v) >= 40 and re.fullmatch(r"[A-Za-z0-9+/_=-]+", v)]
    segments = [x for x in path.split("/") if x]
    last = segments[-1].lower() if segments else ""
    port = p.port
    data = {
        "length": len(s), "hostname_length": len(host), "num_dots": s.count("."), "hostname_dots": host.count("."),
        "subdomain_count": len(sub), "subdomains": sub, "registered_domain": registered, "tld": tld,
        "special_char_count": sum(special.values()), "special_chars": special,
        "has_at_symbol": "@" in p.netloc, "at_symbol_count": s.count("@"),
        "is_ip_host": bool(ip_fmt), "ip_format": ip_fmt,
        "port": port, "non_standard_port": port is not None and port not in (80, 443),
        "suspicious_port": port is not None and (port in HIGH_RISK_PORTS or port not in COMMON_WEB_PORTS),
        "url_encoding": {"encoded_char_count": len(encoded), "in_host": host_encoded, "double_encoded": bool(re.search(r"%25[0-9a-fA-F]{2}", s))},
        "hex_encoding": {"hex_sequences": len(hex_seqs), "hex_ip_host": ip_fmt == "hexadecimal", "samples": hex_seqs[:3]},
        "hyphen_count": s.count("-"), "hostname_hyphen_count": host.count("-"),
        "excessive_hyphens": host.count("-") >= THRESHOLDS["host_hyphens"],
        "suspicious_keywords": kw, "is_shortener": host in SHORTENER_DOMAINS or registered in SHORTENER_DOMAINS,
        "suspicious_tld": tld in RISKY_TLDS, "uses_https": None if not p.has_scheme else p.scheme == "https",
        "path": {"length": len(path), "depth": len(segments), "has_double_slash": "//" in path, "executable_extension": last.endswith(EXEC_EXTENSIONS),
                 "entropy": round(entropy(path.lower()), 3), "looks_like_cms_probe": bool(re.search(r"/(wp-admin|wp-content|wp-includes|administrator|cgi-bin)/", path.lower()))},
        "query": {"length": len(query), "param_count": len(params), "redirect_params": sorted(set(redirect_params)), "has_base64_like_value": bool(b64_values), "long_values": sum(len(v) > 100 for _, v in params)},
    }
    data["findings"] = _findings(data)
    return data


def _f(findings, fid, sev, detail):
    findings.append({"id": fid, "severity": sev, "detail": detail})


def _findings(d: dict) -> list[dict]:
    t, out = THRESHOLDS, []
    if d["is_ip_host"]:
        _f(out, "ip_host", "high", f"Host is an IP address ({d['ip_format']}) instead of a domain name")
    if d["has_at_symbol"]:
        _f(out, "at_symbol", "high", "'@' in the authority part: everything before it is ignored by browsers and can disguise the real host")
    if d["hex_encoding"]["hex_ip_host"]:
        _f(out, "hex_ip", "high", "Host is written as a hexadecimal number")
    elif d["hex_encoding"]["hex_sequences"]:
        _f(out, "hex_encoding", "medium", f"{d['hex_encoding']['hex_sequences']} hexadecimal escape sequence(s)")
    enc = d["url_encoding"]
    if enc["in_host"]:
        _f(out, "encoded_host", "high", "Percent-encoding inside the host name")
    elif enc["double_encoded"]:
        _f(out, "double_encoding", "medium", "Double URL-encoding detected")
    elif enc["encoded_char_count"] >= t["many_encoded"]:
        _f(out, "heavy_url_encoding", "medium", f"{enc['encoded_char_count']} percent-encoded characters")
    if d["suspicious_port"]:
        _f(out, "suspicious_port", "medium", f"Unusual port {d['port']}")
    elif d["non_standard_port"]:
        _f(out, "non_standard_port", "low", f"Non-standard port {d['port']}")
    if d["excessive_hyphens"]:
        _f(out, "excessive_hyphens", "medium", f"{d['hostname_hyphen_count']} hyphens in the host name")
    if d["suspicious_keywords"]:
        _f(out, "suspicious_keywords", "medium" if len(d["suspicious_keywords"]) >= 2 else "low", "Keywords: " + ", ".join(d["suspicious_keywords"]))
    if d["is_shortener"]:
        _f(out, "url_shortener", "medium", "Known URL-shortening service hides the final destination")
    if d["suspicious_tld"]:
        _f(out, "risky_tld", "low", f"Top-level domain .{d['tld']} is heavily abused")
    if d["length"] > t["very_long_url"]:
        _f(out, "very_long_url", "medium", f"URL is {d['length']} characters long")
    elif d["length"] > t["long_url"]:
        _f(out, "long_url", "low", f"URL is {d['length']} characters long")
    if d["subdomain_count"] >= t["deep_subdomains"]:
        _f(out, "deep_subdomains", "medium", f"{d['subdomain_count']} subdomain levels")
    p, q = d["path"], d["query"]
    if p["executable_extension"]:
        _f(out, "executable_path", "high", "Path points to an executable/archive file")
    if p["has_double_slash"]:
        _f(out, "double_slash_path", "low", "'//' inside the path")
    if p["depth"] >= t["deep_path"] or p["length"] > t["long_path"]:
        _f(out, "abnormal_path", "low", f"Unusually deep/long path (depth {p['depth']}, {p['length']} chars)")
    if p["entropy"] > t["high_entropy_path"] and p["length"] > 30:
        _f(out, "random_looking_path", "low", "Path looks randomly generated")
    if p["looks_like_cms_probe"]:
        _f(out, "cms_path", "low", "Path inside a CMS directory (common on compromised sites)")
    if q["redirect_params"]:
        _f(out, "redirect_parameter", "medium", "Query parameter(s) carry another URL: " + ", ".join(q["redirect_params"]))
    if q["has_base64_like_value"] or q["length"] > t["long_query"]:
        _f(out, "abnormal_query", "low", "Long or encoded-looking query string")
    return sorted(out, key=lambda x: -_SEV_ORDER[x["severity"]])
