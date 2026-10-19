"""URL-derived features. Pure functions: no network access, deterministic."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from .schema import URL_FEATURES

NAN = float("nan")
MAX_URL_LENGTH = 2048


class InvalidUrlError(ValueError):
    """Raised for input that is not a parseable http(s) URL."""


# Heuristic lists. They are FEATURES, not rules: the model learns how much each one matters from labelled data.
KEYWORDS = ("login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "password", "wallet", "invoice", "billing", "suspend", "unlock", "authenticate", "recover")
BRANDS = ("paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook", "instagram", "whatsapp", "dhl", "fedex", "hdfc", "icici", "chase", "wellsfargo", "linkedin", "dropbox", "docusign", "office365", "outlook")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"}
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "cfd", "sbs", "icu", "buzz", "rest", "monster"}
EXEC_EXTENSIONS = (".exe", ".scr", ".zip", ".apk", ".msi", ".bat", ".js", ".jar", ".iso", ".docm", ".rar")
# Minimal multi-label public suffixes. For production-grade accuracy swap in the Public Suffix List (e.g. `tldextract`).
MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "com.cn", "co.nz", "co.za", "com.mx", "com.tr"}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"})


@dataclass(frozen=True)
class ParsedUrl:
    raw: str
    has_scheme: bool
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    netloc: str


def parse_url(raw) -> ParsedUrl:
    if raw is None or not isinstance(raw, str):
        raise InvalidUrlError("URL must be a string")
    s = raw.strip()
    if not s:
        raise InvalidUrlError("URL is empty")
    if len(s) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"URL is longer than {MAX_URL_LENGTH} characters")
    if re.search(r"\s", s):
        raise InvalidUrlError("URL must not contain whitespace")
    has_scheme = "://" in s
    if has_scheme:
        scheme = s.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise InvalidUrlError("Only http and https URLs are supported")
        full = s
    else:
        if re.match(r"^[a-z][a-z0-9+.-]*:(?!\d+(/|$|\?|#))", s, re.I):
            raise InvalidUrlError("Only http and https URLs are supported")
        scheme, full = "", "http://" + s
    try:
        parts = urlsplit(full)
        host, port = parts.hostname, parts.port
    except ValueError as e:
        raise InvalidUrlError(f"Malformed URL: {e}") from None
    if not host:
        raise InvalidUrlError("URL has no host")
    return ParsedUrl(s, has_scheme, scheme, host.rstrip("."), port, parts.path, parts.query, parts.netloc)


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]+", host))  # decimal / hex IP tricks


def split_host(host: str) -> tuple[list[str], str, str, str]:
    """-> (subdomain labels, domain name, public suffix, registered domain)"""
    if is_ip_host(host):
        return [], host, "", host
    labels = host.split(".")
    if len(labels) < 2:
        return [], host, "", host
    n = 2 if ".".join(labels[-2:]) in MULTI_SUFFIXES and len(labels) >= 3 else 1
    return labels[:-n - 1], labels[-n - 1], ".".join(labels[-n:]), ".".join(labels[-n - 1:])


def registered_domain(raw: str) -> str:
    return split_host(parse_url(raw).host)[3]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _ratio(a: float, b: float) -> float:
    return a / b if b else 0.0


def extract_url_features(raw: str) -> dict[str, float]:
    p = parse_url(raw)
    s, low = p.raw, p.raw.lower()
    host, path = p.host, p.path
    path_low = (path + "?" + p.query).lower()
    sub, name, suffix, _ = split_host(host)
    ip = is_ip_host(host)
    host_labels = host.split(".")
    host_letters = sum(c.isalpha() for c in host)
    host_n, name_n = host.translate(_LEET), name.translate(_LEET)
    kw_all = sum(k in low for k in KEYWORDS)
    last_seg = path.rsplit("/", 1)[-1].lower()
    f = {
        "url_length": len(s), "hostname_length": len(host), "path_length": len(path), "query_length": len(p.query),
        "num_dots": s.count("."), "num_hyphens": s.count("-"), "num_underscores": s.count("_"), "num_slashes": s.count("/"),
        "num_digits": sum(c.isdigit() for c in s), "num_at": s.count("@"), "num_question": s.count("?"),
        "num_ampersand": s.count("&"), "num_equals": s.count("="), "num_percent": s.count("%"),
        "digit_ratio": _ratio(sum(c.isdigit() for c in s), len(s)), "letter_ratio": _ratio(sum(c.isalpha() for c in s), len(s)),
        "subdomain_count": len(sub), "hostname_num_hyphens": host.count("-"),
        "hostname_digit_ratio": _ratio(sum(c.isdigit() for c in host), len(host)),
        "host_vowel_ratio": _ratio(sum(c in "aeiou" for c in host), host_letters),
        "domain_name_length": len(name), "longest_host_label": max(len(x) for x in host_labels),
        "is_https": NAN if not p.has_scheme else float(p.scheme == "https"),
        "has_port": float(p.port is not None and p.port not in (80, 443)),
        "has_at_symbol": float("@" in p.netloc), "is_ip_host": float(ip),
        "has_punycode": float(any(l.startswith("xn--") for l in host_labels)),
        "has_www": float(host.startswith("www.")),
        "is_shortener": float(host in SHORTENERS), "suspicious_tld": float(bool(suffix) and suffix.rsplit(".", 1)[-1] in RISKY_TLDS),
        "path_depth": len([x for x in path.split("/") if x]), "num_query_params": len(parse_qsl(p.query, keep_blank_values=True)),
        "num_encoded_chars": len(re.findall(r"%[0-9a-fA-F]{2}", s)), "has_double_slash_in_path": float("//" in path),
        "path_has_exec_extension": float(last_seg.endswith(EXEC_EXTENSIONS)),
        "url_entropy": entropy(low), "hostname_entropy": entropy(host), "path_entropy": entropy(path.lower()),
        "num_suspicious_keywords": kw_all,
        "keywords_in_hostname": sum(k in host for k in KEYWORDS), "keywords_in_path": sum(k in path_low for k in KEYWORDS),
        "brand_in_host_not_domain": float(any(b in host_n and name != b for b in BRANDS)),
        "brand_in_path_not_domain": float(any(b in path_low and name != b for b in BRANDS)),
        "brand_lookalike_domain": float(any(b in name_n and name != b for b in BRANDS)),
    }
    return {k: float(f[k]) for k in URL_FEATURES}  # fixed order; KeyError here = schema drift
