"""Domain registration data via RDAP (the public, JSON successor of WHOIS). Parsing is pure; fetching is injected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


def pick_server(bootstrap: dict, tld: str) -> str | None:
    tld = tld.lower().lstrip(".")
    for entry in bootstrap.get("services", []):
        if tld in [t.lower() for t in entry[0]] and entry[1]:
            https = [u for u in entry[1] if u.startswith("https://")]
            if https:
                return https[0] if https[0].endswith("/") else https[0] + "/"
    return None


def _dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _vcard_name(entity: dict) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "fn":
            return str(item[3])[:120]
    return None


def parse_rdap(doc: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    ev = {e.get("eventAction"): _dt(e.get("eventDate")) for e in doc.get("events", [])}
    reg, exp = ev.get("registration"), ev.get("expiration")
    registrar = None
    for ent in doc.get("entities", []):
        if "registrar" in ent.get("roles", []):
            registrar = _vcard_name(ent)
            break
    raw = json.dumps(doc).upper()
    return {
        "registered_at": reg.isoformat() if reg else None, "expires_at": exp.isoformat() if exp else None,
        "last_changed_at": (ev.get("last changed").isoformat() if ev.get("last changed") else None),
        "age_days": max(0, (now - reg).days) if reg else None, "registrar": registrar,
        "statuses": [str(s)[:60] for s in doc.get("status", [])][:8],
        "privacy_redacted": True if "REDACTED" in raw else (False if any("registrant" in e.get("roles", []) for e in doc.get("entities", [])) else None),
        "nameservers": sorted(n.get("ldhName", "").lower() for n in doc.get("nameservers", []) if n.get("ldhName")),
    }


class RdapClient:
    """fetch_json(url) -> dict | None   (use the SafeFetcher-backed function from the engine)."""

    def __init__(self, fetch_json, cache_ttl: float = 3600.0):
        self.fetch_json, self.ttl = fetch_json, cache_ttl
        self._bootstrap, self._bootstrap_at, self._cache = None, 0.0, {}

    def _server(self, tld: str):
        if self._bootstrap is None or time.monotonic() - self._bootstrap_at > 86400:
            self._bootstrap, self._bootstrap_at = self.fetch_json(BOOTSTRAP_URL), time.monotonic()
        return pick_server(self._bootstrap or {}, tld)

    def lookup(self, registered_domain: str) -> dict:
        hit = self._cache.get(registered_domain)
        if hit and time.monotonic() - hit[0] < self.ttl:
            return hit[1]
        tld = registered_domain.rsplit(".", 1)[-1]
        try:
            server = self._server(tld)
            if not server:
                out = {"available": False, "error": "no_rdap_server_for_tld"}
            else:
                doc = self.fetch_json(f"{server}domain/{registered_domain}")
                out = {"available": False, "error": "rdap_unavailable"} if not doc else {"available": True, **parse_rdap(doc), "source": "rdap"}
        except Exception:  # network/parse problems must never break the scan
            out = {"available": False, "error": "rdap_failed"}
        if out.get("available") or out.get("error") == "no_rdap_server_for_tld":
            self._cache[registered_domain] = (time.monotonic(), out)
        return out
