"""Explainable reputation indicators from local knowledge (no third-party API keys required)."""
from __future__ import annotations

from pathlib import Path

from .dns_wire import DnsError

FREE_HOSTING = {"blogspot.com", "weebly.com", "wixsite.com", "github.io", "pages.dev", "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "glitch.me", "herokuapp.com", "000webhostapp.com", "workers.dev", "onrender.com", "repl.co", "sites.google.com", "azurewebsites.net", "ngrok.io", "ngrok-free.app", "godaddysites.com", "myshopify.com"}
DYNAMIC_DNS = {"duckdns.org", "no-ip.com", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "serveo.net", "dyndns.org", "freeddns.org", "myftp.biz"}


def load_blocklist(path: str | None) -> set[str]:
    if not path or not Path(path).is_file():
        return set()
    return {l.strip().lower() for l in Path(path).read_text().splitlines() if l.strip() and not l.startswith("#")}


def _dnsbl(dns, registered_domain: str, zone: str) -> dict:
    prov = f"DNSBL:{zone}"
    try:
        r = dns.query(f"{registered_domain}.{zone}", "A")
    except DnsError:
        return {"provider": prov, "reputation": "Unknown", "is_known_malicious": False, "threat_category": None, "detail": "lookup failed"}
    codes = [a.data for a in r.of_type("A")]
    if not codes:
        return {"provider": prov, "reputation": "Clean", "is_known_malicious": False, "threat_category": None, "detail": None}
    if any(c.startswith("127.255.255.") for c in codes):  # list operators use these codes for "query refused / not authorised"
        return {"provider": prov, "reputation": "Unknown", "is_known_malicious": False, "threat_category": None, "detail": "query refused by list operator"}
    return {"provider": prov, "reputation": "Malicious", "is_known_malicious": True, "threat_category": "Listed domain", "detail": ",".join(codes)[:60]}


def assess_reputation(*, host: str, registered_domain: str, tld_risky: bool, is_shortener: bool, age_days: int | None, dns_resolves: bool | None,
                      blocklist: set[str] | frozenset = frozenset(), dns=None, dnsbl_zones=()) -> dict:
    ind = []

    def add(i, sev, d):
        ind.append({"id": i, "severity": sev, "detail": d})

    if age_days is not None:
        if age_days < 7:
            add("domain_very_new", "high", f"Domain registered {age_days} day(s) ago")
        elif age_days < 30:
            add("domain_new", "high", f"Domain registered {age_days} days ago")
        elif age_days < 90:
            add("domain_recent", "medium", f"Domain registered {age_days} days ago")
        elif age_days > 730:
            add("domain_established", "info", f"Domain registered {age_days // 365} year(s) ago")
    if tld_risky:
        add("risky_tld", "low", "High-abuse top-level domain")
    if registered_domain in FREE_HOSTING or any(host.endswith("." + h) for h in FREE_HOSTING):
        add("free_hosting", "medium", "Hosted on a free subdomain/hosting service often abused for phishing")
    if registered_domain in DYNAMIC_DNS:
        add("dynamic_dns", "medium", "Dynamic DNS provider")
    if is_shortener:
        add("url_shortener", "medium", "URL shortening service")
    if dns_resolves is False:
        add("no_dns_record", "medium", "Host does not resolve in DNS")
    providers = []
    hit = registered_domain in blocklist or host in blocklist
    if blocklist:
        providers.append({"provider": "LocalBlocklist", "reputation": "Malicious" if hit else "Clean", "is_known_malicious": hit, "threat_category": "Blocklisted" if hit else None, "detail": None})
        if hit:
            add("local_blocklist", "high", "Domain is on the local blocklist")
    for z in (dnsbl_zones if dns else ()):
        r = _dnsbl(dns, registered_domain, z)
        providers.append(r)
        if r["is_known_malicious"]:
            add("dnsbl_listed", "high", f"Listed on {z}")
    sev = [i["severity"] for i in ind]
    risky = [i for i in ind if i["severity"] in ("high", "medium", "low")]
    rating = "Poor" if "high" in sev else "Neutral" if risky else ("Good" if (age_days or 0) > 365 else "Unknown")
    providers.insert(0, {"provider": "LocalHeuristics", "reputation": "Suspicious" if "high" in sev or sev.count("medium") >= 2 else "Clean" if rating == "Good" else "Unknown",
                         "is_known_malicious": False, "threat_category": "Suspicious domain profile" if "high" in sev else None, "detail": f"{len(risky)} risk indicator(s)"})
    return {"rating": rating, "indicators": ind, "providers": providers}
