"""Orchestrates every analysis module and returns one normalized report (see analysis/schema.py)."""
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
from dataclasses import dataclass
from datetime import datetime, timezone

from features.url_features import InvalidUrlError, is_ip_host, parse_url, split_host

from .brand_impersonation import assess_brand_impersonation
from .config import AnalysisConfig
from .dns_client import DnsClient
from .domain_analysis import analyze_dns
from .homograph import analyze_homograph
from .http_fetch import SafeFetcher
from .netsafe import resolve_public
from .rdap import RdapClient
from .reputation import assess_reputation, load_blocklist
from .risk import compute_risk, recommendations
from .schema import SCHEMA_VERSION
from .tls_analysis import analyze_tls
from .typosquatting import detect_typosquatting
from .url_analysis import analyze_url
from .website_analysis import analyze_website

ENGINE_VERSION = "1.0.0"
log = logging.getLogger("analysis.engine")


@dataclass
class Services:
    dns: object | None = None        # .query(name, type) -> DnsResponse
    fetcher: object | None = None    # .fetch(url, ...) -> FetchResult
    rdap: object | None = None       # .lookup(registered_domain) -> dict
    tls: object | None = None        # callable(scheme, host, port) -> dict


def build_services(cfg: AnalysisConfig) -> Services:
    fetcher = SafeFetcher(cfg)

    def fetch_json(url: str):
        fr = fetcher.fetch(url, accept="application/json", max_bytes=500_000)
        return json.loads(fr.body) if fr.status == 200 and fr.body else None

    return Services(dns=DnsClient(cfg.dns_resolvers or None, cfg.dns_timeout), fetcher=fetcher,
                    rdap=RdapClient(fetch_json) if cfg.rdap_enabled else None,
                    tls=lambda scheme, host, port: analyze_tls(scheme, host, port, cfg=cfg, resolver=resolve_public))


def _mod(status: str, ms: int = 0, **extra) -> dict:
    return {"status": status, "duration_ms": ms, **{k: v for k, v in extra.items() if v is not None}}


class AnalysisEngine:
    def __init__(self, cfg: AnalysisConfig | None = None, services: Services | None = None, predictor=None):
        self.cfg = cfg or AnalysisConfig()
        self.services = services or build_services(self.cfg)
        self.predictor = predictor  # callable(url, security_features) -> dict | None
        self.blocklist = load_blocklist(self.cfg.blocklist_path)

    # ------------------------------------------------------------------ helpers
    def _timed(self, fn):
        t = time.monotonic()
        try:
            return fn(), None, int((time.monotonic() - t) * 1000)
        except Exception as e:  # a failing module must never take the whole analysis down
            log.warning("module failed: %s: %s", type(e).__name__, e)
            return None, type(e).__name__, int((time.monotonic() - t) * 1000)

    def analyze(self, url: str, *, inspect_website: bool = True, include_ml: bool = True) -> dict:
        cfg, sv = self.cfg, self.services
        t0 = time.monotonic()
        deadline = t0 + cfg.total_timeout
        p = parse_url(url)  # raises InvalidUrlError: the caller turns that into a 4xx
        host = p.host
        sub, name, suffix, registered = split_host(host)
        ip, tld = is_ip_host(host), (suffix.rsplit(".", 1)[-1] if suffix else "")
        modules: dict = {}
        log.info("analyze host=%s", host)  # never log the full URL (may contain tokens)

        ua, err, ms = self._timed(lambda: analyze_url(url, p))
        modules["url"] = _mod("ok" if ua else "failed", ms, error=err)
        ua = ua or {"findings": [], "suspicious_keywords": [], "is_shortener": False, "suspicious_tld": False}
        hg, err, ms = self._timed(lambda: analyze_homograph(host))
        modules["homograph"] = _mod("ok" if hg else "failed", ms, error=err)
        hg = hg or {"is_idn": False, "is_suspicious": False, "brand_matches": [], "mixed_script_labels": [], "hidden_characters": []}
        typo, err, ms = self._timed(lambda: detect_typosquatting(registered, name, tld) if not ip else {"candidate": host, "registered_domain": registered, "is_typosquat": False, "matches": [], "best": None})
        modules["typosquatting"] = _mod("ok" if typo else "failed", ms, error=err)
        typo = typo or {"candidate": name, "registered_domain": registered, "is_typosquat": False, "matches": [], "best": None}

        # ---- network modules, concurrently, under one wall-clock budget
        net = cfg.enable_network
        scheme_for_tls = p.scheme or "https"
        futs, ex = {}, ThreadPoolExecutor(max_workers=4, thread_name_prefix="analysis")
        try:
            if net and not ip and sv.dns is not None:
                futs["dns"] = ex.submit(self._timed, lambda: analyze_dns(sv.dns, host, registered))
            if net and not ip and sv.rdap is not None:
                futs["rdap"] = ex.submit(self._timed, lambda: sv.rdap.lookup(registered))
            if sv.tls is not None and (scheme_for_tls == "http" or net):
                futs["tls"] = ex.submit(self._timed, lambda: sv.tls(scheme_for_tls, host, p.port))
            if net and inspect_website and sv.fetcher is not None:
                futs["site"] = ex.submit(self._timed, lambda: self._fetch(p, deadline))
            res = {}
            for k, f in futs.items():
                try:
                    res[k] = f.result(timeout=max(0.1, deadline - time.monotonic()))
                except FutTimeout:
                    res[k] = (None, "timeout", int(cfg.total_timeout * 1000))
        finally:
            ex.shutdown(wait=False, cancel_futures=True)  # sockets carry their own timeouts, so stragglers die on their own

        def got(k):
            return res[k] if k in res else (None, None, 0)

        dns_res, e1, m1 = got("dns")
        reg_res, e2, m2 = got("rdap")
        if ip:
            domain, dstat = {"dns": None, "registration": None, "findings": [], "status": "skipped", "reason": "host_is_ip_address"}, "skipped"
        elif not net:
            domain, dstat = {"dns": None, "registration": None, "findings": [], "status": "skipped", "reason": "network_disabled"}, "skipped"
        else:
            reg = reg_res if reg_res is not None else ({"available": False, "error": e2 or "not_configured"} if sv.rdap is not None else {"available": False, "error": "rdap_disabled"})
            dstat = "failed" if dns_res is None and not reg.get("available") else ("ok" if (dns_res and dns_res["resolves"] is not None and reg.get("available")) else "partial")
            domain = {"status": dstat, "dns": dns_res, "registration": reg, "findings": list((dns_res or {}).get("findings", []))}
        modules["domain"] = _mod(dstat, max(m1, m2), error=e1 or e2 if dstat == "failed" else None, reason=domain.get("reason"))

        tls_res, e, ms = got("tls")
        if tls_res is None:
            tls_res = {"status": "skipped" if not e else "failed", "https": None, "certificate_valid": None, "hostname_match": None, "issuer": None, "expires_at": None, "findings": [], **({"error": e} if e else {"reason": "network_disabled"})}
        modules["tls"] = _mod(tls_res["status"], ms, error=tls_res.get("error"), reason=tls_res.get("reason"))

        site_fr, e, ms = got("site")
        website, werr = (analyze_website(site_fr, registered), e) if "site" in res and e is None else ({"status": "failed" if e else "skipped", "fetched": False, "findings": [], **({"error": e} if e else {"reason": "not_requested" if net else "network_disabled"})}, e)
        modules["website"] = _mod(website["status"], ms, error=website.get("error"), reason=website.get("reason"))

        age = ((domain.get("registration") or {}).get("age_days"))
        rep, err, ms = self._timed(lambda: assess_reputation(host=host, registered_domain=registered, tld_risky=bool(ua.get("suspicious_tld")), is_shortener=bool(ua.get("is_shortener")),
                                                              age_days=age, dns_resolves=(dns_res or {}).get("resolves") if dns_res else None, blocklist=self.blocklist,
                                                              dns=sv.dns if net and sv.dns else None, dnsbl_zones=cfg.dnsbl_zones if net else ()))
        modules["reputation"] = _mod("ok" if rep else "failed", ms, error=err)
        rep = rep or {"rating": "Unknown", "indicators": [], "providers": []}

        brand, err, ms = self._timed(lambda: assess_brand_impersonation(registered_domain=registered, domain_name=name, subdomains=sub, path=p.path, typo=typo, homograph=hg, website=website))
        modules["brand"] = _mod("ok" if brand else "failed", ms, error=err)
        brand = brand or {"is_impersonation_suspected": False, "score": 0, "verified_brand_domain": None, "targets": []}

        sec = self._security_features(domain, tls_res, website, rep)
        ml = None
        if not include_ml:
            modules["ml"] = _mod("skipped", reason="not_requested")
        elif self.predictor is None:
            modules["ml"] = _mod("skipped", reason="no_model")
        else:
            ml, err, ms = self._timed(lambda: self.predictor(url, {k: v for k, v in sec.items() if v is not None}))
            modules["ml"] = _mod("ok" if ml else "failed", ms, error=err)

        parts = {"url": ua, "domain": domain, "tls": tls_res, "website": website, "homograph": hg, "brand": brand, "reputation": rep}
        risk = compute_risk(parts, ml, cfg.ml_weight)
        return {
            "schema_version": SCHEMA_VERSION, "engine_version": ENGINE_VERSION, "analyzed_at": datetime.now(timezone.utc).isoformat(), "duration_ms": int((time.monotonic() - t0) * 1000),
            "url": {"input": url[:2048], "scheme": p.scheme or None, "host": host, "unicode_host": hg.get("unicode_host", host), "registered_domain": registered, "tld": tld, "port": p.port,
                    "path": p.path[:500], "query": p.query[:500], "is_ip": ip},
            "modules": modules, "url_analysis": ua, "domain_analysis": domain, "tls_analysis": tls_res, "website_analysis": website, "typosquatting": typo, "homograph": hg,
            "brand_impersonation": brand, "threat_intelligence": rep["providers"], "reputation": {"rating": rep["rating"], "indicators": rep["indicators"]},
            "ml": ml, "risk": risk, "recommendations": recommendations(risk), "security_features": sec,
        }

    def _fetch(self, p, deadline):
        fetcher = self.services.fetcher
        if p.has_scheme:
            return fetcher.fetch(p.raw, deadline=deadline)
        fr = fetcher.fetch("https://" + p.raw, deadline=deadline)  # scheme-less input: prefer https, fall back to http
        if fr.status is None and not fr.blocked:
            fr = fetcher.fetch("http://" + p.raw, deadline=deadline)
        return fr

    @staticmethod
    def _security_features(domain: dict, tls: dict, web: dict, rep: dict) -> dict:
        dns, reg = domain.get("dns") or {}, domain.get("registration") or {}
        forms, ifr = web.get("forms") or {}, web.get("iframes") or {}
        fetched = web.get("fetched")
        b = lambda v: None if v is None else float(bool(v))
        return {
            "domain_age_days": reg.get("age_days"), "whois_privacy": b(reg.get("privacy_redacted")), "dns_resolves": b(dns.get("resolves")), "nameserver_count": len(dns["nameservers"]) if dns.get("nameservers") else None,
            "tls_valid": b(tls.get("certificate_valid")), "tls_cert_age_days": tls.get("age_days"), "tls_hostname_match": b(tls.get("hostname_match")),
            "redirect_count": (web.get("redirects") or {}).get("count") if fetched else None,
            "has_login_form": b(forms.get("login_form")) if fetched and web.get("title") is not None or forms else None, "has_password_field": b((web.get("password_fields") or 0) > 0) if "password_fields" in web else None,
            "external_form_action": b(forms.get("external_action")) if forms else None, "iframe_count": ifr.get("count"), "hidden_element_count": (web.get("hidden_elements") or {}).get("total"),
            "has_suspicious_scripts": b((web.get("scripts") or {}).get("is_suspicious")) if "scripts" in web else None,
            "threat_feed_hits": sum(1 for p in rep["providers"] if p.get("is_known_malicious")) if rep["providers"] else None,
        }
