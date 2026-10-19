"""Transparent additive risk scoring. Every point of the score is traceable to a named factor.

The weights below are EXPERT HEURISTICS, not values learned from data or validated against a labelled dataset.
Tune them (and evaluate them) on your own data before relying on the score for decisions.
"""
from __future__ import annotations

POINTS = {
    # URL structure
    "ip_host": 18, "at_symbol": 15, "hex_ip": 15, "hex_encoding": 6, "encoded_host": 14, "double_encoding": 6, "heavy_url_encoding": 5, "suspicious_port": 8, "non_standard_port": 3,
    "excessive_hyphens": 6, "url_shortener": 10, "risky_tld": 6, "very_long_url": 8, "long_url": 4, "deep_subdomains": 7, "executable_path": 14, "double_slash_path": 2,
    "abnormal_path": 3, "random_looking_path": 3, "cms_path": 3, "redirect_parameter": 8, "abnormal_query": 3,
    # domain / DNS / reputation
    "domain_very_new": 25, "domain_new": 18, "domain_recent": 8, "free_hosting": 5, "dynamic_dns": 8, "dns_not_resolving": 8, "private_ip_resolution": 20, "fast_flux": 8,
    "no_nameservers": 3, "local_blocklist": 60, "dnsbl_listed": 40,
    # TLS
    "no_https": 8, "cert_expired": 20, "cert_not_yet_valid": 15, "hostname_mismatch": 20, "self_signed": 12, "untrusted_chain": 10, "cert_very_new": 4, "weak_tls": 4,
    "weak_signature": 4, "tls_unavailable": 8,
    # page content
    "login_form": 4, "external_form_action": 18, "insecure_form_submit": 6, "unusual_form_action": 8, "hidden_iframe": 12, "external_iframe": 2, "many_hidden_elements": 3,
    "suspicious_scripts": 12, "meta_refresh_redirect": 6, "javascript_redirect": 3, "right_click_blocked": 4, "long_redirect_chain": 6, "cross_domain_redirect": 8,
    "untrusted_tls": 5, "download_content": 20,
    # homograph
    "homograph_mixed_script": 20, "homograph_hidden_characters": 20, "homograph_whole_script": 25, "punycode_idn": 6,
}
KEYWORD_POINTS, KEYWORD_CAP = 3, 12
BRAND_FACTOR = 0.45          # brand impersonation score (0-100) x factor
STRONG_BRAND = 80            # impersonation score at/above which mitigations are not applied
HARD_EVIDENCE = {"local_blocklist", "dnsbl_listed", "download_content", "suspicious_scripts", "external_form_action"}
GROUP = {"url": "url", "domain": "domain", "tls": "tls", "website": "website", "brand": "brand", "homograph": "homograph", "reputation": "domain"}
ICONS = {"url": "🧱", "domain": "🌍", "tls": "🔒", "website": "📄", "brand": "🏷", "homograph": "🔤", "combo": "🚩", "blocklist": "🚫"}
LEVELS = [(20, "Very Low"), (40, "Low"), (60, "Medium"), (80, "High"), (101, "Critical")]


def level_of(score: int) -> str:
    return next(n for lim, n in LEVELS if score < lim)


def _sev(points: float) -> str:
    return "High" if points >= 15 else "Medium" if points >= 6 else "Low"


def compute_risk(parts: dict, ml: dict | None, ml_weight: float = 0.4) -> dict:
    """parts: {'url','domain','tls','website','typosquatting','homograph','brand','reputation'} module outputs."""
    factors: dict[str, dict] = {}

    def take(fid, group, pts, detail, icon=None):
        if pts > 0 and (fid not in factors or pts > factors[fid]["points"]):
            factors[fid] = {"id": fid, "group": group, "points": round(pts, 1), "severity": _sev(pts), "detail": detail, "icon": icon or ICONS.get(group, "⚠️")}

    for group, key in (("url", "url"), ("domain", "domain"), ("tls", "tls"), ("website", "website"), ("domain", "reputation")):
        mod = parts.get(key) or {}
        for f in (mod.get("findings") or mod.get("indicators") or []):
            if f["id"] == "suspicious_keywords":
                n = len((parts["url"] or {}).get("suspicious_keywords", []))
                take("suspicious_keywords", "url", min(KEYWORD_CAP, KEYWORD_POINTS * n), f["detail"])
            elif f["id"] in POINTS:
                take(f["id"], group, POINTS[f["id"]], f["detail"], ICONS["blocklist"] if f["id"] in ("local_blocklist", "dnsbl_listed") else None)
    h = parts.get("homograph") or {}
    if h.get("mixed_script_labels"):
        take("homograph_mixed_script", "homograph", POINTS["homograph_mixed_script"], "Label mixes scripts (e.g. Latin + Cyrillic)")
    if h.get("hidden_characters"):
        take("homograph_hidden_characters", "homograph", POINTS["homograph_hidden_characters"], "Invisible or bidirectional control characters in the host")
    if h.get("whole_script_confusable"):
        take("homograph_whole_script", "homograph", POINTS["homograph_whole_script"], "Whole label uses non-Latin look-alike letters")
    if h.get("is_idn") and not h.get("is_suspicious"):
        take("punycode_idn", "homograph", POINTS["punycode_idn"], "Internationalised (IDN/punycode) domain")
    brand = parts.get("brand") or {}
    top = (brand.get("targets") or [None])[0]
    if top:
        take("brand_impersonation", "brand", top["score"] * BRAND_FACTOR, f"Possible impersonation of {top['brand']} (" + ", ".join(s["id"] for s in top["signals"][:3]) + ")")
    web = parts.get("website") or {}
    if (web.get("forms") or {}).get("login_form") and (top and top["score"] >= 50 or (parts.get("domain") or {}).get("findings") and any(f["id"] in ("dns_not_resolving",) for f in parts["domain"]["findings"]) or "domain_very_new" in factors or "domain_new" in factors or "external_form_action" in factors):
        take("credential_harvest_pattern", "combo", 10, "Password form combined with other phishing indicators")

    mitig = []
    age = ((parts.get("domain") or {}).get("registration") or {}).get("age_days")
    if isinstance(age, int) and age > 730:
        mitig.append({"id": "domain_established", "points": -12, "detail": f"Domain is {age // 365} years old"})
    elif isinstance(age, int) and age > 365:
        mitig.append({"id": "domain_over_1y", "points": -6, "detail": "Domain is more than a year old"})
    tls = parts.get("tls") or {}
    if tls.get("certificate_valid") and tls.get("chain_trusted"):
        mitig.append({"id": "valid_tls", "points": -3, "detail": "Valid, trusted TLS certificate"})
    verified = brand.get("verified_brand_domain")
    # Age / TLS only lower suspicion of *unknown* intent. They never excuse a blocklist/DNSBL hit or a strong brand impersonation.
    if {"local_blocklist", "dnsbl_listed"} & set(factors) or (top and top["score"] >= STRONG_BRAND):
        mitig = []
    pos = sum(f["points"] for f in factors.values())
    heur = pos + sum(m["points"] for m in mitig)
    hard = sorted(set(factors) & HARD_EVIDENCE)
    if verified and not (set(factors) & {"local_blocklist", "dnsbl_listed"}):
        heur = min(heur, 10)
        mitig.append({"id": "verified_brand_domain", "points": 0, "detail": f"Registered domain officially belongs to {verified}"})
    heuristic = int(round(max(0, min(100, heur))))
    method, final = "heuristic", heuristic
    if ml and ml.get("probability") is not None:
        blended = int(round((1 - ml_weight) * heuristic + ml_weight * ml["probability"] * 100))
        method, final = "blended", max(blended, heuristic) if {"local_blocklist", "dnsbl_listed"} & set(factors) else blended
    final = max(0, min(100, final))
    lvl = level_of(final)
    ordered = sorted(factors.values(), key=lambda f: -f["points"])
    if top and top["score"] >= 50:
        category = "Brand Impersonation"
    elif "external_form_action" in factors or ("login_form" in factors and final >= 40):
        category = "Credential Phishing"
    elif {"download_content", "executable_path"} & set(factors):
        category = "Malware Delivery"
    else:
        category = "Legitimate" if final < 40 else "Suspicious Site"
    summary = {"Very Low": "No significant phishing indicators were found.", "Low": "Minor anomalies were found; normal caution applies.", "Medium": "Several suspicious signals were found; verify before proceeding.",
               "High": "Strong phishing characteristics were detected.", "Critical": "Multiple severe phishing indicators were detected."}[lvl]
    return {"score": final, "level": lvl, "category": category, "method": method, "heuristic_score": heuristic, "ml_weight": ml_weight if method == "blended" else 0.0, "summary": summary,
            "factors": ordered, "mitigating_factors": mitig, "hard_evidence": hard,
            "indicators": [{"icon": f["icon"], "text": f["detail"], "detail": f["id"].replace("_", " "), "sev": f["severity"]} for f in ordered[:8]]}


def recommendations(risk: dict) -> list[dict]:
    ids, lvl = {f["id"] for f in risk["factors"]}, risk["level"]
    rec = []
    add = lambda icon, title, desc, pr: rec.append({"icon": icon, "title": title, "description": desc, "priority": pr, "sort_order": len(rec)})
    if lvl in ("High", "Critical"):
        add("🚫", "Do not enter credentials", "Never submit passwords, one-time codes or card data on this site.", "High")
        add("📥", "Do not download files", "Avoid any automatic or prompted downloads from this domain.", "High")
        add("⛔", "Block the URL", "Add the domain to your email and web gateway blocklists.", "High")
        add("📣", "Report the website", "Submit to your IT/security team and to phishing report services.", "Medium")
    elif lvl == "Medium":
        add("⚠️", "Proceed with caution", "Avoid entering sensitive information until the site is verified.", "Medium")
        add("✉️", "Verify the sender", "Confirm the link through a trusted channel before using it.", "Medium")
    else:
        add("✅", "No action required", "No significant risk indicators were found.", "Low")
    if ids & {"brand_impersonation"}:
        add("🔎", "Verify the domain", "Open the real service by typing its address manually instead of using this link.", "High" if lvl in ("High", "Critical") else "Medium")
    if ids & {"homograph_mixed_script", "homograph_whole_script", "homograph_hidden_characters"}:
        add("🔤", "Check for look-alike characters", "The domain contains characters that imitate Latin letters.", "High")
    if ids & {"domain_very_new", "domain_new"}:
        add("📅", "Be wary of brand-new domains", "Phishing sites are frequently registered days before use.", "Medium")
    if lvl in ("Low", "Very Low"):
        add("🧩", "Keep your browser updated", "Updates add Safe Browsing improvements.", "Low")
    return rec
