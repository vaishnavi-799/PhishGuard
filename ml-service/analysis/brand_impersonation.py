"""Combines typosquatting, homograph and page-content signals into a per-brand impersonation assessment."""
from __future__ import annotations

import re

from .brands import official_brand, load_brands
from .similarity import jaro_winkler, levenshtein_similarity, ngram_similarity
from .typosquatting import combined_similarity, normalize_ascii_lookalikes

# Weight (0-100) each kind of evidence carries. Heuristic and tunable: not learned from data.
WEIGHTS = {"homograph": 90, "typosquat:homoglyph_substitution": 85, "typosquat:substitution": 80, "typosquat:omission": 80, "typosquat:insertion": 80, "typosquat:repetition": 80,
           "typosquat:transposition": 80, "typosquat:combosquatting": 70, "typosquat:tld_swap": 60, "typosquat:similar_name": 55,
           "brand_in_subdomain": 65, "brand_in_path": 30, "brand_in_page_title": 45, "brand_login_form": 25}


def _word(text: str, needle: str) -> bool:
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", text))


def assess_brand_impersonation(*, registered_domain: str, domain_name: str, subdomains: list[str], path: str, typo: dict, homograph: dict, website: dict | None, brands=None) -> dict:
    brands = brands or load_brands()
    owner = official_brand(registered_domain, brands)
    if owner:
        return {"is_impersonation_suspected": False, "score": 0, "verified_brand_domain": owner.name, "targets": []}
    sig: dict[str, dict] = {}

    def add(brand, sid, detail):
        t = sig.setdefault(brand.name, {"brand": brand.name, "sector": brand.sector, "signals": [], "metrics": None, "_b": brand})
        if all(s["id"] != sid for s in t["signals"]):
            t["signals"].append({"id": sid, "weight": WEIGHTS[sid], "detail": detail})

    by_name = {b.name: b for b in brands}
    for m in typo.get("matches", []):
        b = by_name[m["brand"]]
        add(b, f"typosquat:{m['technique']}", f"'{domain_name}' is a {m['technique'].replace('_', ' ')} of '{m['brand_label']}'")
        sig[b.name]["metrics"] = {k: m[k] for k in ("levenshtein_similarity", "jaro_winkler", "ngram_similarity", "similarity", "technique")}
    for m in homograph.get("brand_matches", []):
        add(by_name[m["brand"]], "homograph", f"Look-alike characters spell '{m['brand_label']}'")
    sub_tokens = {t for s in subdomains for t in re.split(r"[-_.]+", normalize_ascii_lookalikes(s))}
    path_low = path.lower()
    page_text = ""
    if website and website.get("status") == "ok" and website.get("fetched"):
        page_text = " ".join(filter(None, [website.get("title"), website.get("site_name")] + (website.get("headings") or []))).lower()
    login = bool(website and website.get("forms", {}).get("login_form"))
    for b in brands:
        for lab in b.labels:
            if len(lab) >= 3 and lab in sub_tokens:
                add(b, "brand_in_subdomain", f"'{lab}' appears in a subdomain of an unrelated domain")
            if len(lab) >= 4 and lab in path_low:
                add(b, "brand_in_path", f"'{lab}' appears in the URL path")
        if page_text and (_word(page_text, b.name.lower()) or any(len(l) >= 4 and _word(page_text, l) for l in b.labels)):
            add(b, "brand_in_page_title", f"Page title/headings mention {b.name} but the domain is not {b.name}'s")
            if login:
                add(b, "brand_login_form", f"A password form is shown on a page presenting itself as {b.name}")
    targets = []
    for name, t in sig.items():
        w = sorted((s["weight"] for s in t["signals"]), reverse=True)
        t["score"] = min(100, int(round(w[0] + 0.25 * sum(w[1:]))))
        if t["metrics"] is None:
            lab = t["_b"].labels[0]
            lev, jw, ng = levenshtein_similarity(lab, domain_name), jaro_winkler(lab, domain_name), ngram_similarity(lab, domain_name)
            t["metrics"] = {"levenshtein_similarity": round(lev, 4), "jaro_winkler": round(jw, 4), "ngram_similarity": round(ng, 4), "similarity": round(combined_similarity(lev, jw, ng), 4), "technique": None}
        t["official_domains"] = sorted(t["_b"].domains)[:3]
        del t["_b"]
        targets.append(t)
    targets.sort(key=lambda t: (-t["score"], t["brand"]))
    top = targets[0]["score"] if targets else 0
    return {"is_impersonation_suspected": top >= 50, "score": top, "verified_brand_domain": None, "targets": targets[:5]}
