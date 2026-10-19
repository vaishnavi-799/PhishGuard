"""Typosquatting detection against a brand list using Levenshtein, Jaro-Winkler and n-gram similarity."""
from __future__ import annotations

import re

from .brands import Brand, load_brands
from .similarity import jaro_winkler, levenshtein, levenshtein_similarity, ngram_similarity

MIN_FUZZY_LEN = 4        # shorter brand labels (dhl, ups, sbi...) are only matched as whole tokens: fuzzy matching would be noise
MIN_COMBINED = 0.82      # combined similarity needed to report a "similar_name" match without a recognised technique
COMBO_WORDS = {"login", "signin", "secure", "security", "verify", "verification", "account", "accounts", "update", "support", "help", "service", "services", "billing", "payment", "pay", "wallet", "online", "official", "customer", "care", "portal", "mail", "web", "app", "alert", "confirm", "recover", "unlock", "id", "my", "india", "refund", "bonus"}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


def normalize_ascii_lookalikes(s: str) -> str:
    """Digit/ASCII look-alikes: paypa1 -> paypal, rnicrosoft -> microsoft, vvhatsapp -> whatsapp."""
    return s.translate(_LEET).replace("rn", "m").replace("vv", "w")


def combined_similarity(lev_sim: float, jw: float, ng: float) -> float:
    return 0.4 * lev_sim + 0.35 * jw + 0.25 * ng


def _edit_technique(brand: str, cand: str) -> str | None:
    """Classify a distance-1/2 variation of `brand`."""
    if len(cand) == len(brand):
        diff = [i for i in range(len(brand)) if brand[i] != cand[i]]
        if len(diff) == 2 and diff[1] == diff[0] + 1 and brand[diff[0]] == cand[diff[1]] and brand[diff[1]] == cand[diff[0]]:
            return "transposition"
        return "substitution" if len(diff) <= 2 else None
    if len(cand) == len(brand) - 1 and levenshtein(brand, cand) == 1:
        return "omission"
    if len(cand) == len(brand) + 1 and levenshtein(brand, cand) == 1:
        i = next((k for k in range(len(cand)) if k >= len(brand) or cand[k] != brand[k]), len(cand) - 1)
        return "repetition" if (i > 0 and cand[i] == cand[i - 1]) else "insertion"
    return None


def _tokens(label: str) -> list[str]:
    return [t for t in re.split(r"[-_.]+", label) if t]


def match_brand(label: str, tld: str, registered: str, brand: Brand) -> dict | None:
    if registered in brand.domains:
        return None  # the genuine domain
    best = None
    for bl in brand.labels:
        technique, token = None, label
        if label == bl:
            technique = "tld_swap"  # brand name on a TLD the brand does not use
        elif normalize_ascii_lookalikes(label) == bl:
            technique = "homoglyph_substitution"
        else:
            toks = _tokens(label)
            if bl in toks and len(toks) > 1:
                technique, token = "combosquatting", bl
            elif len(bl) >= MIN_FUZZY_LEN and len(label) > len(bl) and (label.startswith(bl) or label.endswith(bl)):
                rest = label[len(bl):] if label.startswith(bl) else label[:-len(bl)]
                if rest in COMBO_WORDS or len(rest) >= 3:
                    technique, token = "combosquatting", bl
        if technique is None and len(bl) >= MIN_FUZZY_LEN:
            max_d = 1 if len(bl) < 8 else 2
            for cand in [label] + [t for t in _tokens(label) if len(t) >= MIN_FUZZY_LEN and t != label]:
                d, tech = levenshtein(bl, cand), _edit_technique(bl, cand)
                if 0 < d <= max_d or tech == "transposition":  # a swap of two letters costs 2 plain edits but is one human typo
                    technique, token = tech or "similar_name", cand
                    break
        if technique is None and len(bl) >= MIN_FUZZY_LEN:
            if combined_similarity(levenshtein_similarity(bl, label), jaro_winkler(bl, label), ngram_similarity(bl, label)) >= MIN_COMBINED:
                technique = "similar_name"
        if technique is None:
            continue
        compared = bl if technique == "combosquatting" else (label if technique in ("homoglyph_substitution", "tld_swap", "similar_name") else token)
        lev, jw, ng = levenshtein_similarity(bl, compared), jaro_winkler(bl, compared), ngram_similarity(bl, compared)
        m = {"brand": brand.name, "brand_label": bl, "technique": technique, "matched_token": token, "distance": levenshtein(bl, compared),
             "levenshtein_similarity": round(lev, 4), "jaro_winkler": round(jw, 4), "ngram_similarity": round(ng, 4),
             "similarity": round(combined_similarity(lev, jw, ng), 4), "official_domains": sorted(brand.domains)[:3]}
        if best is None or m["similarity"] > best["similarity"]:
            best = m
    return best


def detect_typosquatting(registered_domain: str, domain_name: str, tld: str, brands=None, limit: int = 5) -> dict:
    matches = [m for b in (brands or load_brands()) if (m := match_brand(domain_name, tld, registered_domain, b))]
    matches.sort(key=lambda m: (-m["similarity"], m["brand"]))
    return {"candidate": domain_name, "registered_domain": registered_domain, "is_typosquat": bool(matches), "matches": matches[:limit], "best": matches[0] if matches else None}
