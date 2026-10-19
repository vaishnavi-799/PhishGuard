"""Generates a SYNTHETIC dataset to verify the pipeline. It is NOT real phishing data.

Both classes are produced from hand-written templates, so a model trained on it learns those templates.
Metrics obtained on this file say nothing about real-world accuracy.
Usage: python -m training.generate_sample_data --rows 3000 --out data/sample/synthetic_urls.csv
"""
from __future__ import annotations

import argparse
import random
from pathlib import Path

import numpy as np
import pandas as pd

LEGIT_SITES = ["github.com", "wikipedia.org", "python.org", "stackoverflow.com", "mozilla.org", "nytimes.com", "bbc.co.uk", "amazon.com", "paypal.com", "microsoft.com", "apple.com", "google.com", "linkedin.com", "dropbox.com", "netflix.com", "nasa.gov", "medium.com", "reddit.com", "imdb.com", "bankofamerica.com"]
WORDS = ["green", "blue", "river", "stone", "bright", "north", "quick", "maple", "urban", "pixel", "garden", "studio", "market", "cloud", "daily", "craft", "solar", "bakery", "fitness", "travel", "books", "design", "coffee", "energy", "legal", "dental"]
LEGIT_PATHS = ["", "/", "/about", "/products/item-123", "/blog/2024/how-to-get-started", "/contact", "/docs/api/v2/reference", "/search?q=best+laptops&page=2", "/news/world/article-48213", "/login", "/account/settings", "/help/faq"]
BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook", "dhl", "hdfc", "chase", "linkedin", "dropbox", "docusign", "outlook"]
KEYS = ["secure", "login", "verify", "update", "account", "confirm", "signin", "billing", "support", "unlock"]
RISKY = ["xyz", "top", "tk", "click", "cfd", "icu", "online", "info", "site"]
FREE_HOSTS = ["weebly.com", "blogspot.com", "pages.dev", "web.app", "000webhostapp.com", "github.io"]


def _rand_token(r: random.Random, n: int) -> str:
    return "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def _typo(r: random.Random, b: str) -> str:
    return r.choice([b.replace("l", "1", 1), b.replace("o", "0", 1), b + b[-1], b[:-1] + "-" + b[-1], b + "-" + r.choice(KEYS), r.choice(KEYS) + "-" + b])


def legit_url(r: random.Random) -> str:
    if r.random() < 0.5:
        host = r.choice(LEGIT_SITES)
    else:
        host = "-".join(r.sample(WORDS, r.choice([1, 1, 2]))) + "." + r.choice(["com", "org", "net", "io", "co.uk", "de", "in"])
    if r.random() < 0.35:
        host = r.choice(["www", "www", "blog", "docs", "shop", "support", "mail"]) + "." + host
    path = r.choice(LEGIT_PATHS)
    return ("https" if r.random() < 0.92 else "http") + "://" + host + path


def phishing_url(r: random.Random) -> str:
    kind = r.choices(["typo", "subdomain", "keywords", "ip", "shortener", "freehost", "hard"], [25, 20, 15, 8, 7, 10, 15])[0]
    scheme = "https" if r.random() < 0.6 else "http"
    path = r.choice(["/login", "/verify/account", "/secure/signin.php?id=" + _rand_token(r, 10), "/update-billing", "/", "/wp-content/auth/index.html", "/confirm?session=" + _rand_token(r, 24)])
    if kind == "typo":
        host = _typo(r, r.choice(BRANDS)) + "." + r.choice(["com", "net"] + RISKY)
    elif kind == "subdomain":
        host = r.choice(BRANDS) + ".com." + "-".join(r.sample(KEYS, 2)) + "." + r.choice(RISKY)
    elif kind == "keywords":
        host = "-".join(r.sample(KEYS, r.choice([2, 3]))) + "." + r.choice(["com", "net"] + RISKY)
    elif kind == "ip":
        host, scheme = ".".join(str(r.randint(1, 254)) for _ in range(4)), "http"
    elif kind == "shortener":
        host, path = r.choice(["bit.ly", "tinyurl.com", "cutt.ly", "t.co"]), "/" + _rand_token(r, 7)
    elif kind == "freehost":
        host = _rand_token(r, r.randint(6, 12)) + "." + r.choice(FREE_HOSTS)
    else:  # "hard": clean-looking domain, no obvious lexical tell
        host = r.choice(WORDS) + r.choice(WORDS) + "." + r.choice(["com", "net", "org"])
        path = r.choice(["/", "/login", "/portal/auth", "/home"])
    url = scheme + "://" + host + path
    if r.random() < 0.03:
        url = scheme + "://" + r.choice(BRANDS) + ".com@" + host + path
    if r.random() < 0.05:
        url += "&redirect=%2F%2F" + _rand_token(r, 6) + "%2E" + r.choice(RISKY)
    return url


def _security(rng: np.random.Generator, label: int) -> dict:
    p = bool(label)
    age = rng.lognormal(3.0, 1.2) if p and rng.random() < 0.8 else rng.lognormal(7.0, 1.0)
    row = {
        "domain_age_days": round(float(age), 1), "whois_privacy": int(rng.random() < (0.7 if p else 0.3)),
        "dns_resolves": int(rng.random() < (0.9 if p else 0.99)), "nameserver_count": int(rng.integers(1, 5)),
        "tls_valid": int(rng.random() < (0.75 if p else 0.97)), "tls_cert_age_days": round(float(rng.lognormal(2.5 if p else 5.0, 1.0)), 1),
        "tls_hostname_match": int(rng.random() < (0.8 if p else 0.98)), "redirect_count": int(rng.poisson(1.8 if p else 0.4)),
        "has_login_form": int(rng.random() < (0.8 if p else 0.25)), "has_password_field": int(rng.random() < (0.75 if p else 0.2)),
        "external_form_action": int(rng.random() < (0.45 if p else 0.04)), "iframe_count": int(rng.poisson(1.0 if p else 0.3)),
        "hidden_element_count": int(rng.poisson(3.0 if p else 1.0)), "has_suspicious_scripts": int(rng.random() < (0.4 if p else 0.05)),
        "threat_feed_hits": int(rng.poisson(1.6 if p else 0.15)),
    }
    return {k: (np.nan if rng.random() < 0.3 else v) for k, v in row.items()}  # 30% of values missing, like real life


def generate(n: int = 3000, seed: int = 42, phishing_ratio: float = 0.5, label_noise: float = 0.03) -> pd.DataFrame:
    r, rng = random.Random(seed), np.random.default_rng(seed)
    rows, seen = [], set()
    while len(rows) < n:
        y = int(r.random() < phishing_ratio)
        url = phishing_url(r) if y else legit_url(r)
        if url in seen:
            continue
        seen.add(url)
        observed = 1 - y if r.random() < label_noise else y  # a few deliberately wrong labels, as in real data
        rows.append({"url": url, "label": observed, "source": "synthetic", **_security(rng, y)})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rows", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/sample/synthetic_urls.csv")
    a = ap.parse_args()
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    generate(a.rows, a.seed).to_csv(out, index=False)
    print(f"Wrote {a.rows} SYNTHETIC rows to {out}")
