"""Internationalised-domain (homograph) analysis: punycode decoding, mixed scripts, confusable skeletons."""
from __future__ import annotations

import unicodedata

from .brands import load_brands
from features.url_features import split_host

# Visually confusable non-ASCII characters -> ASCII look-alike (a practical subset of Unicode UTS #39 confusables).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "ӏ": "l", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "υ": "u", "χ": "x", "β": "b", "ε": "e", "η": "n",
    "ɑ": "a", "ɡ": "g", "ɩ": "i", "ʋ": "v", "ǀ": "l", "ǃ": "!", "ⅼ": "l", "ⅰ": "i", "ⅽ": "c", "ⅾ": "d", "ա": "w", "օ": "o", "ս": "u", "ց": "g", "հ": "h",
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ƒ": "f",
}
INVISIBLE = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u180e"}
BIDI = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\u200e", "\u200f"}
RELEVANT_SCRIPTS = {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "CJK", "HIRAGANA", "KATAKANA", "HANGUL", "THAI", "DEVANAGARI"}


def decode_punycode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return label
    return label


def to_unicode_host(host: str) -> str:
    return ".".join(decode_punycode_label(l) for l in host.lower().split("."))


def to_ascii_host(host: str) -> str | None:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def script_of(ch: str) -> str:
    if ch.isascii():
        return "LATIN" if ch.isalpha() else "COMMON"
    try:
        first = unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"
    if first in ("CJK", "HIRAGANA", "KATAKANA", "HANGUL", "LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "THAI", "DEVANAGARI"):
        return first
    return "COMMON" if not ch.isalpha() else first


def skeleton(label: str) -> str:
    """Map a label to the ASCII string it visually resembles."""
    s = unicodedata.normalize("NFKC", label).lower()
    return "".join(CONFUSABLES.get(c, c) for c in s if c not in INVISIBLE and c not in BIDI)


def analyze_homograph(host: str) -> dict:
    uni = to_unicode_host(host)
    labels_u = uni.split(".")
    labels_raw = host.lower().split(".")
    punycode = [l for l in labels_raw if l.startswith("xn--")]
    non_ascii = any(not c.isascii() for c in uni)
    scripts, mixed, hidden_chars = {}, [], []
    for l in labels_u:
        sc = sorted({script_of(c) for c in l if script_of(c) in RELEVANT_SCRIPTS})
        scripts[l] = sc
        if len(sc) > 1:
            mixed.append(l)
    for c in uni:
        if c in INVISIBLE or c in BIDI:
            hidden_chars.append(f"U+{ord(c):04X}")
    _, name_u, suffix_u, registered_u = split_host(uni)
    sk_name = skeleton(name_u)
    matches = []
    if non_ascii or hidden_chars:
        for b in load_brands():
            for lab in b.labels:
                if sk_name == lab and name_u != lab:
                    matches.append({"brand": b.name, "brand_label": lab, "skeleton": sk_name, "technique": "confusable_characters"})
    is_idn = bool(punycode) or non_ascii
    whole_script = bool(non_ascii and len(name_u) > 0 and all(script_of(c) in ("CYRILLIC", "GREEK", "COMMON") for c in name_u) and sk_name.isascii())
    return {
        "is_idn": is_idn, "punycode_labels": punycode, "unicode_host": uni, "ascii_host": to_ascii_host(uni),
        "contains_non_ascii": non_ascii, "scripts_by_label": scripts, "mixed_script_labels": mixed,
        "whole_script_confusable": whole_script, "hidden_characters": hidden_chars,
        "skeleton": sk_name if non_ascii else None, "brand_matches": matches,
        "is_suspicious": bool(matches or mixed or hidden_chars or whole_script),
    }
