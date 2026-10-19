"""Static HTML inspection. The page is parsed as text with html.parser: no JavaScript is ever executed, nothing is rendered."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from features.url_features import split_host

MAX_INLINE_SCRIPT_CHARS = 200_000
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])|(?:^|;)\s*(?:width|height)\s*:\s*0(?:px)?\s*(?:;|$)|font-size\s*:\s*0", re.I)
_SKIP_HIDDEN = {"script", "style", "meta", "link", "head", "title", "html", "body", "noscript", "template", "base", "option"}
_REFRESH = re.compile(r"^\s*\d+\s*;\s*url\s*=\s*['\"]?([^'\";]+)", re.I)


def _reg(host: str | None) -> str:
    return split_host(host)[3] if host else ""


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title, self._heading, self.headings = "", False, None, []
        self.meta, self.forms, self._form_stack = {}, [], []
        self.inputs, self.iframes, self.hidden_styled, self.script_src = [], [], 0, []
        self.inline_js, self._in_script, self.base, self.refresh = [], False, None, None
        self.oncontextmenu_blocked = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in ("h1", "h2") and len(self.headings) < 6:
            self._heading = tag
            self.headings.append("")
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if name == "refresh":
                m = _REFRESH.match(a.get("content", ""))
                self.refresh = m.group(1).strip() if m else self.refresh
            elif name in ("og:site_name", "application-name", "og:title", "description"):
                self.meta[name] = a.get("content", "")[:200]
        elif tag == "base" and a.get("href"):
            self.base = a["href"]
        elif tag == "form":
            f = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(f)
            self._form_stack.append(f)
        elif tag == "input":
            i = {"type": (a.get("type") or "text").lower(), "name": a.get("name", "")[:40], "autocomplete": a.get("autocomplete", "")}
            self.inputs.append(i)
            if self._form_stack:
                self._form_stack[-1]["inputs"].append(i)
        elif tag == "iframe":
            st = a.get("style", "")
            tiny = a.get("width", "x").strip() in ("0", "1") or a.get("height", "x").strip() in ("0", "1")
            self.iframes.append({"src": a.get("src", "")[:300], "hidden": bool(_HIDDEN_STYLE.search(st)) or tiny or "hidden" in a, "sandboxed": "sandbox" in a})
        elif tag == "script":
            self._in_script = True
            if a.get("src"):
                self.script_src.append(a["src"][:300])
        if "return false" in a.get("oncontextmenu", "").lower():
            self.oncontextmenu_blocked = True
        if tag not in _SKIP_HIDDEN and tag != "input" and ("hidden" in a or _HIDDEN_STYLE.search(a.get("style", ""))):
            self.hidden_styled += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in ("h1", "h2"):
            self._heading = None
        elif tag == "form" and self._form_stack:
            self._form_stack.pop()
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title = (self.title + data)[:300]
        elif self._heading and self.headings:
            self.headings[-1] = (self.headings[-1] + data)[:200]
        elif self._in_script:
            used = sum(map(len, self.inline_js))
            if used < MAX_INLINE_SCRIPT_CHARS:
                self.inline_js.append(data[:MAX_INLINE_SCRIPT_CHARS - used])  # truncate the chunk itself: one giant chunk must not bypass the cap


def analyze_scripts(js: str) -> dict:
    c = lambda pat, fl=0: len(re.findall(pat, js, fl))
    sig = {
        "eval": c(r"\beval\s*\("), "function_constructor": c(r"new\s+Function\s*\("), "atob": c(r"\batob\s*\("), "unescape": c(r"\bunescape\s*\("),
        "from_char_code": c(r"String\.fromCharCode"), "document_write_unescape": c(r"document\.write\s*\(\s*unescape"),
        "hex_escapes": c(r"\\x[0-9a-fA-F]{2}"), "long_base64_blob": c(r"[A-Za-z0-9+/=]{200,}"),
        "very_long_line": sum(1 for l in js.split("\n") if len(l) > 3000 and l.count(" ") < len(l) / 40),
        "location_redirect": c(r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\("),
        "popup": c(r"window\.open\s*\("), "cookie_access": c(r"document\.cookie"),
        "key_listener": c(r"addEventListener\s*\(\s*['\"]key(?:down|press|up)['\"]") + c(r"\.onkey(?:down|press|up)\s*="),
        "exfil_call": c(r"XMLHttpRequest|\bfetch\s*\(|sendBeacon"),
    }
    reasons = []
    if sig["eval"] and (sig["atob"] or sig["unescape"] or sig["from_char_code"]):
        reasons.append("eval_with_decoder")
    if sig["document_write_unescape"]:
        reasons.append("document_write_unescape")
    if sig["hex_escapes"] > 20:
        reasons.append("hex_escaped_strings")
    if sig["long_base64_blob"]:
        reasons.append("base64_blob")
    if sig["very_long_line"]:
        reasons.append("minified_blob")
    if sig["key_listener"] and sig["exfil_call"]:
        reasons.append("possible_keylogger")
    return {"signals": {k: v for k, v in sig.items() if v}, "suspicious_reasons": reasons, "is_suspicious": bool(reasons)}


def analyze_html(html: str, page_url: str) -> dict:
    p = _Collector()
    try:
        p.feed(html)
        p.close()
    except Exception:  # html.parser is tolerant, but never let a hostile page break the scan
        pass
    page_host = urlsplit(page_url).hostname or ""
    page_reg, base = _reg(page_host), p.base or page_url
    forms = []
    for f in p.forms[:10]:
        raw = f["action"].strip()
        target = urljoin(base, raw) if raw else page_url
        sp = urlsplit(target)
        scheme_bad = raw.lower().startswith(("javascript:", "mailto:", "data:"))
        host = sp.hostname or ""
        ext = bool(host) and _reg(host) != page_reg and not scheme_bad
        types = [i["type"] for i in f["inputs"]]
        forms.append({"action_host": host or None, "method": f["method"], "external": ext, "action_scheme_unusual": scheme_bad,
                      "insecure_submit": urlsplit(page_url).scheme == "https" and sp.scheme == "http",
                      "has_password": "password" in types, "input_types": sorted(set(types))})
    pw = sum(i["type"] == "password" for i in p.inputs)
    hidden_inputs = sum(i["type"] == "hidden" for i in p.inputs)
    ifr = [{"src_host": urlsplit(urljoin(base, i["src"])).hostname, "hidden": i["hidden"], "external": _reg(urlsplit(urljoin(base, i["src"])).hostname) not in ("", page_reg), "sandboxed": i["sandboxed"]} for i in p.iframes[:20]]
    ext_scripts = sorted({h for h in (urlsplit(urljoin(base, s)).hostname for s in p.script_src) if h and _reg(h) != page_reg})
    scripts = analyze_scripts("\n".join(p.inline_js))
    js_redirect = scripts["signals"].get("location_redirect", 0) > 0
    out = {
        "title": p.title.strip()[:200] or None, "site_name": p.meta.get("og:site_name") or p.meta.get("application-name"), "headings": [h.strip() for h in p.headings if h.strip()][:5],
        "forms": {"count": len(p.forms), "items": forms, "login_form": any(f["has_password"] for f in forms) or pw > 0, "external_action": any(f["external"] for f in forms), "insecure_submit": any(f["insecure_submit"] for f in forms)},
        "password_fields": pw,
        "iframes": {"count": len(p.iframes), "hidden": sum(i["hidden"] for i in ifr), "external": sum(i["external"] for i in ifr), "items": ifr[:5]},
        "hidden_elements": {"hidden_inputs": hidden_inputs, "styled_hidden": p.hidden_styled, "total": hidden_inputs + p.hidden_styled},
        "scripts": {"inline_chars": sum(map(len, p.inline_js)), "external_count": len(p.script_src), "external_hosts": ext_scripts[:10], **scripts},
        "client_side_redirect": {"meta_refresh": p.refresh, "javascript": js_redirect},
        "right_click_blocked": p.oncontextmenu_blocked,
    }
    out["findings"] = _findings(out)
    return out


def _findings(w: dict) -> list[dict]:
    f = []
    add = lambda i, s, d: f.append({"id": i, "severity": s, "detail": d})
    if w["forms"]["login_form"]:
        add("login_form", "low", "Page asks for a password")
    if w["forms"]["external_action"]:
        add("external_form_action", "high", "A form submits data to a different domain")
    if w["forms"]["insecure_submit"]:
        add("insecure_form_submit", "medium", "HTTPS page submits a form over plain HTTP")
    if any(i["action_scheme_unusual"] for i in w["forms"]["items"]):
        add("unusual_form_action", "medium", "Form action uses a javascript:/mailto:/data: URL")
    if w["iframes"]["hidden"]:
        add("hidden_iframe", "high", f"{w['iframes']['hidden']} hidden iframe(s)")
    elif w["iframes"]["external"]:
        add("external_iframe", "low", f"{w['iframes']['external']} iframe(s) from other domains")
    if w["hidden_elements"]["total"] >= 10:
        add("many_hidden_elements", "low", f"{w['hidden_elements']['total']} hidden elements/inputs")
    if w["scripts"]["is_suspicious"]:
        add("suspicious_scripts", "high", "Obfuscation/exfiltration patterns: " + ", ".join(w["scripts"]["suspicious_reasons"]))
    if w["client_side_redirect"]["meta_refresh"]:
        add("meta_refresh_redirect", "medium", "Page redirects via <meta refresh>")
    elif w["client_side_redirect"]["javascript"]:
        add("javascript_redirect", "low", "Script changes window.location")
    if w["right_click_blocked"]:
        add("right_click_blocked", "low", "Context menu is disabled (inspection evasion)")
    return f


def analyze_website(fr, registered_domain: str) -> dict:
    """fr: FetchResult from SafeFetcher (or None when fetching was skipped)."""
    base = {"status": "skipped", "fetched": False, "findings": []}
    if fr is None:
        return {**base, "reason": "not_requested"}
    chain = fr.redirects
    redirects = {"count": len(chain), "chain": chain[:6], "cross_domain": any(r["cross_domain"] for r in chain), "ends_on_different_domain": bool(fr.final_url) and _reg(urlsplit(fr.final_url).hostname) != registered_domain}
    meta = {"final_url": fr.final_url, "http_status": fr.status, "content_type": fr.content_type, "tls_verified": fr.tls_verified, "redirects": redirects, "is_download": fr.is_download}
    if fr.blocked or (fr.error and fr.status is None):
        return {"status": "failed", "fetched": False, "error": fr.blocked or fr.error, **meta, "findings": []}
    findings = []
    if redirects["count"] >= 3:
        findings.append({"id": "long_redirect_chain", "severity": "medium", "detail": f"{redirects['count']} redirects before the final page"})
    if redirects["cross_domain"]:
        findings.append({"id": "cross_domain_redirect", "severity": "medium", "detail": "Redirected to a different domain"})
    if fr.tls_verified is False:
        findings.append({"id": "untrusted_tls", "severity": "medium", "detail": "The site's TLS certificate is not trusted"})
    if fr.is_download:
        findings.append({"id": "download_content", "severity": "high", "detail": f"URL serves a file download ({fr.content_type}); it was not downloaded"})
    if fr.body is None:
        return {"status": "ok", "fetched": True, **meta, "page": None, "findings": findings}
    html = fr.body.decode(_charset(fr), "replace")
    page = analyze_html(html, fr.final_url or fr.url)
    return {"status": "ok", "fetched": True, **meta, "truncated": fr.truncated, "size_bytes": len(fr.body), **page, "findings": findings + page["findings"]}


def _charset(fr) -> str:
    m = re.search(r"charset=([\w-]+)", fr.headers.get("content-type", ""), re.I)
    try:
        if m:
            "x".encode(m.group(1))
            return m.group(1)
    except LookupError:
        pass
    return "utf-8"
