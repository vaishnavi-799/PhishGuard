import unittest

from analysis.url_analysis import analyze_url


def ids(u):
    return {f["id"] for f in analyze_url(u)["findings"]}


class UrlAnalysisTests(unittest.TestCase):
    def test_clean_url_has_no_findings(self):
        d = analyze_url("https://www.example.com/docs/intro")
        self.assertEqual(d["findings"], [])
        self.assertEqual((d["subdomains"], d["registered_domain"], d["uses_https"], d["is_ip_host"], d["has_at_symbol"]), (["www"], "example.com", True, False, False))

    def test_length_dots_and_subdomains(self):
        d = analyze_url("https://a.b.c.d.example.co.uk/x")
        self.assertEqual((d["subdomain_count"], d["registered_domain"], d["num_dots"]), (4, "example.co.uk", 6))
        self.assertIn("deep_subdomains", ids("https://a.b.c.example.com"))
        self.assertIn("very_long_url", ids("https://example.com/" + "a" * 250))
        self.assertIn("long_url", ids("https://example.com/" + "a" * 120))

    def test_at_symbol(self):
        d = analyze_url("https://paypal.com@evil.example.org/login")
        self.assertTrue(d["has_at_symbol"])
        self.assertIn("at_symbol", {f["id"] for f in d["findings"]})
        self.assertFalse(analyze_url("https://example.com/user@name")["has_at_symbol"])  # '@' in the path is harmless

    def test_ip_hosts_in_every_format(self):
        for u, fmt in [("http://192.0.2.7/x", "dotted_quad"), ("http://2130706433/", "decimal"), ("http://0x7f000001/", "hexadecimal"), ("http://[2001:db8::1]/", "ipv6")]:
            d = analyze_url(u)
            self.assertTrue(d["is_ip_host"], u)
            self.assertEqual(d["ip_format"], fmt, u)
            self.assertIn("ip_host", {f["id"] for f in d["findings"]})
        self.assertIn("hex_ip", ids("http://0x7f000001/"))

    def test_ports(self):
        self.assertEqual((analyze_url("https://example.com:443/")["non_standard_port"], analyze_url("https://example.com/")["port"]), (False, None))
        d = analyze_url("http://example.com:4444/")
        self.assertTrue(d["suspicious_port"] and d["non_standard_port"])
        d = analyze_url("http://example.com:8080/")
        self.assertTrue(d["non_standard_port"] and not d["suspicious_port"])
        self.assertIn("suspicious_port", ids("http://example.com:31337/"))

    def test_url_and_hex_encoding(self):
        d = analyze_url("https://example.com/a%20b%2Fc?q=%41%42%43")
        self.assertEqual(d["url_encoding"]["encoded_char_count"], 5)
        self.assertIn("heavy_url_encoding", {f["id"] for f in d["findings"]})
        self.assertIn("double_encoding", ids("https://example.com/%252e%252e"))
        self.assertIn("encoded_host", ids("https://exa%6dple.com/"))
        self.assertIn("hex_encoding", ids("https://example.com/\\x41\\x42"))
        self.assertEqual(analyze_url("https://example.com/plain")["url_encoding"]["encoded_char_count"], 0)

    def test_hyphens_keywords_shortener_tld(self):
        self.assertIn("excessive_hyphens", ids("https://secure-login-verify-account.example.com"))
        self.assertNotIn("excessive_hyphens", ids("https://my-site.example.com"))
        d = analyze_url("https://example.com/secure/login/verify")
        self.assertEqual(sorted(d["suspicious_keywords"]), ["login", "secure", "verify"])
        self.assertIn("url_shortener", ids("https://bit.ly/3abc"))
        self.assertIn("url_shortener", ids("https://tinyurl.com/x"))
        self.assertIn("risky_tld", ids("https://example.xyz"))

    def test_abnormal_path_and_query(self):
        self.assertIn("executable_path", ids("https://example.com/files/setup.exe"))
        self.assertIn("double_slash_path", ids("https://example.com/a//b"))
        self.assertIn("abnormal_path", ids("https://example.com/a/b/c/d/e/f/g/h"))
        self.assertIn("cms_path", ids("https://example.com/wp-content/x/index.php"))
        self.assertIn("redirect_parameter", ids("https://example.com/r?next=https://evil.com"))
        self.assertIn("redirect_parameter", ids("https://example.com/r?url=http%3A%2F%2Fevil.com"))
        self.assertNotIn("redirect_parameter", ids("https://example.com/r?next=/home"))
        self.assertIn("abnormal_query", ids("https://example.com/p?data=" + "A" * 60))

    def test_special_characters_counted(self):
        d = analyze_url("https://example.com/a$b!c?x=(1)")
        self.assertEqual(d["special_chars"], {"$": 1, "!": 1, "(": 1, ")": 1})
        self.assertEqual(d["special_char_count"], 4)

    def test_findings_are_sorted_by_severity(self):
        sev = [f["severity"] for f in analyze_url("http://192.0.2.1:4444/login?next=http://x.io")["findings"]]
        order = {"high": 3, "medium": 2, "low": 1, "info": 0}
        self.assertEqual(sev, sorted(sev, key=lambda s: -order[s]))


if __name__ == "__main__":
    unittest.main()
