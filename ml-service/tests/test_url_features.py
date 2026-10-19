import math
import unittest

from features import ALL_FEATURES, URL_FEATURES, extract_all, extract_url_features, registered_domain
from features.security_features import extract_security_features
from features.url_features import InvalidUrlError, entropy, parse_url


class UrlFeatureTests(unittest.TestCase):
    def test_basic_structure(self):
        f = extract_url_features("https://www.example.com/a/b?x=1&y=2")
        self.assertEqual(f["url_length"], len("https://www.example.com/a/b?x=1&y=2"))
        self.assertEqual((f["subdomain_count"], f["has_www"], f["is_https"], f["path_depth"], f["num_query_params"], f["is_ip_host"]), (1, 1, 1, 2, 2, 0))

    def test_ip_host_and_http(self):
        f = extract_url_features("http://192.168.0.1/login")
        self.assertEqual((f["is_ip_host"], f["subdomain_count"], f["is_https"], f["keywords_in_path"]), (1, 0, 0, 1))

    def test_missing_scheme_is_unknown_not_http(self):
        f = extract_url_features("example.com/login")
        self.assertTrue(math.isnan(f["is_https"]))
        self.assertEqual(extract_url_features("example.com:8080/x")["has_port"], 1)

    def test_brand_features(self):
        self.assertEqual(extract_url_features("https://paypal.com/login")["brand_in_host_not_domain"], 0)  # the real brand
        self.assertEqual(extract_url_features("https://paypal.com.secure-verify.xyz/")["brand_in_host_not_domain"], 1)
        self.assertEqual(extract_url_features("https://paypa1-secure.com")["brand_lookalike_domain"], 1)
        self.assertEqual(extract_url_features("https://secure-verify.xyz/")["suspicious_tld"], 1)

    def test_multi_label_suffix(self):
        self.assertEqual(registered_domain("https://news.bbc.co.uk/x"), "bbc.co.uk")
        self.assertEqual(extract_url_features("https://news.bbc.co.uk/x")["subdomain_count"], 1)

    def test_entropy(self):
        self.assertEqual(entropy("aaaa"), 0.0)
        self.assertAlmostEqual(entropy("abcd"), 2.0)

    def test_schema_is_complete_and_finite(self):
        f = extract_url_features("https://a-b.example.org/p?q=%41&r=2")
        self.assertEqual(list(f), URL_FEATURES)
        self.assertTrue(all(math.isfinite(v) or math.isnan(v) for v in f.values()))
        self.assertEqual(list(extract_all("https://example.com")), ALL_FEATURES)

    def test_invalid_urls_are_rejected(self):
        for bad in ["", "   ", "javascript:alert(1)", "mailto:a@b.co", "ftp://x.com/f", "http://", "a b.com", "http://x.com/" + "a" * 2100, None, 5]:
            with self.assertRaises(InvalidUrlError, msg=repr(bad)[:40]):
                parse_url(bad)

    def test_security_features(self):
        s = extract_security_features({"domain_age_days": 3, "tls_valid": True, "redirect_count": None})
        self.assertEqual((s["domain_age_days"], s["tls_valid"]), (3.0, 1.0))
        self.assertTrue(math.isnan(s["redirect_count"]) and math.isnan(s["threat_feed_hits"]))
        with self.assertRaises(ValueError):
            extract_security_features({"not_a_feature": 1})
        with self.assertRaises(ValueError):
            extract_security_features({"domain_age_days": "3"})
        self.assertTrue(math.isnan(extract_security_features({"domain_age_days": float("inf")})["domain_age_days"]))


if __name__ == "__main__":
    unittest.main()
