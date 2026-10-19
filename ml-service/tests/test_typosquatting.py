import unittest

from analysis.brands import load_brands, official_brand
from analysis.typosquatting import _edit_technique, detect_typosquatting, normalize_ascii_lookalikes
from features.url_features import split_host


def best(host):
    _, name, suffix, reg = split_host(host)
    return detect_typosquatting(reg, name, suffix.rsplit(".", 1)[-1])["best"]


class TyposquattingTests(unittest.TestCase):
    def test_brand_list_is_loaded(self):
        brands = load_brands()
        self.assertGreater(len(brands), 40)
        self.assertEqual(official_brand("paypal.com").name, "PayPal")
        self.assertIsNone(official_brand("example.com"))

    def test_genuine_domains_never_match(self):
        for h in ["paypal.com", "www.paypal.com", "amazon.in", "login.microsoftonline.com", "hdfcbank.com", "google.co.in"]:
            self.assertIsNone(best(h), h)

    def test_unrelated_domains_do_not_match(self):
        for h in ["example.com", "mydhlpay.com", "bank-of-bankia.com", "stonesoup.net", "cloudpeak.io"]:
            self.assertIsNone(best(h), h)

    def test_each_technique_is_classified(self):
        for host, tech in [("paypla.com", "transposition"), ("paypall.com", "repetition"), ("gogle.com", "omission"), ("goggle.com", "substitution"), ("paypa1.com", "homoglyph_substitution"),
                           ("micros0ft.com", "homoglyph_substitution"), ("rnicrosoft.com", "homoglyph_substitution"), ("paypal-secure-login.com", "combosquatting"), ("securepaypal.net", "combosquatting"),
                           ("hdfcbank.xyz", "tld_swap"), ("netflixx.com", "repetition"), ("amazonn.in", "repetition")]:
            m = best(host)
            self.assertIsNotNone(m, host)
            self.assertEqual(m["technique"], tech, host)

    def test_match_reports_all_three_metrics(self):
        m = best("paypa1.com")
        self.assertEqual(m["brand"], "PayPal")
        for k in ("levenshtein_similarity", "jaro_winkler", "ngram_similarity", "similarity", "distance"):
            self.assertIn(k, m)
        self.assertTrue(0 <= m["similarity"] <= 1 and m["distance"] == 1)
        self.assertGreater(m["jaro_winkler"], 0.9)

    def test_brand_token_inside_another_domain_is_combosquatting(self):
        self.assertEqual(best("github-pages-demo.org")["technique"], "combosquatting")

    def test_short_brand_labels_only_match_whole_tokens(self):
        self.assertEqual(best("dhl-parcel.com")["technique"], "combosquatting")
        self.assertIsNone(best("dhx.com"))  # would be a fuzzy match for "dhl" if short brands were fuzzy-matched

    def test_results_are_ranked_and_limited(self):
        r = detect_typosquatting("paypal-amazon-google.com", "paypal-amazon-google", "com", limit=2)
        self.assertEqual(len(r["matches"]), 2)
        self.assertGreaterEqual(r["matches"][0]["similarity"], r["matches"][1]["similarity"])
        self.assertTrue(r["is_typosquat"])

    def test_helpers(self):
        self.assertEqual(normalize_ascii_lookalikes("paypa1"), "paypal")
        self.assertEqual(normalize_ascii_lookalikes("rnicrosoft"), "microsoft")
        self.assertEqual(_edit_technique("paypal", "paypla"), "transposition")
        self.assertEqual(_edit_technique("paypal", "paypl"), "omission")
        self.assertEqual(_edit_technique("paypal", "paypaal"), "repetition")
        self.assertEqual(_edit_technique("paypal", "payxpal"), "insertion")


if __name__ == "__main__":
    unittest.main()
