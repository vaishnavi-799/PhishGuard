import unittest

from analysis.brand_impersonation import assess_brand_impersonation
from analysis.homograph import analyze_homograph
from analysis.typosquatting import detect_typosquatting
from features.url_features import parse_url, split_host


def assess(url, website=None):
    p = parse_url(url)
    sub, name, suffix, reg = split_host(p.host)
    return assess_brand_impersonation(registered_domain=reg, domain_name=name, subdomains=sub, path=p.path, typo=detect_typosquatting(reg, name, suffix.rsplit(".", 1)[-1]), homograph=analyze_homograph(p.host), website=website)


def page(title, login=False, status="ok"):
    return {"status": status, "fetched": True, "title": title, "site_name": None, "headings": [], "forms": {"login_form": login}}


def signals(r, i=0):
    return {s["id"] for s in r["targets"][i]["signals"]}


class BrandImpersonationTests(unittest.TestCase):
    def test_official_domains_are_verified_and_never_flagged(self):
        for u in ["https://www.paypal.com/signin", "https://login.microsoftonline.com/", "https://www.amazon.in/gp/css", "https://hdfcbank.com/netbanking"]:
            r = assess(u, page("PayPal Microsoft Amazon HDFC", login=True))
            self.assertFalse(r["is_impersonation_suspected"], u)
            self.assertEqual((r["score"], r["targets"]), (0, []))
            self.assertIsNotNone(r["verified_brand_domain"])

    def test_unrelated_site_has_no_targets(self):
        r = assess("https://www.example.com/about", page("Example Domain"))
        self.assertEqual((r["is_impersonation_suspected"], r["targets"], r["verified_brand_domain"]), (False, [], None))

    def test_typosquat(self):
        r = assess("https://paypa1.com/login")
        self.assertTrue(r["is_impersonation_suspected"])
        self.assertEqual(r["targets"][0]["brand"], "PayPal")
        self.assertIn("typosquat:homoglyph_substitution", signals(r))
        self.assertGreaterEqual(r["score"], 80)
        m = r["targets"][0]["metrics"]
        self.assertTrue(all(k in m for k in ("levenshtein_similarity", "jaro_winkler", "ngram_similarity", "similarity")))

    def test_subdomain_abuse(self):
        r = assess("https://paypal.com.account-verify.xyz/")
        self.assertTrue(r["is_impersonation_suspected"])
        self.assertIn("brand_in_subdomain", signals(r))
        r = assess("https://login.secure-microsoft.evil.top/")
        self.assertEqual(r["targets"][0]["brand"], "Microsoft")

    def test_homograph_signal(self):
        r = assess("https://раураl.com/")
        self.assertIn("homograph", signals(r))
        self.assertGreaterEqual(r["score"], 90)

    def test_path_mention_alone_is_weak(self):
        r = assess("https://blog.example.com/posts/paypal-fees-explained")
        self.assertEqual(signals(r), {"brand_in_path"})
        self.assertFalse(r["is_impersonation_suspected"])

    def test_page_content_on_a_foreign_domain(self):
        r = assess("https://random-site.example.org/", page("PayPal - Log in", login=True))
        self.assertEqual(signals(r), {"brand_in_page_title", "brand_login_form"})
        self.assertTrue(r["is_impersonation_suspected"])
        r = assess("https://random-site.example.org/", page("PayPal - Log in", login=False))
        self.assertEqual(signals(r), {"brand_in_page_title"})
        self.assertEqual(assess("https://random-site.example.org/", page("PayPal", status="failed"))["targets"], [])  # a failed fetch contributes nothing

    def test_more_evidence_scores_higher(self):
        weak = assess("https://paypal-help.example.org/")["score"]
        strong = assess("https://paypal-help.example.org/", page("PayPal Help", login=True))["score"]
        self.assertGreater(strong, weak)
        self.assertLessEqual(strong, 100)

    def test_targets_are_ranked_and_limited(self):
        r = assess("https://paypal-amazon-google-apple-netflix-dropbox.com/")
        self.assertLessEqual(len(r["targets"]), 5)
        scores = [t["score"] for t in r["targets"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


if __name__ == "__main__":
    unittest.main()
