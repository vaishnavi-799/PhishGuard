import random
import unittest

from analysis.risk import BRAND_FACTOR, POINTS, compute_risk, level_of, recommendations


def parts(**over):
    base = {"url": {"findings": [], "suspicious_keywords": []}, "domain": {"findings": [], "registration": {}}, "tls": {"findings": []}, "website": {"findings": [], "forms": {}},
            "homograph": {}, "brand": {"targets": [], "verified_brand_domain": None}, "reputation": {"indicators": []}}
    base.update(over)
    return base


def f(i, sev="high"):
    return {"id": i, "severity": sev, "detail": i.replace("_", " ")}


class RiskTests(unittest.TestCase):
    def test_empty_input_is_zero_risk(self):
        r = compute_risk(parts(), None)
        self.assertEqual((r["score"], r["level"], r["category"], r["method"], r["factors"]), (0, "Very Low", "Legitimate", "heuristic", []))

    def test_single_factor_is_traceable(self):
        r = compute_risk(parts(url={"findings": [f("ip_host")], "suspicious_keywords": []}), None)
        self.assertEqual(r["score"], POINTS["ip_host"])
        self.assertEqual([(x["id"], x["points"], x["group"]) for x in r["factors"]], [("ip_host", POINTS["ip_host"], "url")])
        self.assertEqual(r["indicators"][0]["sev"], "High")

    def test_score_equals_sum_of_factor_points(self):
        ids = ["ip_host", "at_symbol", "url_shortener", "domain_new"]
        r = compute_risk(parts(url={"findings": [f(i) for i in ids[:3]], "suspicious_keywords": []}, reputation={"indicators": [f("domain_new")]}), None)
        self.assertEqual(r["score"], min(100, sum(POINTS[i] for i in ids)))
        self.assertEqual(sum(x["points"] for x in r["factors"]), sum(POINTS[i] for i in ids))

    def test_keyword_points_are_capped(self):
        one = compute_risk(parts(url={"findings": [f("suspicious_keywords", "low")], "suspicious_keywords": ["login"]}), None)["score"]
        many = compute_risk(parts(url={"findings": [f("suspicious_keywords")], "suspicious_keywords": list("abcdefgh")}), None)["score"]
        self.assertEqual((one, many), (3, 12))

    def test_same_finding_from_two_modules_counts_once(self):
        r = compute_risk(parts(url={"findings": [f("risky_tld", "low")], "suspicious_keywords": []}, reputation={"indicators": [f("risky_tld", "low")]}), None)
        self.assertEqual(r["score"], POINTS["risky_tld"])

    def test_mitigations_reduce_but_never_below_zero(self):
        base = parts(url={"findings": [f("long_url", "low")], "suspicious_keywords": []})
        old = compute_risk({**base, "domain": {"findings": [], "registration": {"age_days": 3000}}}, None)
        self.assertEqual(old["score"], 0)  # 4 points - 12
        self.assertEqual(old["mitigating_factors"][0]["id"], "domain_established")
        tls = compute_risk({**base, "tls": {"findings": [], "certificate_valid": True, "chain_trusted": True}}, None)
        self.assertEqual(tls["score"], 1)

    def test_mitigations_never_excuse_hard_evidence_or_strong_impersonation(self):
        old_valid = {"domain": {"findings": [], "registration": {"age_days": 4000}}, "tls": {"findings": [], "certificate_valid": True, "chain_trusted": True}}
        listed = compute_risk(parts(reputation={"indicators": [f("local_blocklist")]}, **old_valid), None)
        self.assertEqual((listed["score"], listed["mitigating_factors"]), (POINTS["local_blocklist"], []))
        t = {"brand": "PayPal", "score": 90, "signals": [{"id": "homograph", "weight": 90, "detail": ""}]}
        strong = compute_risk(parts(brand={"targets": [t], "verified_brand_domain": None}, **old_valid), None)
        self.assertEqual((strong["score"], strong["mitigating_factors"]), (round(90 * BRAND_FACTOR), []))
        weak_t = {"brand": "PayPal", "score": 30, "signals": [{"id": "brand_in_path", "weight": 30, "detail": ""}]}
        weak = compute_risk(parts(brand={"targets": [weak_t], "verified_brand_domain": None}, **old_valid), None)
        self.assertEqual(weak["score"], 0)  # 13.5 points of weak evidence are outweighed by a 4000-day-old domain

    def test_verified_brand_domain_caps_the_score(self):
        noisy = parts(url={"findings": [f("very_long_url"), f("deep_subdomains"), f("heavy_url_encoding")], "suspicious_keywords": ["login", "secure", "verify"]}, brand={"targets": [], "verified_brand_domain": "PayPal"})
        r = compute_risk(noisy, None)
        self.assertLessEqual(r["score"], 10)
        self.assertEqual(r["level"], "Very Low")
        listed = compute_risk({**noisy, "reputation": {"indicators": [f("local_blocklist")]}}, None)
        self.assertGreaterEqual(listed["score"], 60)  # hard evidence is not capped away

    def test_brand_impersonation_contributes_and_sets_category(self):
        t = {"brand": "PayPal", "score": 80, "signals": [{"id": "typosquat:substitution", "weight": 80, "detail": ""}]}
        r = compute_risk(parts(brand={"targets": [t], "verified_brand_domain": None}), None)
        self.assertEqual(r["score"], round(80 * BRAND_FACTOR))
        self.assertEqual(r["category"], "Brand Impersonation")

    def test_categories(self):
        self.assertEqual(compute_risk(parts(website={"findings": [f("external_form_action")], "forms": {"login_form": True}}), None)["category"], "Credential Phishing")
        self.assertEqual(compute_risk(parts(website={"findings": [f("download_content")], "forms": {}}), None)["category"], "Malware Delivery")
        r = compute_risk(parts(url={"findings": [f("ip_host"), f("at_symbol"), f("hex_ip")], "suspicious_keywords": []}), None)
        self.assertEqual((r["category"], r["score"] >= 40), ("Suspicious Site", True))

    def test_credential_harvest_combination(self):
        w = {"findings": [f("login_form", "low")], "forms": {"login_form": True}}
        plain = compute_risk(parts(website=w), None)["score"]
        young = compute_risk(parts(website=w, reputation={"indicators": [f("domain_very_new")]}), None)
        self.assertIn("credential_harvest_pattern", [x["id"] for x in young["factors"]])
        self.assertEqual(young["score"], plain + POINTS["domain_very_new"] + 10)

    def test_homograph_factors(self):
        r = compute_risk(parts(homograph={"mixed_script_labels": ["x"], "hidden_characters": ["U+200B"], "whole_script_confusable": True, "is_idn": True, "is_suspicious": True}), None)
        self.assertEqual({x["id"] for x in r["factors"]}, {"homograph_mixed_script", "homograph_hidden_characters", "homograph_whole_script"})
        self.assertEqual({x["id"] for x in compute_risk(parts(homograph={"is_idn": True, "is_suspicious": False}), None)["factors"]}, {"punycode_idn"})

    def test_score_is_capped_at_100(self):
        every = [f(i) for i in POINTS]
        self.assertEqual(compute_risk(parts(url={"findings": every, "suspicious_keywords": []}), None)["score"], 100)

    def test_ml_blending(self):
        base = parts(url={"findings": [f("ip_host"), f("url_shortener"), f("at_symbol")], "suspicious_keywords": []})  # 18+10+15 = 43
        h = compute_risk(base, None)
        self.assertEqual((h["score"], h["method"]), (43, "heuristic"))
        b = compute_risk(base, {"probability": 0.9}, 0.4)
        self.assertEqual((b["method"], b["score"], b["heuristic_score"]), ("blended", round(0.6 * 43 + 0.4 * 90), 43))
        self.assertEqual(compute_risk(base, {"probability": None}, 0.4)["method"], "heuristic")
        self.assertEqual(compute_risk(base, {"probability": 0.9}, 0.0)["score"], 43)

    def test_ml_cannot_hide_blocklist_hits(self):
        r = compute_risk(parts(reputation={"indicators": [f("local_blocklist")]}), {"probability": 0.0}, 0.9)
        self.assertGreaterEqual(r["score"], r["heuristic_score"])

    def test_level_boundaries(self):
        for s, lvl in [(0, "Very Low"), (19, "Very Low"), (20, "Low"), (39, "Low"), (40, "Medium"), (59, "Medium"), (60, "High"), (79, "High"), (80, "Critical"), (100, "Critical")]:
            self.assertEqual(level_of(s), lvl, s)

    def test_fuzz_score_always_valid(self):
        rnd, ids = random.Random(1), list(POINTS)
        for _ in range(300):
            fs = [f(rnd.choice(ids)) for _ in range(rnd.randint(0, 12))]
            ml = rnd.choice([None, {"probability": rnd.random()}])
            r = compute_risk(parts(url={"findings": fs, "suspicious_keywords": ["a"] * rnd.randint(0, 5)}, domain={"findings": [], "registration": {"age_days": rnd.choice([None, 1, 500, 5000])}}), ml, rnd.random())
            self.assertTrue(isinstance(r["score"], int) and 0 <= r["score"] <= 100)
            self.assertEqual(r["level"], level_of(r["score"]))


class RecommendationTests(unittest.TestCase):
    def rec(self, score_ids, level):
        r = {"level": level, "factors": [{"id": i} for i in score_ids]}
        return recommendations(r)

    def titles(self, *a):
        return [x["title"] for x in self.rec(*a)]

    def test_high_risk(self):
        t = self.titles(["ip_host"], "High")
        self.assertTrue({"Do not enter credentials", "Do not download files", "Block the URL", "Report the website"} <= set(t))

    def test_medium_and_low(self):
        self.assertIn("Proceed with caution", self.titles([], "Medium"))
        self.assertIn("No action required", self.titles([], "Very Low"))
        self.assertNotIn("Do not enter credentials", self.titles([], "Low"))

    def test_specific_advice(self):
        self.assertIn("Verify the domain", self.titles(["brand_impersonation"], "High"))
        self.assertIn("Check for look-alike characters", self.titles(["homograph_mixed_script"], "High"))
        self.assertIn("Be wary of brand-new domains", self.titles(["domain_new"], "Medium"))

    def test_shape_and_order(self):
        recs = self.rec([], "Critical")
        self.assertEqual([r["sort_order"] for r in recs], list(range(len(recs))))
        self.assertTrue(all({"icon", "title", "description", "priority"} <= set(r) and r["priority"] in ("High", "Medium", "Low") for r in recs))


if __name__ == "__main__":
    unittest.main()
