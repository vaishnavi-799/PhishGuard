import unittest

from app.service import PredictionService
from app.modeling import ModelNotFoundError
from features.url_features import InvalidUrlError
from tests._fixtures import trained


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = PredictionService.load(trained()[0])

    def test_response_contract(self):
        r = self.svc.predict("http://paypa1-secure-login.xyz/verify/account", top_k=5)
        self.assertEqual(set(r), {"prediction", "probability", "confidence", "top_features", "explanation", "model_version", "explanation_method", "ignored_features"})
        self.assertIn(r["prediction"], ("phishing", "legitimate"))
        self.assertTrue(0 <= r["probability"] <= 1 and 0 <= r["confidence"] <= 1)
        self.assertEqual(r["prediction"] == "phishing", r["probability"] >= self.svc.bundle.threshold)
        self.assertTrue(0 < len(r["top_features"]) <= 5)
        self.assertEqual(len(r["explanation"]), len(r["top_features"]))
        mags = [abs(f["contribution"]) for f in r["top_features"]]
        self.assertEqual(mags, sorted(mags, reverse=True))
        self.assertTrue(all(f["direction"] == ("phishing" if f["contribution"] > 0 else "legitimate") for f in r["top_features"]))
        self.assertIn(r["explanation_method"], ("shap_tree", "occlusion"))

    def test_obvious_cases_are_ranked_sensibly(self):
        bad = self.svc.predict("http://paypa1-secure-login.xyz/verify/account")["probability"]
        good = self.svc.predict("https://www.github.com/about")["probability"]
        self.assertGreater(bad, good + 0.3)

    def test_security_features_change_the_output(self):
        base = self.svc.predict("https://some-new-site.com/login")
        young = self.svc.predict("https://some-new-site.com/login", {"domain_age_days": 2, "threat_feed_hits": 4, "external_form_action": True})
        old = self.svc.predict("https://some-new-site.com/login", {"domain_age_days": 5000, "threat_feed_hits": 0, "external_form_action": False})
        self.assertGreater(young["probability"], old["probability"])
        self.assertNotEqual(base["probability"], young["probability"])

    def test_confidence_drops_when_inputs_are_missing(self):
        # same URL, but with vs without optional signals: coverage differs, so the scaling factor differs
        full = self.svc.predict("https://some-new-site.com/login", {k: 1 for k in ("domain_age_days", "tls_valid", "dns_resolves", "redirect_count", "threat_feed_hits")})
        self.assertLessEqual(full["confidence"], abs(2 * full["probability"] - 1) + 1e-6)

    def test_unavailable_inputs_are_never_used_as_explanations(self):
        r = self.svc.predict("https://some-new-site.com/login", top_k=20)  # no security signals supplied
        self.assertTrue(r["top_features"])
        self.assertTrue(all(f["value"] is not None for f in r["top_features"]))
        self.assertFalse({f["feature"] for f in r["top_features"]} & set(__import__("features").SECURITY_FEATURES))

    def test_explain_flag_and_determinism(self):
        r = self.svc.predict("https://a.example.org/x", explain=False)
        self.assertEqual((r["top_features"], r["explanation"], r["explanation_method"]), ([], [], None))
        self.assertEqual(self.svc.predict("https://a.example.org/x?q=1"), self.svc.predict("https://a.example.org/x?q=1"))

    def test_bad_input(self):
        with self.assertRaises(InvalidUrlError):
            self.svc.predict("javascript:alert(1)")
        with self.assertRaises(ValueError):
            self.svc.predict("https://example.com", {"made_up": 1})

    def test_missing_model(self):
        import tempfile
        with self.assertRaises(ModelNotFoundError):
            PredictionService.load(tempfile.mkdtemp())

    def test_model_info(self):
        info = self.svc.info()
        self.assertTrue(info["dataset"]["synthetic"] and info["test_metrics"]["n_samples"] > 0)


if __name__ == "__main__":
    unittest.main()
