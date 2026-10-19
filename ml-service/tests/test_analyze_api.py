"""HTTP tests for POST /analyze. Skipped automatically when fastapi / httpx are not installed."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

HAVE = bool(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx") and importlib.util.find_spec("pydantic"))

if HAVE:
    import dataclasses
    from fastapi.testclient import TestClient
    from analysis.config import AnalysisConfig
    from analysis.engine import AnalysisEngine
    from app.config import Settings
    from app.main import create_app
    from tests._fakes import services


@unittest.skipUnless(HAVE, "fastapi/httpx/pydantic not installed")
class AnalyzeApiTests(unittest.TestCase):
    def client(self, max_concurrent=8, **kw):
        eng = AnalysisEngine(dataclasses.replace(AnalysisConfig(), max_concurrent=max_concurrent), services())
        return TestClient(create_app(Settings(model_dir=Path(tempfile.mkdtemp()), **kw), engine=eng))  # no trained model: /analyze must still work

    def test_analyze_returns_the_normalized_report(self):
        with self.client() as c:
            r = c.post("/analyze", json={"url": "https://paypa1-secure-login.xyz/verify"})
            self.assertEqual(r.status_code, 200, r.text)
            b = r.json()
            self.assertEqual((b["schema_version"], b["modules"]["ml"]["status"]), ("1.0", "skipped"))
            self.assertIn(b["risk"]["level"], ("Medium", "High", "Critical"))
            from analysis.schema import validate_report
            self.assertEqual(validate_report(b), [])

    def test_validation_errors(self):
        with self.client() as c:
            for body in ({"url": "javascript:alert(1)"}, {"url": "ftp://x.com/a"}, {"url": "x"}, {}, {"url": "https://a.com", "unknown": 1}, {"url": "https://a.com", "inspect_website": "maybe"}):
                self.assertEqual(c.post("/analyze", json=body).status_code, 422, body)

    def test_api_key_is_required_when_configured(self):
        with self.client(api_key="k3y") as c:
            self.assertEqual(c.post("/analyze", json={"url": "https://example.com"}).status_code, 401)
            self.assertEqual(c.post("/analyze", json={"url": "https://example.com"}, headers={"X-API-Key": "bad"}).status_code, 401)
            self.assertEqual(c.post("/analyze", json={"url": "https://example.com"}, headers={"X-API-Key": "k3y"}).status_code, 200)

    def test_capacity_limit_returns_429(self):
        with self.client(max_concurrent=0) as c:
            self.assertEqual(c.post("/analyze", json={"url": "https://example.com"}).status_code, 429)

    def test_options_are_honoured(self):
        with self.client() as c:
            b = c.post("/analyze", json={"url": "https://www.example.com/", "inspect_website": False, "include_ml": False}).json()
            self.assertEqual((b["modules"]["website"]["status"], b["modules"]["ml"]["reason"]), ("skipped", "not_requested"))


if __name__ == "__main__":
    unittest.main()
