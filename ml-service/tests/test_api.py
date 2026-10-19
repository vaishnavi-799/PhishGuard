"""HTTP-level tests. Skipped automatically when fastapi / httpx are not installed."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

HAVE = bool(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx") and importlib.util.find_spec("pydantic"))

if HAVE:
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.main import create_app
    from tests._fixtures import trained


@unittest.skipUnless(HAVE, "fastapi/httpx/pydantic not installed")
class ApiTests(unittest.TestCase):
    def client(self, **kw):
        return TestClient(create_app(Settings(model_dir=kw.pop("model_dir", trained()[0]), **kw)))

    def test_predict_ok(self):
        with self.client() as c:
            r = c.post("/predict", json={"url": "http://paypa1-secure-login.xyz/verify", "security_features": {"domain_age_days": 3}, "top_k": 3})
            self.assertEqual(r.status_code, 200, r.text)
            b = r.json()
            self.assertIn(b["prediction"], ("phishing", "legitimate"))
            self.assertLessEqual(len(b["top_features"]), 3)
            self.assertEqual(c.get("/health").json()["model_loaded"], True)
            self.assertIn("test_metrics", c.get("/model").json())

    def test_validation_errors_are_422(self):
        with self.client() as c:
            for body in ({"url": "javascript:alert(1)"}, {"url": "x"}, {"url": "https://a.com", "security_features": {"nope": 1}}, {"url": "https://a.com", "extra": 1}, {"url": "https://a.com", "top_k": 99}, {}):
                self.assertEqual(c.post("/predict", json=body).status_code, 422, body)

    def test_api_key(self):
        with self.client(api_key="s3cret-key") as c:
            body = {"url": "https://example.com/login"}
            self.assertEqual(c.post("/predict", json=body).status_code, 401)
            self.assertEqual(c.post("/predict", json=body, headers={"X-API-Key": "wrong"}).status_code, 401)
            self.assertEqual(c.post("/predict", json=body, headers={"X-API-Key": "s3cret-key"}).status_code, 200)
            self.assertEqual(c.get("/health").status_code, 200)  # health stays open for orchestrators

    def test_no_model_gives_503_not_a_fake_answer(self):
        with self.client(model_dir=Path(tempfile.mkdtemp())) as c:
            self.assertEqual(c.post("/predict", json={"url": "https://example.com"}).status_code, 503)
            h = c.get("/health").json()
            self.assertEqual((h["status"], h["model_loaded"]), ("degraded", False))


if __name__ == "__main__":
    unittest.main()
