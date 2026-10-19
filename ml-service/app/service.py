"""Framework-independent prediction logic (the FastAPI layer in main.py is a thin wrapper around this)."""
from __future__ import annotations

import logging
import math
from pathlib import Path

import numpy as np
import pandas as pd

from app.modeling import ModelBundle
from explainability.explainer import Explainer
from features import extract_all, parse_url
from features.schema import SECURITY_FEATURES
from preprocessing.pipeline import to_model_input

log = logging.getLogger("ml.service")


class PredictionService:
    def __init__(self, bundle: ModelBundle, explainer: Explainer | None = None):
        self.bundle = bundle
        self.explainer = explainer or Explainer(bundle)

    @classmethod
    def load(cls, model_dir: str | Path) -> "PredictionService":
        return cls(ModelBundle.load(model_dir))

    def _frame(self, url: str, security: dict | None) -> pd.DataFrame:
        row = extract_all(url, security)  # raises InvalidUrlError / ValueError for bad input
        return to_model_input(pd.DataFrame([row]), self.bundle.feature_names)

    def predict(self, url: str, security_features: dict | None = None, top_k: int = 5, explain: bool = True) -> dict:
        X = self._frame(url, security_features)
        p = float(self.bundle.predict_proba(X)[0])
        coverage = float(1.0 - X.isna().to_numpy().mean())
        # confidence = distance from the decision boundary, scaled down when many input features are unavailable.
        # It is a heuristic reliability indicator, NOT a calibrated statistical confidence interval.
        confidence = abs(2 * p - 1) * (0.5 + 0.5 * coverage)
        top, text = self.explainer.explain_row(X, top_k) if explain else ([], [])
        ignored = sorted(k for k in (security_features or {}) if k in SECURITY_FEATURES and k not in self.bundle.feature_names)
        log.info("predict host=%s p=%.3f", parse_url(url).host, p)  # never log the full URL: it can contain tokens
        return {
            "prediction": "phishing" if p >= self.bundle.threshold else "legitimate",
            "probability": round(p, 4), "confidence": round(float(confidence), 4),
            "top_features": top, "explanation": text,
            "model_version": self.bundle.version, "explanation_method": self.explainer.method if explain else None,
            "ignored_features": ignored,
        }

    def info(self) -> dict:
        m = self.bundle.metadata
        return {"model_version": m["model_version"], "algorithm": m["algorithm"], "created_at": m["created_at"], "threshold": m["threshold"],
                "n_features": len(m["feature_names"]), "feature_names": m["feature_names"], "dropped_features": m.get("dropped_features", []),
                "explanation_method": self.explainer.method, "dataset": {k: m["dataset"].get(k) for k in ("rows_out", "class_counts", "synthetic", "sha256", "warning")},
                "test_metrics": m["metrics"]["test"]}
