"""Per-prediction feature contributions (log-odds scale; positive = pushes toward 'phishing').

Primary method: SHAP TreeExplainer (exact TreeSHAP) for XGBoost models.
Fallback (SHAP not installed, or non-XGBoost model): occlusion. Each feature is replaced by its training median and the
change in log-odds is reported. It is a simpler attribution than SHAP and is labelled `occlusion` in the API response.
"""
from __future__ import annotations

import logging
import math

import numpy as np
import pandas as pd

from app.modeling import ModelBundle
from explainability.text import describe
from features.schema import label

log = logging.getLogger("ml.explain")
_EPS = 1e-6


def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, _EPS, 1 - _EPS)
    return np.log(p / (1 - p))


class Explainer:
    def __init__(self, bundle: ModelBundle, prefer_shap: bool = True):
        self.bundle = bundle
        self.method = "occlusion"
        self._shap = None
        medians = bundle.metadata.get("feature_medians", {})
        self._baseline = {f: (medians.get(f) if medians.get(f) is not None else np.nan) for f in bundle.feature_names}
        if prefer_shap and bundle.algorithm == "xgboost":
            try:
                import shap
                self._shap = shap.TreeExplainer(bundle.estimator)
                self.method = "shap_tree"
            except Exception as e:  # ImportError or SHAP/XGBoost version mismatch
                log.warning("SHAP unavailable (%s); using occlusion explanations", e)

    def contributions(self, X: pd.DataFrame) -> np.ndarray:
        """-> array (n_rows, n_features) in the bundle's feature order."""
        X = X.reindex(columns=self.bundle.feature_names).astype(float)
        if self._shap is not None:
            vals = self._shap.shap_values(X)
            if isinstance(vals, list):  # older SHAP versions return one array per class
                vals = vals[-1]
            return np.asarray(vals, dtype=float)
        return self._occlusion(X)

    def _occlusion(self, X: pd.DataFrame) -> np.ndarray:
        base = _logit(self.bundle.predict_proba(X))
        out = np.zeros(X.shape, dtype=float)
        for j, f in enumerate(X.columns):
            if X[f].isna().all():  # not supplied by the caller: nothing to attribute
                continue
            Xm = X.copy()
            Xm[f] = self._baseline[f]
            out[:, j] = base - _logit(self.bundle.predict_proba(Xm))
        return out

    def explain_row(self, X: pd.DataFrame, top_k: int = 5) -> tuple[list[dict], list[str]]:
        contrib = self.contributions(X.iloc[[0]])[0]
        names = self.bundle.feature_names
        order = np.argsort(-np.abs(contrib))
        top, text = [], []
        for j in order:
            c = float(contrib[j])
            if len(top) >= top_k or abs(c) < 1e-9:
                break
            v = X.iloc[0][names[j]]
            if v is None or (isinstance(v, float) and math.isnan(v)):
                continue  # only explain with values the caller actually provided; "not available" is not an explanation
            v = float(v)
            top.append({"feature": names[j], "label": label(names[j]), "value": v, "contribution": round(c, 4), "direction": "phishing" if c > 0 else "legitimate"})
            text.append(describe(names[j], v, c))
        return top, text
