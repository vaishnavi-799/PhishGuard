"""Estimator construction and the on-disk model bundle (model file + metadata.json)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from preprocessing.dataset import file_sha256

# 'xgboost' is the production algorithm. 'hist_gbm' (scikit-learn) exists so the pipeline can be run and tested
# on machines without XGBoost; it is NOT meant to replace it.
ALGORITHMS = ("xgboost", "hist_gbm")
METADATA_FILE = "metadata.json"


class ModelNotFoundError(RuntimeError):
    pass


def default_params(algorithm: str, seed: int) -> dict:
    if algorithm == "xgboost":
        return dict(n_estimators=600, max_depth=6, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8, min_child_weight=2,
                    reg_lambda=1.0, tree_method="hist", eval_metric="logloss", early_stopping_rounds=30, random_state=seed, n_jobs=-1)
    if algorithm == "hist_gbm":
        return dict(max_iter=300, learning_rate=0.08, max_depth=None, early_stopping=True, validation_fraction=0.1, n_iter_no_change=20, random_state=seed)
    raise ValueError(f"Unknown algorithm '{algorithm}'. Choose from {ALGORITHMS}")


def build_estimator(algorithm: str, seed: int = 42, params: dict | None = None):
    p = {**default_params(algorithm, seed), **(params or {})}
    if algorithm == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as e:
            raise RuntimeError("xgboost is not installed. Run `pip install -r requirements.txt` (or use --algorithm hist_gbm for a local smoke test).") from e
        return XGBClassifier(**p), p
    from sklearn.ensemble import HistGradientBoostingClassifier
    return HistGradientBoostingClassifier(**p), p


@dataclass
class ModelBundle:
    estimator: object
    metadata: dict
    path: Path | None = field(default=None)

    @property
    def algorithm(self) -> str:
        return self.metadata["algorithm"]

    @property
    def feature_names(self) -> list[str]:
        return self.metadata["feature_names"]

    @property
    def threshold(self) -> float:
        return float(self.metadata.get("threshold", 0.5))

    @property
    def version(self) -> str:
        return self.metadata["model_version"]

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """P(phishing) for each row. Columns are re-ordered to the training order."""
        X = X.reindex(columns=self.feature_names).astype(float)
        return np.asarray(self.estimator.predict_proba(X))[:, 1]

    def save(self, directory: str | Path) -> Path:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        if self.algorithm == "xgboost":
            fname = "model.json"  # XGBoost's native format: no pickle involved
            self.estimator.save_model(str(d / fname))
        else:
            import joblib
            fname = "model.joblib"
            joblib.dump(self.estimator, d / fname)
        self.metadata["model_file"] = fname
        self.metadata["model_sha256"] = file_sha256(d / fname)
        (d / METADATA_FILE).write_text(json.dumps(self.metadata, indent=2, default=_json_default))
        self.path = d
        return d

    @classmethod
    def load(cls, directory: str | Path) -> "ModelBundle":
        d = Path(directory)
        meta_path = d / METADATA_FILE
        if not meta_path.is_file():
            raise ModelNotFoundError(f"No trained model in '{d}'. Train one first: python -m training.train --data <csv>")
        meta = json.loads(meta_path.read_text())
        model_path = d / meta["model_file"]
        if not model_path.is_file():
            raise ModelNotFoundError(f"Model file missing: {model_path}")
        if file_sha256(model_path) != meta["model_sha256"]:
            raise ModelNotFoundError("Model file does not match its recorded checksum (corrupted or modified); refusing to load it")
        if meta["algorithm"] == "xgboost":
            from xgboost import XGBClassifier
            est = XGBClassifier()
            est.load_model(str(model_path))
        else:
            import joblib  # joblib uses pickle: only load model directories you trust
            est = joblib.load(model_path)
        return cls(est, meta, d)


def _json_default(o):
    if isinstance(o, (np.floating, np.integer)):
        return o.item()
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(f"Not JSON serialisable: {type(o)}")
