"""Trains one small model on SYNTHETIC data, shared by the tests (so tests don't retrain repeatedly)."""
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

from training.generate_sample_data import generate
from training.train import run

ALGORITHM = "xgboost" if importlib.util.find_spec("xgboost") else "hist_gbm"
_cache: dict = {}


def trained(rows: int = 1500, seed: int = 7) -> tuple[Path, Path]:
    """-> (model_dir, csv_path)"""
    if "v" not in _cache:
        tmp = Path(tempfile.mkdtemp(prefix="mlsvc_"))
        csv = tmp / "data.csv"
        generate(rows, seed).to_csv(csv, index=False)
        run(str(csv), str(tmp / "model"), algorithm=ALGORITHM, seed=seed, verbose=False)
        _cache["v"] = (tmp / "model", csv)
    return _cache["v"]
