"""DataFrame <-> model matrix. Used identically by training and serving, so features cannot drift apart."""
from __future__ import annotations

import numpy as np
import pandas as pd

from features import ALL_FEATURES, SECURITY_FEATURES, extract_all


def build_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    """One row per URL. Security columns are used when present in df, otherwise left as NaN."""
    sec_cols = [c for c in SECURITY_FEATURES if c in df.columns]
    rows = []
    for rec in df[["url"] + sec_cols].itertuples(index=False):
        sec = {c: (None if pd.isna(v) else v) for c, v in zip(sec_cols, rec[1:])}
        rows.append(extract_all(rec[0], sec))
    return pd.DataFrame(rows, columns=ALL_FEATURES, index=df.index).astype(float)


def trainable_columns(train_features: pd.DataFrame) -> tuple[list[str], list[str]]:
    """Features that have at least one observed value in the TRAINING split, and those that do not."""
    keep = [c for c in train_features.columns if train_features[c].notna().any()]
    return keep, [c for c in train_features.columns if c not in keep]


def to_model_input(frame: pd.DataFrame, feature_names: list[str]) -> pd.DataFrame:
    """Order/select columns exactly as the model was trained; absent columns become NaN."""
    return frame.reindex(columns=feature_names).astype(float)


def median_baseline(train_features: pd.DataFrame) -> dict[str, float | None]:
    med = train_features.median(numeric_only=True)
    return {c: (None if pd.isna(med.get(c)) else float(med[c])) for c in train_features.columns}
