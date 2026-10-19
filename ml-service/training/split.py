from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

from features import registered_domain


def split_dataset(df: pd.DataFrame, test_size: float = 0.2, seed: int = 42, group_by_domain: bool = True):
    """-> (train_idx, test_idx). With group_by_domain, every URL of a registered domain lands on ONE side of the split.

    Without it, near-identical URLs from the same site leak across train/test and inflate every metric.
    """
    y = df["label"].to_numpy()
    idx = np.arange(len(df))
    if group_by_domain:
        groups = df["url"].map(registered_domain).to_numpy()
        n_splits = max(2, round(1 / test_size))
        tr, te = next(StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed).split(idx, y, groups))
    else:
        tr, te = train_test_split(idx, test_size=test_size, random_state=seed, stratify=y)
    for name, part in (("train", tr), ("test", te)):
        if len(set(y[part])) < 2:
            raise ValueError(f"The {name} split contains a single class; collect more data or lower test_size")
    return np.sort(tr), np.sort(te)
