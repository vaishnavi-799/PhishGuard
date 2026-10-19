"""Loading and validating the training CSV. The schema is documented in data/README.md."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from features import SECURITY_FEATURES
from features.url_features import InvalidUrlError, parse_url

REQUIRED_COLUMNS = ("url", "label")
LABEL_MAP = {"1": 1, "phishing": 1, "phish": 1, "malicious": 1, "bad": 1, "0": 0, "legitimate": 0, "legit": 0, "benign": 0, "good": 0}
MIN_ROWS = 200


@dataclass
class DatasetReport:
    path: str
    sha256: str
    rows_in: int = 0
    rows_out: int = 0
    dropped_blank_url: int = 0
    dropped_invalid_url: int = 0
    dropped_duplicates: int = 0
    dropped_conflicting_labels: int = 0
    class_counts: dict = field(default_factory=dict)
    synthetic: bool = False
    security_columns_present: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_dataset(path: str | Path) -> tuple[pd.DataFrame, DatasetReport]:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}. See data/README.md for the expected CSV schema.")
    df = pd.read_csv(path, dtype={"url": str, "label": str})
    rep = DatasetReport(path=str(path), sha256=file_sha256(path), rows_in=len(df))
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required column(s) {missing}. Found: {list(df.columns)}")

    lab = df["label"].astype(str).str.strip().str.lower()
    unknown = sorted(set(lab[~lab.isin(LABEL_MAP)].unique()))
    if unknown:
        raise ValueError(f"Unrecognised label value(s) {unknown[:10]}. Allowed: {sorted(LABEL_MAP)}")
    df["label"] = lab.map(LABEL_MAP).astype(int)

    df["url"] = df["url"].fillna("").astype(str).str.strip()
    blank = df["url"] == ""
    rep.dropped_blank_url = int(blank.sum())
    df = df[~blank]

    def parsable(u: str) -> bool:
        try:
            parse_url(u)
            return True
        except InvalidUrlError:
            return False

    ok = df["url"].map(parsable)
    rep.dropped_invalid_url = int((~ok).sum())
    df = df[ok]

    # The same URL with different labels is label noise: drop every copy rather than guess.
    n_labels = df.groupby("url")["label"].transform("nunique")
    rep.dropped_conflicting_labels = int((n_labels > 1).sum())
    df = df[n_labels == 1]
    before = len(df)
    df = df.drop_duplicates(subset="url", keep="first")
    rep.dropped_duplicates = before - len(df)

    present = [c for c in SECURITY_FEATURES if c in df.columns]
    for c in present:
        df[c] = pd.to_numeric(df[c], errors="coerce")  # blanks / junk -> NaN (treated as "not available")
    rep.security_columns_present = present
    rep.synthetic = bool("source" in df.columns and len(df) and (df["source"].astype(str).str.lower() == "synthetic").all())

    df = df.reset_index(drop=True)
    rep.rows_out = len(df)
    rep.class_counts = {"legitimate": int((df["label"] == 0).sum()), "phishing": int((df["label"] == 1).sum())}
    if min(rep.class_counts.values()) == 0:
        raise ValueError(f"Dataset needs both classes, got {rep.class_counts}")
    if rep.rows_out < MIN_ROWS:
        raise ValueError(f"Dataset has only {rep.rows_out} usable rows (minimum {MIN_ROWS}); metrics would be meaningless")
    return df, rep
