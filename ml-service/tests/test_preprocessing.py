import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from features import ALL_FEATURES
from preprocessing.dataset import MIN_ROWS, load_dataset
from preprocessing.pipeline import build_feature_frame, to_model_input, trainable_columns


def make_csv(df: pd.DataFrame) -> Path:
    p = Path(tempfile.mkdtemp()) / "d.csv"
    df.to_csv(p, index=False)
    return p


def base(n=MIN_ROWS + 40):
    return pd.DataFrame({"url": [f"https://site{i}.example.com/p{i}" for i in range(n)], "label": [i % 2 for i in range(n)]})


class DatasetTests(unittest.TestCase):
    def test_missing_columns(self):
        with self.assertRaisesRegex(ValueError, "missing required"):
            load_dataset(make_csv(base().drop(columns="label")))

    def test_unknown_label(self):
        d = base(); d["label"] = d["label"].astype(object); d.loc[0, "label"] = "maybe"
        with self.assertRaisesRegex(ValueError, "Unrecognised label"):
            load_dataset(make_csv(d))

    def test_single_class_and_too_few_rows(self):
        d = base(); d["label"] = 1
        with self.assertRaisesRegex(ValueError, "both classes"):
            load_dataset(make_csv(d))
        with self.assertRaisesRegex(ValueError, "usable rows"):
            load_dataset(make_csv(base(20)))

    def test_cleaning_report(self):
        d = base()
        d = pd.concat([d, pd.DataFrame({"url": [d.url[0], d.url[1], "", "javascript:alert(1)", "https://dup.example.com"], "label": [d.label[0], 1 - d.label[1], 0, 1, 0]})])
        d = pd.concat([d, d.tail(1)])  # exact duplicate row
        df, r = load_dataset(make_csv(d))
        self.assertEqual((r.dropped_blank_url, r.dropped_invalid_url, r.dropped_conflicting_labels), (1, 1, 2))
        self.assertGreaterEqual(r.dropped_duplicates, 1)
        self.assertEqual(len(df), r.rows_out)
        self.assertEqual(sum(r.class_counts.values()), r.rows_out)

    def test_label_aliases_and_numeric_coercion(self):
        d = base(); d["label"] = d["label"].map({0: "benign", 1: "Phishing"}); d["domain_age_days"] = "12"; d.loc[0, "domain_age_days"] = "junk"
        df, r = load_dataset(make_csv(d))
        self.assertEqual(set(df.label), {0, 1})
        self.assertTrue(np.isnan(df.domain_age_days[0]) and df.domain_age_days[1] == 12)
        self.assertEqual(r.security_columns_present, ["domain_age_days"])
        self.assertFalse(r.synthetic)

    def test_synthetic_flag(self):
        d = base(); d["source"] = "synthetic"
        self.assertTrue(load_dataset(make_csv(d))[1].synthetic)

    def test_feature_frame(self):
        df, _ = load_dataset(make_csv(base()))
        X = build_feature_frame(df)
        self.assertEqual(list(X.columns), ALL_FEATURES)
        self.assertEqual(len(X), len(df))
        keep, dropped = trainable_columns(X)
        self.assertIn("domain_age_days", dropped)  # no security data in this CSV -> excluded from the model
        self.assertIn("url_length", keep)
        self.assertEqual(list(to_model_input(X, keep[:3]).columns), keep[:3])


if __name__ == "__main__":
    unittest.main()
