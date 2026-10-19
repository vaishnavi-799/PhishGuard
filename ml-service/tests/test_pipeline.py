import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from app.modeling import ModelBundle, ModelNotFoundError
from features import registered_domain
from preprocessing.dataset import load_dataset
from preprocessing.pipeline import build_feature_frame, to_model_input
from tests._fixtures import ALGORITHM, trained
from training.evaluate import evaluate
from training.generate_sample_data import generate
from training.split import split_dataset
from training.train import run


class EvaluateTests(unittest.TestCase):
    def test_known_values(self):
        m = evaluate([0, 0, 1, 1], [0.1, 0.6, 0.4, 0.9], 0.5)
        self.assertEqual(m["confusion_matrix"], {"tn": 1, "fp": 1, "fn": 1, "tp": 1})
        self.assertEqual((m["accuracy"], m["precision"], m["recall"], m["f1"]), (0.5, 0.5, 0.5, 0.5))
        self.assertAlmostEqual(m["roc_auc"], 0.75)
        self.assertIsNone(evaluate([1, 1], [0.9, 0.8])["roc_auc"])


class SplitTests(unittest.TestCase):
    def test_domain_groups_never_straddle_the_split(self):
        rows = [{"url": f"https://d{i % 80}.com/p{i}", "label": (i % 80) % 2} for i in range(1200)]
        df = pd.DataFrame(rows)
        tr, te = split_dataset(df, 0.2, 1, True)
        dom = df.url.map(registered_domain)
        self.assertFalse(set(dom.iloc[tr]) & set(dom.iloc[te]))
        self.assertEqual(len(set(tr) & set(te)), 0)
        self.assertEqual(len(tr) + len(te), len(df))


class TrainingPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model_dir, cls.csv = trained()

    def test_artifacts_and_metrics(self):
        meta = json.loads((self.model_dir / "metadata.json").read_text())
        self.assertEqual(meta["algorithm"], ALGORITHM)
        self.assertTrue((self.model_dir / meta["model_file"]).is_file() and (self.model_dir / "metrics.json").is_file())
        t = meta["metrics"]["test"]
        for k in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            self.assertTrue(0.0 <= t[k] <= 1.0, k)
        cm = t["confusion_matrix"]
        self.assertEqual(sum(cm.values()), t["n_samples"], "confusion matrix must account for every test sample")
        self.assertEqual(meta["split"]["n_test"], t["n_samples"])
        self.assertTrue(meta["dataset"]["synthetic"] and meta["dataset"]["warning"], "synthetic data must be flagged in the metadata")

    def test_save_load_roundtrip_is_identical(self):
        df, _ = load_dataset(self.csv)
        X = build_feature_frame(df.head(300))
        a, b = ModelBundle.load(self.model_dir), ModelBundle.load(self.model_dir)
        np.testing.assert_allclose(a.predict_proba(X), b.predict_proba(X))
        self.assertEqual(len(a.predict_proba(X)), 300)

    def test_tampered_model_is_refused(self):
        tmp = Path(tempfile.mkdtemp())
        for f in self.model_dir.iterdir():
            (tmp / f.name).write_bytes(f.read_bytes())
        mf = tmp / json.loads((tmp / "metadata.json").read_text())["model_file"]
        mf.write_bytes(mf.read_bytes() + b" ")
        with self.assertRaisesRegex(ModelNotFoundError, "checksum"):
            ModelBundle.load(tmp)
        with self.assertRaises(ModelNotFoundError):
            ModelBundle.load(tmp / "nope")

    def test_model_separates_classes_on_heldout_data(self):
        df, _ = load_dataset(self.csv)
        fresh = generate(600, seed=999)  # URLs the model has never seen
        X = to_model_input(build_feature_frame(fresh), ModelBundle.load(self.model_dir).feature_names)
        p = ModelBundle.load(self.model_dir).predict_proba(X)
        self.assertGreater(p[fresh.label == 1].mean() - p[fresh.label == 0].mean(), 0.4)

    def test_predictions_are_learned_not_hardcoded(self):
        """Shuffle the labels: a real learner can then do no better than chance. A faked pipeline would still 'score' well."""
        df = pd.read_csv(self.csv)
        df["label"] = np.random.default_rng(0).permutation(df["label"].to_numpy())
        tmp = Path(tempfile.mkdtemp())
        df.to_csv(tmp / "shuffled.csv", index=False)
        meta = run(str(tmp / "shuffled.csv"), str(tmp / "m"), algorithm=ALGORITHM, verbose=False)
        self.assertLess(meta["metrics"]["test"]["roc_auc"], 0.65)

    def test_bad_inputs_fail_loudly(self):
        with self.assertRaises(FileNotFoundError):
            run("/nonexistent.csv", verbose=False)
        with self.assertRaises(ValueError):
            from app.modeling import build_estimator
            build_estimator("random_forest")


if __name__ == "__main__":
    unittest.main()
