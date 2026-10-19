from __future__ import annotations

import numpy as np
from sklearn.metrics import (accuracy_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score)


def evaluate(y_true, y_prob, threshold: float = 0.5) -> dict:
    """All numbers are computed from the given predictions; nothing here is a constant."""
    y_true = np.asarray(y_true).astype(int)
    y_prob = np.asarray(y_prob, dtype=float)
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both = len(set(y_true)) == 2
    return {
        "threshold": threshold,
        "n_samples": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)) if both else None,
        "brier_score": float(brier_score_loss(y_true, y_prob)),  # probability quality (lower is better)
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "confusion_matrix_rows_actual_cols_predicted": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }
