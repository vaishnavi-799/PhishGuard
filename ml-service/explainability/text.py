"""Turns numeric contributions into readable sentences. Wording is templated; every number comes from the model."""
from __future__ import annotations

import math

from features.schema import BINARY_FEATURES, label


def format_value(name: str, value) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "not available"
    if name in BINARY_FEATURES:
        return "yes" if value >= 0.5 else "no"
    return f"{value:.0f}" if float(value).is_integer() else f"{value:.2f}"


def describe(name: str, value, contribution: float) -> str:
    direction = "raises" if contribution > 0 else "lowers"
    return f"{label(name)}: {format_value(name, value)} — {direction} phishing risk ({contribution:+.2f})"
