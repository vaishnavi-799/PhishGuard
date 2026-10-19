"""Optional security features supplied by other services (WHOIS/TLS/page analysis/threat feeds)."""
from __future__ import annotations

import math
from typing import Mapping

from .schema import SECURITY_FEATURES

NAN = float("nan")


def coerce(value) -> float:
    if value is None:
        return NAN
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        v = float(value)
        return v if math.isfinite(v) else NAN
    raise ValueError(f"Security feature values must be numbers, booleans or null, got {type(value).__name__}")


def check_keys(features: Mapping | None) -> None:
    unknown = sorted(set(features or {}) - set(SECURITY_FEATURES))
    if unknown:
        raise ValueError(f"Unknown security feature(s) {unknown}. Allowed: {SECURITY_FEATURES}")


def extract_security_features(features: Mapping | None) -> dict[str, float]:
    check_keys(features)
    out = {k: NAN for k in SECURITY_FEATURES}
    for k, v in (features or {}).items():
        out[k] = coerce(v)
    return out
