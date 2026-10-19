"""Shape of the normalized report returned by AnalysisEngine.analyze() / POST /analyze (schema_version 1.0)."""
from __future__ import annotations

SCHEMA_VERSION = "1.0"
STATUSES = {"ok", "partial", "failed", "skipped"}
TOP_LEVEL = {"schema_version": str, "engine_version": str, "analyzed_at": str, "duration_ms": int, "url": dict, "modules": dict, "url_analysis": dict, "domain_analysis": dict,
             "tls_analysis": dict, "website_analysis": dict, "typosquatting": dict, "homograph": dict, "brand_impersonation": dict, "threat_intelligence": list,
             "ml": (dict, type(None)), "risk": dict, "recommendations": list, "security_features": dict}
MODULES = ("url", "domain", "tls", "website", "typosquatting", "homograph", "brand", "reputation", "ml")


def validate_report(r: dict) -> list[str]:
    """Returns a list of problems (empty = valid)."""
    errs = []
    for k, t in TOP_LEVEL.items():
        if k not in r:
            errs.append(f"missing '{k}'")
        elif not isinstance(r[k], t):
            errs.append(f"'{k}' has wrong type {type(r[k]).__name__}")
    if errs:
        return errs
    if r["schema_version"] != SCHEMA_VERSION:
        errs.append("unsupported schema_version")
    for m in MODULES:
        if r["modules"].get(m, {}).get("status") not in STATUSES:
            errs.append(f"modules.{m}.status invalid")
    risk = r["risk"]
    if not (isinstance(risk.get("score"), int) and 0 <= risk["score"] <= 100):
        errs.append("risk.score must be an int 0-100")
    for k in ("level", "category", "method", "factors", "indicators"):
        if k not in risk:
            errs.append(f"risk.{k} missing")
    for t in r["threat_intelligence"]:
        if not {"provider", "reputation", "is_known_malicious"} <= set(t):
            errs.append("threat_intelligence item incomplete")
    for rec in r["recommendations"]:
        if not {"title", "description", "priority"} <= set(rec):
            errs.append("recommendation incomplete")
    return errs
