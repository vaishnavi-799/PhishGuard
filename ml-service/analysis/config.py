"""Runtime configuration for the analysis engine (all limits are enforced; see README)."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _csv(name: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.environ.get(name, "").split(",") if x.strip())


@dataclass(frozen=True)
class AnalysisConfig:
    enable_network: bool = True          # False => DNS/RDAP/TLS/website modules are skipped (offline analysis)
    allow_private_targets: bool = False  # SSRF guard: never fetch loopback/private/link-local addresses (tests flip this)
    dns_resolvers: tuple = ()            # empty => /etc/resolv.conf, then 1.1.1.1 / 8.8.8.8
    dns_timeout: float = 3.0
    tls_timeout: float = 5.0
    http_timeout: float = 6.0            # per request (connect + each read)
    total_timeout: float = 20.0          # whole analysis wall-clock budget
    max_redirects: int = 5
    max_body_bytes: int = 1_000_000      # HTML read cap; bodies are never executed or stored
    fetch_ports: tuple = (80, 443, 8080, 8443, 8000, 8008, 8888)  # we only fetch pages on these ports
    user_agent: str = "PhishGuardAnalyzer/1.0 (static security scan; does not execute scripts)"
    rdap_enabled: bool = True
    dnsbl_zones: tuple = ()              # e.g. ("dbl.spamhaus.org",) - off by default (check each provider's usage policy)
    blocklist_path: str | None = None    # optional text file, one domain per line
    ml_weight: float = 0.4               # weight of the ML probability in the final risk score (when a model is loaded)
    max_concurrent: int = 8

    @classmethod
    def from_env(cls) -> "AnalysisConfig":
        e = os.environ.get
        return cls(
            enable_network=e("ANALYSIS_ENABLE_NETWORK", "true").lower() != "false",
            allow_private_targets=e("ANALYSIS_ALLOW_PRIVATE", "false").lower() == "true",
            dns_resolvers=_csv("DNS_RESOLVERS"), dns_timeout=float(e("DNS_TIMEOUT", 3)), tls_timeout=float(e("TLS_TIMEOUT", 5)),
            http_timeout=float(e("HTTP_TIMEOUT", 6)), total_timeout=float(e("ANALYSIS_TOTAL_TIMEOUT", 20)),
            max_redirects=int(e("HTTP_MAX_REDIRECTS", 5)), max_body_bytes=int(e("HTTP_MAX_BODY_BYTES", 1_000_000)),
            rdap_enabled=e("RDAP_ENABLED", "true").lower() != "false", dnsbl_zones=_csv("DNSBL_ZONES"),
            blocklist_path=e("BLOCKLIST_PATH") or None, ml_weight=float(e("RISK_ML_WEIGHT", 0.4)), max_concurrent=int(e("ANALYSIS_MAX_CONCURRENT", 8)),
        )
