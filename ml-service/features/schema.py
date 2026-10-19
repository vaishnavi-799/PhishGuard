"""Single source of truth for feature names. Training and serving both import from here."""
from __future__ import annotations

# Computed from the URL string alone (pure functions, no network access).
URL_FEATURES: list[str] = [
    "url_length", "hostname_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes", "num_digits",
    "num_at", "num_question", "num_ampersand", "num_equals", "num_percent",
    "digit_ratio", "letter_ratio",
    "subdomain_count", "hostname_num_hyphens", "hostname_digit_ratio", "host_vowel_ratio",
    "domain_name_length", "longest_host_label",
    "is_https", "has_port", "has_at_symbol", "is_ip_host", "has_punycode", "has_www",
    "is_shortener", "suspicious_tld",
    "path_depth", "num_query_params", "num_encoded_chars", "has_double_slash_in_path", "path_has_exec_extension",
    "url_entropy", "hostname_entropy", "path_entropy",
    "num_suspicious_keywords", "keywords_in_hostname", "keywords_in_path",
    "brand_in_host_not_domain", "brand_in_path_not_domain", "brand_lookalike_domain",
]

# OPTIONAL inputs produced by other analysis modules (WHOIS, TLS, page inspection, threat feeds).
# Missing values are passed to the model as NaN; both XGBoost and HistGradientBoosting handle that natively.
SECURITY_FEATURES: list[str] = [
    "domain_age_days", "whois_privacy", "dns_resolves", "nameserver_count",
    "tls_valid", "tls_cert_age_days", "tls_hostname_match", "redirect_count",
    "has_login_form", "has_password_field", "external_form_action",
    "iframe_count", "hidden_element_count", "has_suspicious_scripts", "threat_feed_hits",
]

ALL_FEATURES: list[str] = URL_FEATURES + SECURITY_FEATURES

BINARY_FEATURES = {
    "is_https", "has_port", "has_at_symbol", "is_ip_host", "has_punycode", "has_www", "is_shortener", "suspicious_tld",
    "has_double_slash_in_path", "path_has_exec_extension", "brand_in_host_not_domain", "brand_in_path_not_domain",
    "brand_lookalike_domain", "whois_privacy", "dns_resolves", "tls_valid", "tls_hostname_match", "has_login_form",
    "has_password_field", "external_form_action", "has_suspicious_scripts",
}

_LABELS = {
    "url_length": "URL length", "hostname_length": "Hostname length", "num_dots": "Number of dots",
    "num_hyphens": "Number of hyphens", "digit_ratio": "Share of digits in URL", "subdomain_count": "Subdomain levels",
    "is_https": "Uses HTTPS", "is_ip_host": "IP address used as host", "is_shortener": "URL shortener",
    "suspicious_tld": "High-abuse top-level domain", "has_at_symbol": "'@' in URL", "has_punycode": "Punycode (xn--) host",
    "num_suspicious_keywords": "Suspicious keywords in URL", "keywords_in_hostname": "Suspicious keywords in hostname",
    "brand_in_host_not_domain": "Brand name in host but not the real domain", "brand_in_path_not_domain": "Brand name in path of a different domain",
    "brand_lookalike_domain": "Look-alike of a known brand domain", "url_entropy": "URL randomness (entropy)",
    "hostname_entropy": "Hostname randomness (entropy)", "domain_age_days": "Domain age (days)", "tls_valid": "Valid TLS certificate",
    "tls_cert_age_days": "TLS certificate age (days)", "redirect_count": "Redirect count", "has_password_field": "Password field on page",
    "has_login_form": "Login form on page", "external_form_action": "Form posts to another host", "threat_feed_hits": "Threat feeds flagging it",
    "path_depth": "Path depth", "num_query_params": "Query parameters", "num_encoded_chars": "Percent-encoded characters",
    "whois_privacy": "WHOIS privacy enabled", "dns_resolves": "Domain resolves in DNS", "has_suspicious_scripts": "Suspicious scripts on page",
}


def label(name: str) -> str:
    return _LABELS.get(name, name.replace("_", " ").capitalize())
