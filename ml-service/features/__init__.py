from .schema import ALL_FEATURES, SECURITY_FEATURES, URL_FEATURES, label
from .security_features import extract_security_features
from .url_features import InvalidUrlError, extract_url_features, parse_url, registered_domain


def extract_all(url: str, security: dict | None = None) -> dict[str, float]:
    """One row of model input: URL features + (optional) security features, in ALL_FEATURES order."""
    return {**extract_url_features(url), **extract_security_features(security)}
