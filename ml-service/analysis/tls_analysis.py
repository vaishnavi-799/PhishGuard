"""TLS certificate inspection. Network probing is separate from (pure, testable) certificate evaluation."""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "anon")
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TlsProbe:
    verified: bool = False
    verify_error: str | None = None
    der: bytes | None = None
    version: str | None = None
    cipher: str | None = None
    error: str | None = None


def probe(host: str, port: int, ip: str, timeout: float, server_name: str | None, cafile: str | None = None) -> TlsProbe:
    """Handshake against a pre-validated IP. First verified; if verification fails, again unverified just to read the certificate."""
    out = TlsProbe()
    for verify in (True, False):
        ctx = ssl.create_default_context(cafile=cafile)
        if not verify:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=server_name) as s:
                    out.der, out.version = s.getpeercert(binary_form=True), s.version()
                    c = s.cipher()
                    out.cipher = c[0] if c else None
                    out.verified = verify
                    return out
        except ssl.SSLCertVerificationError as e:
            out.verify_error = getattr(e, "verify_message", None) or str(e)[:120]
            continue
        except (ssl.SSLError, OSError) as e:
            # A TCP connect timeout means the TLS endpoint could not complete
            # a handshake. Preserve explicit timeout handling at the engine
            # boundary, while probe callers receive the stable handshake error.
            out.error = "tls_handshake_failed"
            return out
    return out


def hostname_matches(host: str, sans: list[str]) -> bool:
    """RFC 6125 matching: a wildcard is only valid as the whole left-most label and never spans dots."""
    host = host.lower().rstrip(".")
    for pat in sans:
        pat = pat.lower().rstrip(".")
        if pat == host:
            return True
        if pat.startswith("*.") and host.count(".") == pat.count(".") and "*" not in pat[2:]:
            if host.split(".", 1)[1] == pat[2:]:
                return True
    return False


def _utc(cert, attr):
    v = getattr(cert, attr + "_utc", None)
    return v if v is not None else getattr(cert, attr).replace(tzinfo=timezone.utc)


def _name(cert_name, oid):
    a = cert_name.get_attributes_for_oid(oid)
    return a[0].value if a else None


def evaluate_certificate(der: bytes, host: str, pr: TlsProbe, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    cert = x509.load_der_x509_certificate(der)
    nb, na = _utc(cert, "not_valid_before"), _utc(cert, "not_valid_after")
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    cn = _name(cert.subject, NameOID.COMMON_NAME)
    names = sans or ([cn] if cn else [])  # CN is only consulted when there is no SAN extension
    is_ip = _is_ip(host)
    if is_ip:
        try:
            ip_sans = {str(i) for i in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)}
        except x509.ExtensionNotFound:
            ip_sans = set()
        match = _norm_ip(host) in ip_sans
    else:
        match = hostname_matches(host, names)
    expired, not_yet = na < now, nb > now
    self_signed = cert.issuer == cert.subject
    weak_cipher = bool(pr.cipher and any(m in pr.cipher for m in WEAK_CIPHER_MARKERS))
    weak_proto = pr.version in WEAK_PROTOCOLS
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    valid = bool(pr.verified and not expired and not not_yet and match)
    f = []
    if expired:
        f.append({"id": "cert_expired", "severity": "high", "detail": f"Certificate expired on {na.date()}"})
    if not_yet:
        f.append({"id": "cert_not_yet_valid", "severity": "high", "detail": f"Certificate valid from {nb.date()}"})
    if not match:
        f.append({"id": "hostname_mismatch", "severity": "high", "detail": f"Certificate does not cover {host}"})
    if self_signed:
        f.append({"id": "self_signed", "severity": "medium", "detail": "Self-signed certificate"})
    if not pr.verified and not self_signed and pr.verify_error:
        f.append({"id": "untrusted_chain", "severity": "medium", "detail": f"Chain not trusted: {pr.verify_error}"})
    if (now - nb).days < 7 and not expired:
        f.append({"id": "cert_very_new", "severity": "low", "detail": f"Certificate issued {(now - nb).days} day(s) ago"})
    if weak_cipher or weak_proto:
        f.append({"id": "weak_tls", "severity": "medium", "detail": f"{pr.version} / {pr.cipher}"})
    if sig in ("md5", "sha1"):
        f.append({"id": "weak_signature", "severity": "medium", "detail": f"Signature hash {sig}"})
    return {
        "certificate_valid": valid, "chain_trusted": pr.verified, "verify_error": pr.verify_error,
        "issuer": {"organization": _name(cert.issuer, NameOID.ORGANIZATION_NAME), "common_name": _name(cert.issuer, NameOID.COMMON_NAME)},
        "subject_common_name": cn, "san_count": len(sans), "san_sample": sans[:5],
        "issued_at": nb.isoformat(), "expires_at": na.isoformat(), "days_until_expiry": (na - now).days, "age_days": max(0, (now - nb).days), "validity_days": (na - nb).days,
        "expired": expired, "not_yet_valid": not_yet, "self_signed": self_signed, "hostname_match": bool(match),
        "tls_version": pr.version, "cipher": pr.cipher, "weak_cipher": weak_cipher or weak_proto, "signature_hash": sig, "findings": f,
    }


def _norm_ip(h: str) -> str:
    import ipaddress
    return str(ipaddress.ip_address(h))


def _is_ip(h: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def analyze_tls(scheme: str, host: str, port: int | None, *, cfg, resolver, prober=probe, now: datetime | None = None) -> dict:
    if scheme != "https":
        return {"status": "ok", "https": False, "certificate_valid": None, "hostname_match": None, "issuer": None, "expires_at": None,
                "findings": [{"id": "no_https", "severity": "medium", "detail": "The URL does not use HTTPS"}]}
    port = port or 443
    rs = resolver(host, port, cfg.allow_private_targets)
    if rs.blocked or not rs.ips:
        return {"status": "failed", "https": True, "error": rs.blocked or rs.error or "unresolvable", "findings": []}
    pr = prober(host, port, rs.ips[0], cfg.tls_timeout, None if _is_ip(host) else host)
    if not pr.der:
        return {"status": "failed", "https": True, "error": pr.error or "no_certificate", "verify_error": pr.verify_error,
                "findings": [{"id": "tls_unavailable", "severity": "medium", "detail": f"TLS handshake failed ({pr.error or pr.verify_error})"}]}
    try:
        return {"status": "ok", "https": True, **evaluate_certificate(pr.der, host, pr, now)}
    except Exception:  # malformed certificate from a hostile server
        return {"status": "failed", "https": True, "error": "certificate_parse_failed", "findings": []}
