"""Generates real X.509 certificates for tests (no openssl binary needed)."""
from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

UTC = dt.timezone.utc


def make_cert(cn="localhost", sans=("localhost",), days_valid=30, start_offset_days=-1, issuer=None, ca=False, ip_sans=(), org="Test Org"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)])
    issuer_name, signer = (issuer[0].subject, issuer[1]) if issuer else (subject, key)
    issuer_pub = issuer[0].public_key() if issuer else key.public_key()
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now + dt.timedelta(days=start_offset_days)).not_valid_after(now + dt.timedelta(days=start_offset_days + days_valid))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    names = [x509.DNSName(s) for s in sans] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ip_sans]
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return b.sign(signer, hashes.SHA256()), key


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def write_pair(directory: Path, cert, key, name="srv"):
    c, k = directory / f"{name}.pem", directory / f"{name}.key"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(c), str(k)
