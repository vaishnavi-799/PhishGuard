"""Fake network services for engine tests."""
from __future__ import annotations

import time

from analysis.dns_wire import DnsError, DnsResponse, Record
from analysis.engine import Services
from analysis.http_fetch import FetchResult


def dns_response(rcode, *records):
    return DnsResponse(1, rcode, False, list(records))


class FakeDns:
    def __init__(self, a=("93.184.216.34",), ns=("ns1.example.net",), nxdomain=False, raises=None):
        self.a, self.ns, self.nx, self.raises, self.calls = a, ns, nxdomain, raises, []

    def query(self, name, qtype):
        self.calls.append((name, qtype))
        if self.raises:
            raise self.raises
        if qtype == "A":
            return dns_response(3) if self.nx else dns_response(0, *[Record(name, "A", 3600, ip) for ip in self.a])
        if qtype == "NS":
            return dns_response(0, *[Record(name, "NS", 3600, n) for n in self.ns])
        return dns_response(0)


class FakeRdap:
    def __init__(self, age_days=3000, available=True):
        self.age, self.available, self.calls = age_days, available, []

    def lookup(self, domain):
        self.calls.append(domain)
        if not self.available:
            return {"available": False, "error": "rdap_unavailable"}
        return {"available": True, "age_days": self.age, "registrar": "Example Registrar", "privacy_redacted": False, "registered_at": "2020-01-01T00:00:00+00:00", "expires_at": None, "statuses": [], "nameservers": [], "source": "rdap"}


class FakeFetcher:
    def __init__(self, html=b"<title>Hello</title>", sleep=0.0, results=None, **kw):
        self.html, self.sleep, self.kw, self.calls, self.results = html, sleep, kw, [], list(results or [])

    def fetch(self, url, **_):
        self.calls.append(url)
        if self.sleep:
            time.sleep(self.sleep)
        if self.results:
            return self.results.pop(0)
        return FetchResult(url=url, final_url=url, status=200, content_type="text/html", body=self.html, headers={"content-type": "text/html"}, **self.kw)


def valid_tls(age_days=200, valid=True):
    return lambda scheme, host, port: ({"status": "ok", "https": True, "certificate_valid": valid, "chain_trusted": valid, "hostname_match": True, "issuer": {"organization": "Test CA", "common_name": "Test CA"},
                                         "expires_at": "2027-01-01T00:00:00+00:00", "age_days": age_days, "tls_version": "TLSv1.3", "weak_cipher": False, "findings": []}
                                        if scheme == "https" else {"status": "ok", "https": False, "certificate_valid": None, "hostname_match": None, "issuer": None, "expires_at": None,
                                                                   "findings": [{"id": "no_https", "severity": "medium", "detail": "The URL does not use HTTPS"}]})


def services(dns=None, rdap=None, fetcher=None, tls=None):
    return Services(dns=dns or FakeDns(), rdap=rdap or FakeRdap(), fetcher=fetcher or FakeFetcher(), tls=tls or valid_tls())
