# Training data

The service trains from **one CSV file**. No real dataset ships with this repository.
`sample/synthetic_urls.csv` is **synthetic** (hand-written URL templates, `source=synthetic`). It exists only to prove the
pipeline runs. Any metric computed on it says **nothing** about real-world detection quality.

## CSV schema

| Column | Required | Type | Description |
|---|---|---|---|
| `url` | yes | text | Full URL (`http://` / `https://`; a missing scheme is allowed). Max 2048 chars, no whitespace. |
| `label` | yes | text/int | `1`, `phishing`, `phish`, `malicious`, `bad` -> phishing.  `0`, `legitimate`, `legit`, `benign`, `good` -> legitimate. Anything else is an error. |
| `source` | no | text | Provenance (e.g. `phishtank`, `tranco`). If every row says `synthetic`, the run is flagged as synthetic in all outputs. |
| *security columns* | no | number/bool | Any of: `domain_age_days`, `whois_privacy`, `dns_resolves`, `nameserver_count`, `tls_valid`, `tls_cert_age_days`, `tls_hostname_match`, `redirect_count`, `has_login_form`, `has_password_field`, `external_form_action`, `iframe_count`, `hidden_element_count`, `has_suspicious_scripts`, `threat_feed_hits`. Booleans as `0/1`. Blank = unknown. |

Rules applied on load (and reported at training time): blank / non-http(s) / unparsable URLs are dropped; a URL that appears
with **conflicting labels** is dropped entirely; exact duplicates are removed; unparsable security values become "unknown".
Training requires both classes and at least 200 usable rows.

Security columns that are **empty for the whole training split** are excluded from the model (listed in
`metadata.json -> dropped_features`), so an URL-only dataset gives a purely URL-based model.

## Building a real dataset (recommendations)

* Phishing: verified phishing URLs from PhishTank / OpenPhish (check each feed's licence and terms).
* Legitimate: a popular-domain list such as Tranco **plus real URLs with paths and query strings**. If legitimate rows are bare
  domains while phishing rows have long paths, the model learns "has a path", not "is phishing".
* Keep URLs that are **live at the same time** for both classes, and prefer a **time-based** hold-out (train on older, test on newer):
  phishing campaigns change quickly, so a random split overstates future accuracy.
* The default split is grouped by registered domain, so URLs of one site never appear in both train and test.
* Security columns must be collected with the same methods the Node backend uses at inference time, or the model will see a distribution it was not trained on.
