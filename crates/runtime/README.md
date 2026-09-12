# truent-runtime

Live, non-exploitative checks of a target you are authorized to test. This is
the one Truent crate that connects to a running system instead of reading
files, and the only one whose findings are marked **proven** — each records
something observed on the wire.

```
truent probe https://example.com --authorized
```

| Check | Findings |
|---|---|
| TLS handshake and leaf certificate | `rt_tls_expired`, `rt_tls_untrusted_cert`, `rt_tls_weak_protocol` |
| HTTP response headers and cookies | `rt_missing_hsts`, `rt_missing_csp`, `rt_missing_frame_options`, `rt_missing_content_type_options`, `rt_insecure_cookie`, `rt_server_banner`, `rt_no_https_redirect` |
| Files that must never be served | `rt_exposed_sensitive_path` (confirmed by content signature, never by status alone) |
| TCP connect sweep of 20 common ports | `rt_open_port` |

## What it sends

`GET` requests and TCP connects — the traffic a browser and `curl -I` produce.
No payloads, no authentication attempts, no writes. A certificate that fails
verification is read on a second, verification-disabled handshake so the
report can say *why*; no application data crosses that connection. Cookie
values and file bodies are never recorded — evidence is names, attributes,
sizes and signatures.

## What it refuses

To run without `--authorized`. Port scanning and path probing of systems you
do not own or have written permission to test is illegal in most
jurisdictions; the flag is your assertion, and the refusal is the default.

## Structure

Every check is an *observation* struct produced by the network layer and a
pure *evaluator* from observation to findings. The evaluators are what the
tests cover, offline, so the behaviour is fixed without a live target.
