---
id: 2026-05-03-critical-ssrf-detector-blocks-all-traffic
date: 2026-05-03T17:36Z
severity: CRITICAL
area: data-plane
component: detector / ssrf
status: open
test_mode: full-qc
---

# SSRF detector fires on every request — clean `GET /` is blocked

## Summary
With dev defaults (`make run-dev`, `config/dev.yaml`), the SSRF
detector returns a positive on every inbound request — including
ones with empty paths, no query string, no body, and no URL-shaped
parameters. The data plane rejects everything with HTTP 403 and
`X-WAF-Rule-Id: detector:ssrf`. There is no usable allow-listing
short of disabling the detector outright. Any operator who runs
`make run-dev` and points a browser at the data plane will see
their first GET blocked, and any synthetic user / smoke test that
expects 200 / 502 (depending on upstream) instead lands on 403.

This also poisons every other dashboard page:

- **Top Attackers** ranks the dev browser's source IP at #1
  because every legitimate page-load the operator does shows up
  as 73+ "attacks."
- **Attack distribution** donut shows `ssrf` 59, `sqli,ssrf` 12,
  `xss,ssrf` 12, `ssrf,recon_path` 12 etc. — the detector is
  glued onto every other detector's hits, so the real distribution
  is unreadable.
- **Three legitimate IPs** I sent clean GETs through (1.0.0.1,
  9.9.9.10, 8.8.4.4) appear in Top Attackers with risk 100,
  detectors `ssrf`. The dashboard tells a SOC analyst these IPs
  are attacking — they're not.

## Repro
```bash
$ curl -i -H "X-Forwarded-For: 8.8.8.8" "http://127.0.0.1:8080/"
HTTP/1.1 403 Forbidden
x-waf-rule-id: detector:ssrf
…
{"error":"forbidden","reason":"…"}

$ curl -i -H "X-Forwarded-For: 8.8.8.8" "http://127.0.0.1:8080/api/users/100"
HTTP/1.1 403 Forbidden
x-waf-rule-id: detector:ssrf

$ curl -i -H "X-Forwarded-For: 8.8.8.8" "http://127.0.0.1:8080/favicon.ico"
HTTP/1.1 403 Forbidden
x-waf-rule-id: detector:ssrf
```

The dashboard's own browser hitting `/favicon.ico` on the data
plane (which happens whenever you point a tab at it) generates an
audit row with `detectors: ["ssrf"], path: /favicon.ico`. Real
SSRF probes (`/fetch?url=http://169.254.169.254/`) match too, but
so does everything else.

## Expected
SSRF should fire on requests whose URL or body contains an
identifiable internal-target indicator (IMDS host, internal CIDR,
file:// scheme, etc.). `GET /`, `GET /api/users/100`,
`GET /favicon.ico` should not match.

## Actual
Every request matches. The detection looks unconditional or
keyed on a pattern that's wider than the description in
`docs/security/detectors/README.md` would suggest.

## Suggested fix
Look at `crates/aegis-security/src/detectors/ssrf*.rs` (or the
matcher the SSRF detector mounts). The fast path is matching
something that universally hits — possibly a default-empty
allow-list compared backwards, a regex that compiled to `.*`, or
a fallthrough where the detector returns "match" instead of "no
match" when its pattern set is empty. Snapshot the bytes of the
detector inputs for the three repros above and look for the
common substring; whatever it is, that's the bug.

Sanity tests to add (or fix) once the detector is corrected:
1. `GET /` → no SSRF tag.
2. `GET /api/users/100` → no SSRF tag.
3. `GET /favicon.ico` → no SSRF tag.
4. `GET /fetch?url=http://169.254.169.254/` → SSRF tag.
5. `POST /` body `{"webhook":"http://10.0.0.1/"}` → SSRF tag.

## Severity rationale
CRITICAL. With dev defaults, the data plane is effectively
fail-closed — no legitimate traffic gets through. Worse, this
creates *false positives that look like real signal*: a SOC
analyst opening the dashboard sees their own legitimate traffic
flagged as attackers and would reach for the Block button on an
innocent IP. That's the Aegis-Gate failure mode that does the
most damage in production: blocking the wrong people because the
detector lied.
