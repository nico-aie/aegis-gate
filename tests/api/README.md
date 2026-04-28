# `tests/api/` — Admin-API smoke tests

Bash-based smoke tests for the security-toggle endpoints
(P1–P8) added to the control plane. They run against a live
admin listener and assert
1. the documented JSON shape on GET,
2. CSRF rejection on PUT without a token,
3. successful audit-mutated PUT round-trip.

## Prerequisites

- A running gateway (admin listener bound at
  `https://127.0.0.1:9443` by default).
- `curl` and `jq`.
- An admin account whose credentials are exported as
  `ADMIN_USER` and `ADMIN_PASS`.

```sh
export ADMIN_USER=admin
export ADMIN_PASS=$(cat /run/secrets/aegis_admin_pass)
```

## Layout

```
tests/api/
├── README.md            (this file)
├── _common.sh           login + CSRF helper sourced by every test
├── auth.sh              admin login + logout + CSRF reject (P1)
├── tls.sh               TLS minimum + security headers   (P4)
├── detectors.sh         GET / PUT /api/detectors          (P2 + P3)
├── risk.sh              GET /api/risk + PUT /api/risk/{ip}/reset (P6)
├── loadmode.sh          GET / PUT /api/loadmode           (P7)
├── logging.sh           GET / PUT /api/logging            (P8)
├── cold-tier.sh         GET /api/cold-tier                (P8)
├── acme.sh              Pebble reachability + directory shape (F-T7)
└── run-all.sh           bring-up + run every script + cleanup
```

## Running

```sh
# Run every script in dependency order
./tests/api/run-all.sh

# Or one at a time
./tests/api/detectors.sh
./tests/api/risk.sh        203.0.113.7
./tests/api/loadmode.sh
./tests/api/logging.sh
./tests/api/cold-tier.sh
```

Each script exits non-zero on any assertion failure; CI greps for
"FAIL" and breaks the build.

## What each script asserts

| Script | Asserts |
|---|---|
| `auth.sh` | bad password → 401, good login → 200 + sets aegis_session + aegis_csrf, authenticated GET works, mutation without CSRF header → 403, logout invalidates session. |
| `tls.sh` | TLS 1.0/1.1 rejected (where curl supports `--tls-max`), TLS 1.2/1.3 succeed, response carries HSTS + X-Content-Type-Options + X-Frame-Options + Referrer-Policy + Permissions-Policy. |
| `detectors.sh` | GET shape (`mask`, `overrides`, `locked_classes`), PUT without CSRF → 403, PUT with CSRF + valid body → 200, mask round-trip. |
| `risk.sh` | GET list shape (`total_tracked`, `clients`), GET unknown ip → 404, PUT reset clears state, PUT reset without CSRF → 403. |
| `loadmode.sh` | GET shape (`mode`, `effective_mode`, …), PUT pin → 200 + `override_active: true`, PUT `unset` → `override_active: false`. |
| `logging.sh` | GET ladder includes all 6 levels, PUT each level round-trips, unknown level → 400 with `validation` reason. |
| `cold-tier.sh` | GET enumerates configured sinks, splunk token never appears in response body. |
| `acme.sh` | Pebble directory reachable on `:14000`, advertises `newAccount` + `newOrder` + `newNonce`. |

## Notes

- Every script saves its cookie jar to `/tmp/aegis-cookies.jar`
  so the same session is reused across calls.
- The `_common.sh` helper logs in and exposes
  `${AEGIS_CSRF}` + `${AEGIS_COOKIES}` env vars.
- These tests are *idempotent*: each script restores the
  pre-existing state on exit (e.g. clears any override it set).
