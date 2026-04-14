# Benign Corpus — False-Positive Regression

Every sample in this directory is a **legitimate** HTTP request
that MUST NOT trigger any detector or rule. If a commit causes a
sample here to be blocked, the false-positive regression suite
fails and the PR is rejected.

## Format

One request per file, raw HTTP/1.1 on the wire (`\r\n` line endings),
named `NNN-<short-description>.http` where `NNN` is a zero-padded
sequence number starting from `001`.

Example — `001-user-profile-get.http`:

```
GET /api/users/42 HTTP/1.1
Host: example.com
Accept: application/json
User-Agent: Mozilla/5.0 ...

```

## Sourcing

- Real web traffic captures (anonymized — strip cookies, auth
  headers, PII in bodies, client IP).
- Public API test fixtures (Stripe, GitHub, Google APIs).
- Browser traces from common web apps (Gmail, YouTube, SPA apps).

## Classes Covered

The corpus should spread across these categories so regressions are
detected regardless of where a new false positive lands:

| Class                        | Target sample count |
|------------------------------|---------------------|
| Plain API GETs               | ≥ 50                |
| POST with JSON body          | ≥ 50                |
| POST with multipart upload   | ≥ 20                |
| Complex query strings        | ≥ 30                |
| Rich HTML form submissions   | ≥ 20                |
| WebSocket upgrade handshakes | ≥ 10                |
| gRPC-over-h2                 | ≥ 10                |

Total target: **≥ 200 samples** before the M2 T2.4 acceptance gate
is evaluated.

## Running the regression

```sh
./tests/security/run-corpus.sh benign
```

Exits non-zero if ANY request in this directory is blocked.
