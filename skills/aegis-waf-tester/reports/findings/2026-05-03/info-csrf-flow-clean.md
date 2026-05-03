---
id: 2026-05-03-info-csrf-flow-clean
date: 2026-05-03T17:46Z
severity: INFO
area: admin-api
component: csrf / mutation
status: open
test_mode: full-qc
---

# CSRF double-submit flow + blacklist enforcement: clean pass

## Summary
Phase 3 ran end-to-end against `/api/blacklist`:

| Case | Status | Reason | Body |
|---|---|---|---|
| Valid CSRF (header == cookie) | 201 | n/a | `{"entry":{…full row…},"ok":true,"request_id":…}` |
| Missing `X-CSRF-Token` | 403 | `csrf_missing_header` | `{"message":"missing X-CSRF-Token header","ok":false,"reason":"csrf_missing_header"}` |
| Mismatched header | 403 | `csrf_mismatch` | `{"message":"csrf header does not match cookie","ok":false,"reason":"csrf_mismatch"}` |

Enforcement check:

```bash
# After valid POST registering 203.0.113.99 …
$ curl -i -H "X-Forwarded-For: 203.0.113.99" "http://127.0.0.1:8080/"
HTTP/1.1 403 Forbidden
x-waf-rule-id: blacklist
{"error":"forbidden","reason":"blocked by blacklist"}
```

Cleanup `DELETE /api/blacklist/qa-test` returned 200; the
follow-up `GET /api/blacklist` reads `entries: []`.

Filing as INFO so the run record shows what *did* work — Phase 3
is the one phase with no findings against it.

One side observation worth verifying separately (didn't open a
finding because I'm not sure if it's intentional): after the
`csrf_mismatch` test posted from the browser, my admin tab showed
the login page on next navigate. `/api/admin/sessions` confirmed
the session was no longer valid until I re-`POST /admin/login`'d.
That could be intentional (treat CSRF mismatch as "session
poisoned, force re-auth") or an unrelated coincidence — flagging
for someone who knows the auth design to confirm.

## Repro
See SKILL.md Phase 3.

## Expected
201 / 403 csrf_missing_header / 403 csrf_mismatch.

## Actual
Same.

## Suggested fix
None — record what works.

## Severity rationale
INFO. Used as evidence the CSRF gate isn't drifting.
