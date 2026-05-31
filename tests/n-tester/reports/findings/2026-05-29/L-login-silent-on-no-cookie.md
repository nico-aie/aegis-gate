---
id: 2026-05-29-login-silent-on-no-cookie
date: 2026-05-29T19:50Z
severity: LOW
area: docs
component: tests/n-tester/_common.sh login()
status: open
test_mode: functional
---

# `login()` aborts silently when `Set-Cookie` is missing instead of failing loud

## Summary
`login()` in `_common.sh` does:
```sh
COOKIE="$(grep -i '^set-cookie: aegis_session=' "$resp_headers" \
          | sed -E 's/.*aegis_session=([^;]+).*/\1/' | tr -d '\r' | head -1)"
```
inside a `set -euo pipefail` script. If the login response has no
`Set-Cookie: aegis_session=…` line (e.g. because the server
returned `401`), grep exits 1, pipefail propagates 1 to the
command substitution, and `set -e` aborts the whole script
**before** the trailing guard `[[ -n "$COOKIE" && -n "$CSRF" ]] || fail "login: failed to capture cookies (body: …)"`
gets a chance to run.

Result: the very explicit error message the author meant to
print is unreachable, the test exits 1 with no output, and
debugging takes minutes longer than it should. This is exactly
what happened in the 2026-05-29 run — every nt-* test exited
silently on a 401 because the cluster YAML auth block is missing
(see `H-cluster-yaml-missing-dashboard-auth`).

## Repro
1. Start a node with no `dashboard_auth` (e.g. current
   `config/cluster-a.yaml`):
   `./target/release/waf run --config config/cluster-a.yaml &`
2. `source tests/n-tester/_common.sh`
3. `set -euo pipefail`
4. `login http://127.0.0.1:9443`
5. Observe: the script exits immediately with no FAIL message.
   The guarded `fail "login: failed to capture cookies (…)"` never
   runs.

## Expected
A loud, specific error: `FAIL: login: HTTP 401, body=…` so the
operator immediately sees that the issue is auth, not network or
config-watcher or anything else.

## Actual
Silent exit 1.

## Suggested fix
Restructure `login()` to capture the HTTP status separately and
fail loud before doing any cookie parsing:

```sh
login() {
  local admin_url="$1"
  local resp_headers body status
  resp_headers="$(mktemp)"
  body="$(curl --silent --insecure --max-time 5 \
       -D "$resp_headers" -o /dev/stdout \
       -w '%{http_code}' \
       -H 'content-type: application/json' \
       --data "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
       "$admin_url/admin/login")" || fail "login: curl failed"
  status="${body: -3}"; body="${body:0:-3}"
  [[ "$status" == "200" ]] || \
    fail "login: HTTP $status — body=${body:0:200}"
  COOKIE="$(grep -i '^set-cookie: aegis_session=' "$resp_headers" \
            | sed -E 's/.*aegis_session=([^;]+).*/\1/' \
            | tr -d '\r' | head -1)" || true
  CSRF="$(grep -i '^set-cookie: aegis_csrf=' "$resp_headers" \
            | sed -E 's/.*aegis_csrf=([^;]+).*/\1/' \
            | tr -d '\r' | head -1)" || true
  rm -f "$resp_headers"
  [[ -n "$COOKIE" && -n "$CSRF" ]] \
    || fail "login: HTTP $status but no aegis_session/aegis_csrf cookies in response"
}
```

Note the `|| true` after each grep — that's what defeats
pipefail. Combined with the `H-cluster-yaml-missing-dashboard-auth`
fix (so login actually 200s), the suite becomes diagnosable.

## Severity rationale
LOW. Same as the FAIL-to-stdout finding: diagnostic quality, not
correctness. But these two together (`_common.sh`'s silent-abort
pattern + runner only capturing stderr) cost real debugging time
on every CI failure that wasn't anticipated.
