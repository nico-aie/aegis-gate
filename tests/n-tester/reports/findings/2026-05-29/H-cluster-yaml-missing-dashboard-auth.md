---
id: 2026-05-29-cluster-yaml-missing-dashboard-auth
date: 2026-05-29T19:50Z
severity: HIGH
area: docs
component: config/cluster-a.yaml, config/cluster-b.yaml
status: open
test_mode: functional
---

# Cluster YAML fixtures are missing `admin.dashboard_auth`; entire `tests/n-tester/` suite is unrunnable

## Summary
`config/cluster-{a,b}.yaml` declare only `admin.bind:` but no
`admin.dashboard_auth.password_hash_ref` or `csrf_secret_ref`.
Result: every `POST /admin/login` against either node returns
`401 invalid_credentials`. Every shell test in `tests/n-tester/`
calls `login` immediately after `start_cluster`, so every test
fails at the same point and the new cluster-config-plane +
AI-confidence features cannot be verified at all. UI playbooks
NT-UI-01..07 are equally blocked because Chrome login goes
through the same endpoint.

## Repro
1. `cd /Users/nico/waf-code/aegis-gate`
2. Clean redis: `docker rm -f aegis-redis aegis-cluster-redis 2>/dev/null`
3. `pkill -f 'target/release/waf' 2>/dev/null; sleep 1`
4. `./target/release/waf run --config config/cluster-a.yaml > /tmp/manual-a.log 2>&1 &`
5. `until curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9443/healthz/ready | grep -q 200; do sleep 0.3; done`
6. `curl -i -s -X POST -H 'content-type: application/json' \
        --data '{"user":"admin","password":"aegis-test-1234"}' \
        http://127.0.0.1:9443/admin/login`

## Expected
`HTTP/1.1 200 OK` with `Set-Cookie: aegis_session=…` and
`Set-Cookie: aegis_csrf=…` headers (matches the dev.yaml
behaviour the README documents and the `tests/n-tester/README.md`
ADMIN_PASS comment promises).

## Actual
```
HTTP/1.1 401 Unauthorized
content-type: application/json; charset=utf-8
cache-control: no-store
content-length: 82
date: Fri, 29 May 2026 19:50:26 GMT

{"message":"user or password incorrect","ok":false,"reason":"invalid_credentials"}
```

Downstream effect, from `tests/n-tester/reports/run-20260529T194211Z.json`:
```
total=12  pass=1  fail=11  skip=0
```
All 11 failures: rc=1, `stderr_tail=""`, duration ~10-12s.
The single "pass" is nt-11 which exited 0 with a `SKIP:` line
(see related finding `L-run-all-skip-bookkeeping`). The pass count
excludes skipped tests is undercounted in nt-tester; verified by
adding `set -x` and observing the script aborting inside `login()`
on `grep -i '^set-cookie: aegis_session='` returning no matches.

## Suggested fix
Copy the `dashboard_auth:` subtree from `config/dev.yaml:392-440`
into both `config/cluster-a.yaml` and `config/cluster-b.yaml`,
under each file's existing `admin:` block. Keep each file's
distinct `bind:` (`127.0.0.1:9443` vs `127.0.0.1:9543`). Same
argon2 hash, csrf secret, and ip_allowlist are fine for dev — the
files already carry a "test harness only" warning. After patching,
re-run `tests/n-tester/run-all.sh`; the auth wall should disappear
and the actual cluster-plane assertions get a chance to run.

Patch sketch (apply to both files, identical block):

```yaml
admin:
  bind: "127.0.0.1:9443"          # 9543 in cluster-b.yaml
  dashboard_auth:
    password_hash_ref: '$argon2id$v=19$m=19456,t=2,p=1$DfRgVNq6Cb+eN3BEMmExAQ$69SVZBNpMFjN4evfN8g+U5jnmP56Gwx3AGaZFr32ZzY'
    csrf_secret_ref:   "test-csrf-secret-do-not-use-in-production-32b"
    session_ttl_idle:     "30m"
    session_ttl_absolute: "8h"
    ip_allowlist: ["127.0.0.1/32", "::1/128"]
    totp_enabled: false
    login_rate_limit:
      per_ip:   { limit: 100, window: "1m" }
      per_user: { limit: 200, window: "15m" }
    lockout:
      threshold: 50
      window: "15m"
      duration: "5m"
```

## Severity rationale
HIGH, not CRITICAL: it is a missing-config issue in test fixtures,
not a security vulnerability or a runtime defect in the WAF
itself. But it blocks 100% of the new-feature regression coverage
(both the cluster config plane and the AI-confidence track), so
release readiness can't be assessed until it's fixed.
