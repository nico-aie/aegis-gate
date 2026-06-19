---
id: 2026-06-19-admin-login-redirect-loop
date: 2026-06-19T00:00Z
severity: CRITICAL
area: admin-api
component: admin-auth / session-validation (cluster)
status: open
test_mode: smoke
target: http://18.140.47.62:9443/
---

# Admin login succeeds (200) but every authenticated request 401s → infinite login-redirect loop

## Summary
On the deploy at `http://18.140.47.62:9443/`, `POST /admin/login` with the
correct credentials returns **200 `{"ok":true}`** and sets the cookies — but
**every** subsequent `/api/*` request returns **401 `admin_unauthenticated`**
(*"missing or invalid session cookie / bearer token"*). The SPA sees the 401s
and bounces back to `/admin/login?next=/dashboard/`, so the operator can never
get past the login screen even though the password is right. Reproduced
deterministically: **10/10 login→`/api/about` cycles failed.**

This is a complete lockout of the admin/control plane → CRITICAL.

## Repro
From a browser tab on the deploy (in-page `fetch`, cookies attached):

```js
// 1. Login — succeeds.
await fetch("/admin/login", {method:"POST", credentials:"include",
  headers:{"content-type":"application/json"},
  body: JSON.stringify({user:"admin", password:"aegis-hackathon-2026"})});
//   → 200  {"ok":true,"user":"admin","session_idle_seconds":1800}

// 2. Immediately hit a protected endpoint in the same context.
await fetch("/api/about", {credentials:"include"});
//   → 401  {"ok":false,"reason":"admin_unauthenticated",
//            "detail":"missing or invalid session cookie / bearer token"}

// 3. Loop it 10x → 0 successes, 10 × 401.
```

Network trace of the UI flow confirms it: `POST /admin/login` → 200, redirect to
`/dashboard/`, SPA fires ~20 `/api/*` calls → **all 401**, SPA redirects to
`/admin/login?next=%2Fdashboard%2F`.

## Expected
After a 200 login, the issued `aegis_session` cookie validates on subsequent
admin requests and the dashboard loads.

## Actual
`aegis_session` is issued at login but rejected on every following request.
Evidence gathered while narrowing the cause:

- **Credentials are correct** — login returns 200 `ok:true` (password/argon2 +
  rate-limit all pass). Not a credential problem.
- **Cookies are being stored over HTTP** — `document.cookie` shows a fresh
  `aegis_csrf=…` after login, and the deploy sets `AEGIS_INSECURE_COOKIES=1`
  (compose/Dockerfile env), so both cookies are emitted **without** `Secure`.
  → This is **not** a "Secure cookie dropped over plain HTTP" problem.
- **State backend is up** — `/healthz/ready` reports
  `checks.state_backend_up: true` (live Redis health). (It also reports
  `status: degraded`, `config_store_degraded: true`, `active_rule_count: 0`,
  but that's the *config-polling* signal, separate from the session store.)
- **Failure is 100% deterministic** (10/10), which rules out a *random*
  round-robin race where some requests happen to land on the minting node.

The login path and the gate are wired to the **same** `services.auth_sessions`
store (`crates/aegis-control/src/api/login.rs::authenticate` →
`sessions.create`, validated by
`crates/aegis-proxy/src/admin_auth_middleware.rs::try_session_auth` →
`sessions.validate`), and the HMAC/TTL logic round-trips correctly in-process.
So a freshly-minted cookie failing validation **100% of the time** means the
validating context is **not the same context that minted it** — i.e. a
cross-node session-portability break in the cluster.

## Root cause (most likely)
The admin plane is a **2-node WAF cluster behind a load balancer with no session
stickiness**:

- `deploy/haproxy/haproxy.cfg` → `backend cluster_http` uses
  `balance leastconn` across `waf-a` and `waf-b` with **no `cookie` directive
  and no stick-table** on `aegis_session`. Admin `:9443` (`frontend in_tls`)
  feeds this backend.
- `deploy/HACKATHON-DEPLOY.md` confirms the prod topology is **2 WAF nodes
  (VM2/VM3) + shared Redis**, fronted by DNS-RR / LB.

For a load-balanced admin plane with no affinity, a session minted on node A
**must** validate on node B. That requires both:

1. **Identical session-signing key on every node.** The key is
   `blake3(csrf_secret_ref)`
   (`crates/aegis-proxy/src/accept.rs:433` → `derive_session_key`). The code's
   own boot warning (`accept.rs:406-418`) says it outright: *"in a multi-node
   deploy, MUST be identical on every node."* If the two VMs were brought up
   with **different (or one set / one unset) `csrf_secret_ref`** values, their
   HMAC keys differ → a cookie minted by node A fails the HMAC check on node B
   → `validate()` returns `None` → 401. The shared Redis record is even found;
   it's the signature that mismatches.
   *(Note: an **empty** secret derives a fixed key — same on all nodes — so the
   break specifically requires **non-identical non-empty** secrets across nodes.)*
2. **The same Redis on every node** for the `adminsess:*` records. If the nodes
   point at different Redis instances, `get_record` misses on the validating
   node.

With `balance leastconn`, consecutive requests alternate between nodes, so the
post-login `/api/*` calls land on the *other* node almost every time →
the observed deterministic 401 loop.

Secondary hardening issue regardless of the above:
`SessionStore::put_record` (`crates/aegis-control/src/admin_auth/session.rs:96`)
**swallows backend write errors** (`let _ = b.set(...).await;`). If a session
write ever fails, login still returns 200 + a cookie for a session that was
never stored, producing this exact loop with no error surfaced.

## How to confirm on the box (operator has shell; the tester does not)
Run these on the VMs, in order — they pinpoint which branch it is in seconds:

```bash
# 1. Are the two nodes signing with the SAME key? Compare the secret.
#    (whatever resolves cfg.admin.dashboard_auth.csrf_secret on each node)
ssh waf-a 'grep -A1 csrf_secret /etc/aegis/waf.yaml; env | grep -i CSRF'
ssh waf-b 'grep -A1 csrf_secret /etc/aegis/waf.yaml; env | grep -i CSRF'
#    → if they differ (or one is empty / one set) → that's the bug.

# 2. Watch the gate decide. Tail logs while doing one login + one /api/about.
docker compose logs -f waf-a waf-b | grep -iE 'admin:|csrf|session|unauth'
#    "CSRF rejected" vs a silent session miss tells you cookie-present-but-bad
#    vs cookie-missing.

# 3. Is the session actually landing in a SHARED Redis?
#    Log in once, then on the Redis box:
redis-cli KEYS 'adminsess:*'
#    EMPTY right after a login → put_record write is failing (or wrong Redis).
#    Present → record persists; the failure is the HMAC key mismatch (branch 1).

# 4. Confirm the LB has no session affinity (it doesn't, in the repo cfg):
grep -nE 'cookie|stick|balance' deploy/haproxy/haproxy.cfg
```

## Suggested fix
Primary — make sessions portable across the cluster (do both):

1. Set the **same** strong `cfg.admin.dashboard_auth.csrf_secret_ref`
   (≥32 random chars) on **every** node and restart. This is the documented
   requirement (`accept.rs:406-418`); the HACKATHON runbook's per-node env
   overlay section should call it out as a shared secret, not a per-node value.
2. Verify all nodes use the **same Redis** (`state.backend: redis`, same URL).

Mitigation / defense-in-depth:

3. Add session affinity at HAProxy as a backstop (stick-table on the
   `aegis_session` cookie, or a `cookie SRV insert` on `backend cluster_http`)
   so a session sticks to its minting node even if key sync regresses.
4. Stop swallowing write failures in `SessionStore::put_record`
   (`session.rs:96`): propagate/log the `b.set` error and fail the login
   (return 5xx) instead of issuing a cookie for an unstored session — so this
   class of bug surfaces loudly at login instead of as a silent redirect loop.
5. Consider a boot-time hard check (not just a `warn`) that refuses to start a
   cluster node with an empty/short `csrf_secret` when `state.backend != in_memory`.

## Severity rationale
CRITICAL: the entire admin / control plane is unreachable — no operator can log
in to the dashboard or admin API despite valid credentials. There is no
workaround from the UI. It blocks all dashboard-driven operation of the WAF.
