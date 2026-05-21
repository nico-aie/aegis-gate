---
id: 2026-05-17-admin-listener-no-session-auth-gate
date: 2026-05-17T00:00Z
severity: CRITICAL
area: admin · auth chain
component: crates/aegis-proxy/src/accept.rs (admin service_fn) · crates/aegis-proxy/src/admin_dispatch.rs · crates/aegis-control/src/api/mutation.rs
interop_contract: Round 1 dashboard auth chain · audit-mutated CRUD
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-002 · Admin listener has NO session / IP-allow-list / capability check — every mutation handler is reachable to anyone on the admin port

## Summary

The admin listener's `service_fn` calls `handle_admin_request` with
the raw request and the peer address — but **with no authentication
gate at the listener edge**. Auth must therefore live inside each
mutation handler. It does not.

Each mutation handler extracts the CSRF cookie + `X-CSRF-Token`
header and validates them via `csrf::validate(cookie, header)` — but
`csrf::validate` only checks `cookie == header` (constant-time string
compare). It does NOT verify the cookie was issued by the server, NOT
linked to any session, NOT signed.

The "double-submit" CSRF pattern is meaningful ONLY when paired with
session authentication: a cross-origin attacker can't read the
victim's cookies, so they can't make their forged form submit a
matching header. But if there's NO session check, the attacker is
already the user — they send their own matching cookie+header from
their own machine and the WAF accepts the mutation.

**Spot-verified**:

1. [accept.rs:875-901](../../../../crates/aegis-proxy/src/accept.rs#L875-L901) — admin `service_fn` calls `handle_admin_request(req, peer, ...)` directly. No `auth_sessions.validate(session_cookie)` call. No IP-allow-list check.
2. [admin_dispatch.rs:60-101](../../../../crates/aegis-proxy/src/admin_dispatch.rs#L60-L101) — dispatcher routes by method+path, no auth call.
3. [admin_mutate.rs:1402-1475](../../../../crates/aegis-proxy/src/admin_mutate.rs#L1402-L1475) (representative `handle_loadmode_put`) — reads only CSRF cookie/header + `X-Actor`. Session cookie is NOT read.
4. [api/mutation.rs:200](../../../../crates/aegis-control/src/api/mutation.rs#L200) — `MutationRequest.apply()` calls `csrf_validate(req.csrf_cookie, req.csrf_header)` and otherwise trusts the request. Line 97 comment says "the proxy admin listener fills these in once it has authenticated the [user]" — but per (1) the listener does NOT authenticate.

## Endpoints reachable without authentication

Every entry in [admin_dispatch.rs:60-422](../../../../crates/aegis-proxy/src/admin_dispatch.rs#L60-L422) is open
except `/admin/drain` (which has its own `AEGIS_DRAIN_TOKEN` check —
see F-HIGH-admin for a separate timing issue there). Examples:

| Endpoint | What it does | Reachable to |
|---|---|---|
| `PUT /api/loadmode` | Pin/clear load mode | Anyone with CSRF cookie+header match |
| `POST /api/rules`, `PUT /api/rules/{id}`, `DELETE /api/rules/{id}` | Rule CRUD | Anyone |
| `PUT /api/detectors` | Detector mask change | Anyone |
| `PUT /api/upstreams/config` | Replace upstream pool | Anyone |
| `PUT /api/mtls/ca-bundle?apply=true` | Replace mTLS CA bundle | Anyone |
| `PUT /api/risk/{ip}/reset` | Clear risk score for any IP | Anyone |
| `PUT /api/risk/thresholds` | Change per-tier risk thresholds | Anyone |
| `GET /api/admin/sessions`, `/api/audit/since`, `/metrics`, `/api/config` | Read all admin state, sessions, audit chain, config | Anyone |

The CSRF cookie is generated and shipped on the login PAGE
([admin_dispatch.rs:79-84](../../../../crates/aegis-proxy/src/admin_dispatch.rs#L79-L84) — `GET /admin/login` and `/admin/login.js` are
unauthenticated). Per [csrf.rs:7-17](../../../../crates/aegis-control/src/admin_auth/csrf.rs#L7-L17) the cookie value is just
`blake3(clock_nanos+counter)[..32]` — but the attacker doesn't even
need to forge that: they can:

1. `GET /admin/login` → response sets `Set-Cookie: aegis_csrf=<value>`
2. Read that value from the response.
3. Send `PUT /api/loadmode` with `Cookie: aegis_csrf=<value>` +
   `X-CSRF-Token: <value>`. CSRF passes (`constant_time_eq` on equal
   bytes). No session check. Mutation lands. Audit entry says
   `actor = whatever they put in X-Actor` (see F-CRITICAL-004).

## Repro

```sh
HOST="http://127.0.0.1:9443"     # admin listener; same on TLS at :9443

# Step 1 — fetch a CSRF cookie unauthenticated:
csrf=$(curl -sk -c /tmp/jar -o /dev/null -D - "$HOST/admin/login" \
        | awk -F'[=;]' '/Set-Cookie: aegis_csrf=/ {print $2}')
echo "Got CSRF cookie: $csrf"

# Step 2 — call a mutation with that cookie:
curl -sk -X PUT "$HOST/api/loadmode" \
    -H "Cookie: aegis_csrf=$csrf" \
    -H "X-CSRF-Token: $csrf" \
    -H "X-Actor: attacker-anon" \
    -H "Content-Type: application/json" \
    -d '{"mode":"emergency"}'
# Expected (Round 1 dashboard auth chain): 401 / 403.
# Actual: 200 + load mode flipped to "emergency".

# Step 3 — verify audit chain attributes to "attacker-anon":
tail -1 ./waf_audit.log | jq '{actor, action}'
```

## Impact

- **Round 1 dashboard auth chain (Pass/Fail gate)** — explicit
  defense-in-depth was specified (IP allow-list → mTLS → argon2id
  → TOTP → HMAC cookie → CSRF → rate-limit). Of those seven layers
  the proxy enforces only "CSRF cookie matches CSRF header" — a
  layer that is meaningless without session auth in front of it.
  Round-1 will fail this criterion outright.
- **Audit chain integrity** — combined with F-CRITICAL-004, an
  anonymous attacker can leave durable, hash-chained NDJSON entries
  attributed to any operator name they choose.
- **Multi-tenant deployments** — any attacker that reaches the admin
  port (default `127.0.0.1:9443`, but operators expose this through
  load balancers in cluster deployments per the README) can take
  over the WAF.

## Suggested fix

Introduce a session-validation middleware at the admin listener
edge. The session machinery (`admin_auth/session.rs`) already
exists; just wire it.

```diff
 let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
     ...
     async move {
+        // Round-1 auth chain step 1: IP allow-list.
+        if !services.admin_auth.is_ip_allowed(peer.ip()) {
+            return Ok(forbidden_response("ip not allow-listed"));
+        }
+        // Step 5: HMAC session cookie validation. Open endpoints
+        // listed below are the only ones that don't require it.
+        let path = req.uri().path();
+        let is_open = matches!(
+            (req.method().as_str(), path),
+            ("POST", "/admin/login")
+              | ("POST", "/admin/logout")
+              | ("GET",  "/admin/login")
+              | ("GET",  "/admin/login.js")
+        ) || path.starts_with("/__waf_control/");   // §2.2 secret-gated
+        if !is_open {
+            let session = services.admin_auth.validate_session(&req);
+            if !session.is_valid() {
+                return Ok(unauthorized_response("login required"));
+            }
+            // Stamp authenticated identity into request extensions
+            // for downstream mutation handlers (see F-CRITICAL-004
+            // fix — actor comes from session, not X-Actor header).
+            req.extensions_mut().insert(session.identity());
+        }
+        if req.method() == hyper::Method::GET
             && req.uri().path() == "/dashboard/sse" { ... }
         let resp = handle_admin_request(...);
         ...
     }
 });
```

This belongs at the listener edge (single chokepoint) rather than
per-handler (35+ handlers to retrofit, easy to forget one).

## Verification

After the fix, the repro above should return `401 Unauthorized`
without a valid session cookie. With a valid session (obtained via
`POST /admin/login` with correct password + TOTP per F-CRITICAL-003),
the mutation should succeed and the audit chain should attribute
it to the session's identity.

Add a regression case in `tests/api/` for every mutation endpoint
asserting `401` without session.

## Severity rationale

CRITICAL. Defense-in-depth is required by the Round-1 spec. The
proxy enforces 1 of 7 specified layers, and that one layer is
meaningless without the others. Single deepest root cause behind
the Round-1 dashboard-auth failure.
