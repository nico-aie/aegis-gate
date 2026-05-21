---
id: 2026-05-17-audit-actor-spoofable-via-x-actor-header
date: 2026-05-17T00:00Z
severity: CRITICAL
area: admin · audit chain · attribution
component: crates/aegis-proxy/src/admin_mutate.rs (every mutation handler) · crates/aegis-control/src/api/mutation.rs (MutationRequest.actor)
interop_contract: v2.3 §6 (audit chain integrity) · Round 1 audit-mutated CRUD attribution
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-004 · Audit-chain `actor` field is taken verbatim from the client-supplied `X-Actor` request header — anyone can impersonate any operator

## Summary

Every mutation handler in `admin_mutate.rs` populates the audit
entry's `actor` field by reading the `X-Actor` request header verbatim,
defaulting to the literal string `"admin"` when the header is absent.
Combined with F-CRITICAL-002 (no session check at the listener
edge), this means **an anonymous attacker who calls a mutation
endpoint chooses what name appears in the durable, hash-chained
audit log**.

The Round-1 contract requires "audit-mutated CRUD" — every config
change goes through the audit chain with attribution. v2.3 §6 lists
audit log as "evidence cho BTC-side correlation". Both rely on
`actor` being trustworthy.

**Spot-verified** at [admin_mutate.rs:1420-1425](../../../../crates/aegis-proxy/src/admin_mutate.rs#L1420-L1425) (`handle_loadmode_put`):

```rust
let actor = req
    .headers()
    .get("x-actor")
    .and_then(|h| h.to_str().ok())
    .unwrap_or("admin")
    .to_string();
```

The same pattern repeats across every mutation handler in
`admin_mutate.rs` (3546 lines, ~35 handlers). The `MutationRequest`
struct in `api/mutation.rs` then takes `actor: &str` and stamps it
into the audit chain.

## Observed code path

`crates/aegis-proxy/src/admin_mutate.rs:1420-1425` (handler-level capture):

```rust
let actor = req
    .headers()
    .get("x-actor")
    .and_then(|h| h.to_str().ok())
    .unwrap_or("admin")
    .to_string();
```

`crates/aegis-control/src/api/mutation.rs:188-226` (`MutationRequest.apply()`):

```rust
pub struct MutationRequest<'a> {
    pub method: &'a str,
    pub csrf_cookie: Option<&'a str>,
    pub csrf_header: Option<&'a str>,
    pub actor: &'a str,                  // ← stamped into audit entry
    pub request_id: &'a str,
    pub resource: &'a str,
    pub action: &'a str,
    pub reason: &'a str,
}

impl<'a> MutationRequest<'a> {
    pub fn apply(...) -> Result<...> {
        if requires_csrf(self.method) {
            match csrf_validate(self.csrf_cookie, self.csrf_header) {
                CsrfResult::Valid => (),
                _ => return Err(MutationError::Csrf(...)),
            }
        }
        // Audit entry attribution:
        audit_chain.append(AuditEntry {
            actor: self.actor.to_string(),    // ← unchecked
            ...
        });
        ...
    }
}
```

No validation against the session, the IP, or any server-side
identity store.

## Repro

(Builds on the F-CRITICAL-002 repro — open admin port + CSRF cookie
mintable via `GET /admin/login`.)

```sh
HOST="http://127.0.0.1:9443"
csrf=$(curl -sk -c /tmp/jar -o /dev/null -D - "$HOST/admin/login" \
        | awk -F'[=;]' '/Set-Cookie: aegis_csrf=/ {print $2}')

# Impersonate "ceo@example.com":
curl -sk -X PUT "$HOST/api/loadmode" \
    -H "Cookie: aegis_csrf=$csrf" \
    -H "X-CSRF-Token: $csrf" \
    -H "X-Actor: ceo@example.com" \
    -H "Content-Type: application/json" \
    -d '{"mode":"emergency"}'

# Inspect the audit chain:
tail -1 ./waf_audit.log | jq '{actor, action, resource, request_id}'
# {
#   "actor":      "ceo@example.com",       ← FORGED
#   "action":     "loadmode_set",
#   "resource":   "/api/loadmode",
#   "request_id": "..."
# }
```

## Impact

- **§6 audit chain integrity** — the chain is hash-chained for
  tamper-evidence, but tamper-evidence is irrelevant when the
  attacker can write anything they want INTO the chain in the first
  place. The chain only guarantees "this entry was written by the
  WAF at time T"; it doesn't guarantee "this entry truly attributes
  to the named operator".
- **Round 1 audit-mutated CRUD** — the contract's intent is
  operator-attributable changes. This bug defeats attribution
  wholesale.
- **Forensic value collapses** — incident response after a real
  breach cannot rely on the audit log to identify the attacker.
  Worse, an attacker can frame a legitimate operator by stamping
  their name on malicious changes.
- **Compliance modes (PCI / HIPAA / SOC 2)** that the README
  advertises depend on durable, attributable audit trails. This
  bug breaks the assumption directly.

## Suggested fix

Take the `actor` from the authenticated session (per F-CRITICAL-002's
session middleware), not from a client header.

Step 1 — F-CRITICAL-002's middleware stamps the session identity
into request extensions:

```rust
req.extensions_mut().insert(session.identity());   // SessionIdentity
```

Step 2 — mutation handlers read from extensions, not headers:

```diff
-let actor = req
-    .headers()
-    .get("x-actor")
-    .and_then(|h| h.to_str().ok())
-    .unwrap_or("admin")
-    .to_string();
+let actor = req
+    .extensions()
+    .get::<SessionIdentity>()
+    .map(|s| s.username().to_string())
+    .ok_or_else(|| MutationError::Internal(
+        "actor not set — auth middleware misconfigured".into()
+    ))?;
```

If you keep an explicit `X-Actor` header for any reason (e.g. for
admins acting on behalf of other operators via a "su" capability),
the value MUST be validated against the session's
authorise-as-other capability and the audit entry MUST record both
the acting session identity AND the "on behalf of" identity.

Cross-cut: this fix is meaningless without F-CRITICAL-002. Land
them in the same PR.

## Verification

After the fix:

```sh
# Logged-in session — actor in chain is the session's user:
curl -sk -X PUT "$HOST/api/loadmode" \
    -H "Cookie: aegis_session=<valid>; aegis_csrf=<valid>" \
    -H "X-CSRF-Token: <valid>" \
    -H "X-Actor: ceo@example.com" \         # IGNORED
    -d '{"mode":"emergency"}'

tail -1 ./waf_audit.log | jq .actor
# "admin"      ← from session, NOT from X-Actor

# Without session — endpoint rejects (per F-CRITICAL-002 fix):
curl -sk -X PUT "$HOST/api/loadmode" \
    -H "Cookie: aegis_csrf=<valid>" \
    -H "X-CSRF-Token: <valid>" \
    -H "X-Actor: ceo@example.com" \
    -d '{"mode":"emergency"}'
# Expect 401.
```

Add a regression case in `tests/api/`:

```sh
# Assert X-Actor header is NOT reflected into the audit chain when
# the session identity differs.
```

## Severity rationale

CRITICAL. Single-line bug that defeats the entire purpose of the
audit chain. v2.3 §6 + Round-1 audit-mutated CRUD both depend on
trustworthy attribution. Trivial exploit (1 HTTP header). Trivial
fix (one substitution per handler, or one middleware-set value).
