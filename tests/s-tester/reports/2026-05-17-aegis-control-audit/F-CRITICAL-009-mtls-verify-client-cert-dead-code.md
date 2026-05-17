---
id: 2026-05-17-mtls-verify-dead-code
date: 2026-05-17T00:00Z
severity: CRITICAL
area: admin auth chain · optional mTLS
component: crates/aegis-control/src/admin_auth/mtls.rs · crates/aegis-proxy/src/accept.rs (admin listener)
interop_contract: Round-1 dashboard auth chain step 2 ("optional mTLS")
status: open
test_mode: source-review (spot-verified via grep)
---

# F-CRITICAL-009 · `admin_auth/mtls.rs::verify_client_cert` is dead code — auth chain step 2 (optional mTLS) is library-only

## Summary

Round-1 dashboard auth chain spec names 7 defense-in-depth layers,
step 2 of which is "optional mTLS".

The function `admin_auth::mtls::verify_client_cert` is defined, with
allow-list logic (`check_ip_allowlist`), but **has zero production
callers**.

**Spot-verified** via `grep -rn "verify_client_cert" crates/`:

```
crates/aegis-control/src/admin_auth/mtls.rs:24:pub fn verify_client_cert(
crates/aegis-control/src/admin_auth/mtls.rs:76:        assert_eq!(verify_client_cert(&cfg, Some("admin")), MtlsResult::Disabled);
crates/aegis-control/src/admin_auth/mtls.rs:82-107: (more tests)
crates/aegis-control/tests/dod.rs:112,118:           (more tests)
```

Production callers: zero. Same for `check_ip_allowlist`.

`aegis-proxy/src/accept.rs:895` (admin listener service_fn) calls
`handle_admin_request` directly without invoking either function.
The TLS acceptor (lines 862-873) does the rustls handshake but
doesn't extract the client cert SAN and feed it to
`verify_client_cert`.

So an operator who sets `cfg.admin.mtls.enabled: true`:
- Sees the dashboard show "mTLS: required"
- Gets the rustls server config to optionally request client certs
- Has **NO enforcement** — clients without a cert (or with a cert
  whose SAN isn't in the allow-list) are not rejected

## Impact

- **Round-1 dashboard auth chain Pass/Fail** — step 2 is missing.
- **Combined with F-CRITICAL-002 in proxy audit** (no session check
  on admin listener), the dashboard has effectively no authentication.
- **Operator-facing risk** — operators reading
  `cfg.admin.mtls.enabled: true` in their config believe they have
  defense-in-depth; in reality, the chain has a gap at step 2.

## Suggested fix

Wire `verify_client_cert` + `check_ip_allowlist` into the admin
listener accept loop:

```diff
 let io = match conn_tls_acceptor.as_ref() {
     Some(acceptor) => match acceptor.accept(stream).await {
         Ok(tls_stream) => {
+            // Round-1 auth chain step 1: IP allow-list.
+            if !crate::admin_auth::mtls::check_ip_allowlist(&cfg.admin, peer.ip()) {
+                tracing::debug!("admin TLS conn from {peer} rejected by IP allow-list");
+                return;
+            }
+            // Round-1 auth chain step 2: optional mTLS.
+            let san = tls_stream.get_ref().1.peer_certificates()
+                .and_then(|certs| certs.first())
+                .and_then(|cert| extract_san_from_cert(cert.as_ref()));
+            match crate::admin_auth::mtls::verify_client_cert(&cfg.admin, san.as_deref()) {
+                MtlsResult::Disabled       => {}
+                MtlsResult::Verified(_)    => {}
+                MtlsResult::NoCertPresented => return forbidden_response("client cert required"),
+                MtlsResult::RejectedSan    => return forbidden_response("client cert SAN not allow-listed"),
+            }
             AdminIo::Tls(tls_stream)
         }
         ...
     },
     ...
 };
```

Cross-fix: F-CRITICAL-002 in proxy audit (session middleware) +
F-CRITICAL-003 in proxy audit (TOTP) are also missing from the same
listener. Land all three together.

## Verification

```sh
# With mTLS required + IP allow-list set:
cat >> waf.yaml <<EOF
admin:
  ip_allow_list: ["10.0.0.0/8"]
  mtls:
    enabled: true
    required: true
    allowed_san: ["admin@example.com"]
EOF

# From an IP NOT in 10.0.0.0/8 with no client cert:
curl -sk "$HOST/api/about" -i
# Expect: connection refused / 403. Today: 200.

# With client cert whose SAN is NOT in allow-list:
curl -sk --cert other.crt --key other.key "$HOST/api/about" -i
# Expect: 403. Today: 200.

# With valid mTLS:
curl -sk --cert admin.crt --key admin.key "$HOST/api/about" -i
# Expect: 200.
```

## Severity rationale

CRITICAL. Round-1 auth chain step missing; dead code with a
plausible-looking implementation makes the gap invisible on cursory
review. ~30 LoC + SAN-extraction helper.
