---
id: 2026-05-17-control-endpoints-missing-observability-headers
date: 2026-05-17T00:00Z
severity: CRITICAL
area: data-plane · interop
component: crates/aegis-proxy/src/accept.rs · admin_dispatch::handle_interop_control_with_rt
interop_contract: v2.3 §5 (mandatory observability headers)
status: open
test_mode: source-review
---

# F-CRITICAL-001 · `/__waf_control/*` responses bypass header stamping — 6 mandatory §5 headers missing

## Summary

All four required control endpoints (`/__waf_control/capabilities`,
`/reset_state`, `/set_profile`, `/flush_cache`) are short-circuited
inside the data-plane accept loop **before** the response is run
through `stamp_interop_response`. As a result, the control responses
carry NONE of the six mandatory v2.3 §5 headers:

- `X-WAF-Request-Id`
- `X-WAF-Risk-Score`
- `X-WAF-Action`
- `X-WAF-Rule-Id`
- `X-WAF-Cache`
- `X-WAF-Mode`

Contract §5 reads: *"WAF của bạn BẮT BUỘC expose required observability
headers ... trên mọi HTTP response được trả qua WAF"*. The OC harness
treats missing required headers as `observability contract failure`
for that response.

## Observed code path

`crates/aegis-proxy/src/accept.rs:1089–1112`:

```rust
let path = req.uri().path().to_string();
// v2.3 contract — the OC benchmarker hits /__waf_control/* on the
// public TLS data plane, not the admin port. Short-circuit ...
if path.starts_with("/__waf_control/") {
    if let Some(rt) = interop.as_ref() {
        let resp = crate::admin_dispatch::handle_interop_control_with_rt(
            req,
            rt.as_ref(),
            upstream_ctx.pow_issuer.get(),
            Some(&state_backend_for_interop),
        ).await;
        return Ok::<_, Infallible>(resp);    // ← returns BEFORE stamping
    }
}
```

The two normal data-plane paths immediately below it
(`accept.rs:1219` and `accept.rs:1326`) DO call
`stamp_interop_response(...)` before returning, which is what guarantees
the §5 headers for proxied traffic. The control branch returns earlier
and bypasses that envelope entirely.

## Repro (once the WAF is running)

```sh
SECRET="${AEGIS_BENCHMARK_SECRET:-waf-hackathon-2026-ctrl}"
HOST="http://127.0.0.1:8080"

# Headers from a normal allowed request — six X-WAF-* headers present:
curl -ski "$HOST/" | grep -i '^x-waf-' | sort

# Headers from a control endpoint — should also carry the six headers,
# but currently returns ZERO X-WAF-* headers:
curl -ski -H "X-Benchmark-Secret: $SECRET" \
    "$HOST/__waf_control/capabilities" | grep -i '^x-waf-' | sort
```

## Impact

- Every call the OC harness makes to a control endpoint registers as
  an observability contract failure for that response.
- A bench tool that asserts "all six headers on every response"
  (a literal reading of §5) will deduct per call — minimum 4 deducts
  per benchmark phase, more if `reset_state` or `set_profile` are
  invoked between sub-tests.
- The `X-WAF-Request-Id` correlation between control responses and
  the audit log breaks, so any post-run inspection that pivots from
  a control request to the chain has no anchor.

## Suggested fix

Stamp a fixed "control-plane envelope" on every `/__waf_control/*`
response before returning. The control surface always decides
`allow / none / BYPASS / enforce` from the WAF's perspective, so the
envelope is constant per response.

```diff
 if path.starts_with("/__waf_control/") {
     if let Some(rt) = interop.as_ref() {
-        let resp = crate::admin_dispatch::handle_interop_control_with_rt(
+        let mut resp = crate::admin_dispatch::handle_interop_control_with_rt(
             req,
             rt.as_ref(),
             upstream_ctx.pow_issuer.get(),
             Some(&state_backend_for_interop),
         ).await;
+        // v2.3 §5 — control responses MUST also carry the six
+        // mandatory observability headers. Stamp a constant
+        // envelope: control surface is `allow`, no rule attribution,
+        // never cacheable, always in enforce-with-respect-to-itself.
+        crate::admin_dispatch::stamp_interop_control_envelope(
+            &mut resp,
+            peer,
+            request_start,
+        );
         return Ok::<_, Infallible>(resp);
     }
 }
```

Add `stamp_interop_control_envelope` in
`crates/aegis-control/src/admin_dispatch.rs` next to
`stamp_interop_response`, reusing the same `format_request_id`,
risk-score `0`, action `allow`, rule-id `none`, cache `BYPASS`,
mode `enforce` writers.

## Verification

After the fix, the second `curl` above should print:

```
x-waf-action: allow
x-waf-cache: BYPASS
x-waf-mode: enforce
x-waf-request-id: <uuid>
x-waf-risk-score: 0
x-waf-rule-id: none
```

A regression test belongs in `tests/contract/` — assert presence of
all six headers on each of the four `/__waf_control/*` endpoints.

## Severity rationale

CRITICAL. The contract explicitly singles out missing observability
headers as a contract failure (§5), and these endpoints are called
on every phase boundary of the benchmark.
