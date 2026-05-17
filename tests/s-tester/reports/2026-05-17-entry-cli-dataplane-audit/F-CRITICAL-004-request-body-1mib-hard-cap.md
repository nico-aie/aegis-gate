---
id: 2026-05-17-request-body-1mib-hard-cap
date: 2026-05-17T00:00Z
severity: CRITICAL
area: data-plane · request ingestion
component: crates/aegis-proxy/src/data_plane.rs (MAX_BODY_BYTES)
interop_contract: Round 1 reverse-proxy criterion ("forward chính xác headers/body"), Round 2 false-positive minimization
status: open
test_mode: source-review
---

# F-CRITICAL-004 · Hard 1 MiB request-body cap blocks legitimate large requests as `body-too-large`

## Summary

The data plane refuses any request whose body exceeds **1 MiB** with
a synthetic 413 `PAYLOAD_TOO_LARGE` + `DecisionTag::block("body-too-large")`.
The cap is hard-coded (`const MAX_BODY_BYTES: usize = 1 * 1024 * 1024`),
not configurable, and applies uniformly across all routes regardless
of upstream needs.

A single file-upload or large-JSON request in the benchmark corpus is
enough to:

- Fail Round 1's *"WAF phải forward chính xác các HTTP methods, headers
  và body tới upstream, đồng thời trả về nguyên vẹn response"* check.
- Score the request as `false_positive` in Round 2 (§7 matrix —
  "Legitimate request bị blocked ... ngoài expected stress conditions").

## Observed code path

`crates/aegis-proxy/src/data_plane.rs:180`:

```rust
const MAX_BODY_BYTES: usize = 1 * 1024 * 1024; // 1 MiB
```

`crates/aegis-proxy/src/data_plane.rs:450-463`:

```rust
if body_bytes.len() > MAX_BODY_BYTES {
    let resp = Response::builder()
        .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::json!({
            "error": "request body too large",
            "max_bytes": MAX_BODY_BYTES,
        }).to_string())))
        .unwrap();
    return (resp, DecisionTag::block("body-too-large"));
}
```

No route exception, no opt-out via config, no streaming fallback.

## Repro

```sh
HOST="http://127.0.0.1:8080"

# Generate a 2 MiB body (just above the cap):
head -c $((2 * 1024 * 1024)) /dev/urandom | base64 > /tmp/payload.bin

curl -sk -X POST -H "content-type: application/octet-stream" \
    --data-binary @/tmp/payload.bin "$HOST/upload" -o /dev/null \
    -w "status=%{http_code}\n"
# → status=413
#   audit log: action=block, rule_id=body-too-large
```

Then drop to ~512 KiB and the same request gets through.

## Impact

- Round 1 reverse-proxy criterion: BTC will likely include at least
  one large-body POST in the validation traffic. A 413 on a benign
  upload is a Round 1 fail (pass/fail gate).
- Round 2: any contract clause that classifies the request — `path`,
  `method`, audit `action` — is recorded as a WAF-initiated block on
  a legitimate request → counted as `false_positive` (§7 normalization).
- The block produces an `X-WAF-Rule-Id: body-too-large` which is not
  in the suggested rule-id namespace and is not advertised by
  `GET /__waf_control/capabilities`, so `set_profile log_only` cannot
  toggle it. The operator cannot opt out at runtime.

## Suggested fix

1. **Raise the default to a realistic value** (16 MiB or 32 MiB —
   typical CDN / WAF defaults). Single hot-path block, no perf cost
   on smaller bodies because the check is on `body_bytes.len()` post-read.

2. **Make it config-driven** — add to the `cfg.runtime` (or
   `cfg.protocols.http`) section so operators can tune per profile:

   ```yaml
   # config/dev.yaml
   runtime:
     max_request_body_bytes: 33554432   # 32 MiB
   ```

3. **Surface the limit in `capabilities`** so the OC can introspect
   what the WAF will refuse:

   ```json
   {
     "features": {
       "body_limits": {
         "supported": true,
         "toggleable": false,
         "policies": ["max_request_body_bytes"]
       }
     }
   }
   ```

4. **Optional follow-up** — stream the body through detectors instead
   of buffering. Required for proper >100 MiB handling without
   blowing per-request memory.

```diff
-const MAX_BODY_BYTES: usize = 1 * 1024 * 1024; // 1 MiB
+// Default; overridable via cfg.runtime.max_request_body_bytes.
+// Chosen to match typical CDN defaults (Cloudflare 100 MiB,
+// AWS WAF 8 MiB on managed rules) without inviting OOM on
+// per-request buffering.
+const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024; // 32 MiB
```

```diff
-if body_bytes.len() > MAX_BODY_BYTES {
+let limit = cfg_runtime.max_request_body_bytes
+    .unwrap_or(DEFAULT_MAX_BODY_BYTES);
+if body_bytes.len() > limit {
     ...
-            "max_bytes": MAX_BODY_BYTES,
+            "max_bytes": limit,
     ...
 }
```

## Verification

After the fix, the 2 MiB repro above should return 200 (proxied to
upstream) and the audit log should show `action: allow`. Drop the
config back to `max_request_body_bytes: 1048576` and the same
request should be blocked — confirms the limit is respected and
the default is no longer the bottleneck.

A regression case belongs in `tests/protocols/` exercising 1 KiB /
1 MiB / 16 MiB / config-limit-plus-one bodies.

## Severity rationale

CRITICAL. Round 1 is a pass/fail gate. A single oversized payload
in the validation set fails the whole team out of the competition,
and the operator has no runtime knob to widen the limit.
