---
id: 2026-05-17-h3-quic-bypasses-security-pipeline
date: 2026-05-17T00:00Z
severity: CRITICAL
area: data-plane · HTTP/3 listener
component: crates/aegis-proxy/src/listener/http3.rs (serve_h3_request)
interop_contract: v2.3 §5 (mandatory headers) · §10 (peer identity) · Round 1 (reverse-proxy + detector + audit)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-001 · HTTP/3 / QUIC requests bypass the entire security pipeline, the 6 §5 headers, and §10 peer identity

## Summary

The HTTP/3 / QUIC listener serves every request by calling the **bare
router-and-forwarder** `crate::proxy::handle_request` instead of the
security-enforcing `data_plane::handle_data_request`. As a result, an
H3 request:

- Skips every detector (SQLi/XSS/SSRF/path-traversal/AI/etc.).
- Skips rate-limit, blacklist, strike-block, risk-score gating.
- Skips XFF / peer-identity capture entirely — QUIC's
  `connection.remote_address()` is never read.
- Returns WITHOUT any of the 6 mandatory §5 observability headers
  (`X-WAF-Request-Id`, `X-WAF-Risk-Score`, `X-WAF-Action`,
  `X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`).
- Is NOT emitted to the v2.3 audit chain.

In a benchmark phase where the OC harness uses H3, **every test case
scores `passed` (attack reached upstream)**, every response is a §5
contract failure, and every audit-correlation step fails.

Spot-verified by reading [listener/http3.rs:261](aegis-gate/crates/aegis-proxy/src/listener/http3.rs#L261):

```rust
let resp = match crate::proxy::handle_request(hyper_req, ctx).await {
    Ok(r) => r,
    Err(e) => {
        return Err(Http3ConfigError::Internal(format!(
            "handle_request failed: {e}"
        )));
    }
};
```

The HTTP/1.1 + HTTP/2 path goes through `data_plane::handle_data_request`
(`accept.rs:1129`) which IS the security-enforcing handler and IS
followed by `stamp_interop_response`. The H3 path takes a different,
shorter route.

## Observed code path

`crates/aegis-proxy/src/listener/http3.rs:204` (paraphrased):

```rust
while let Some((req, mut stream)) = h3_conn.accept().await? {
    // `connection.remote_address()` is in scope but NEVER captured.
    // No peer SocketAddr → no §10 identity.
    let mut body = bytes::BytesMut::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                body.extend_from_slice(chunk.chunk());  // unbounded — see F-HIGH-protocol
                ...
            }
            Ok(None) => break,
            ...
        }
    }
    let hyper_req = Request::from_parts(parts, Full::new(body.freeze()));
    let resp = crate::proxy::handle_request(hyper_req, ctx).await?;
    //         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //         WRONG: bare router+forwarder, no security pipeline,
    //         no header stamping, no audit emit.
}
```

The HTTP/1.1+/2 listener takes the correct path
([accept.rs:1129](aegis-gate/crates/aegis-proxy/src/accept.rs#L1129)):

```rust
let (resp, decision) = handle_data_request(
    req, peer, &detectors, &mask, &risk, &ip_rate_limiter, ...
).await;
// then stamp_interop_response at line 1219 / 1326.
```

Two completely different request handlers for the same WAF.

## Repro

```sh
# Build with H3 feature enabled:
FEATURES="redis geoip alerts ai http3" make build

# Start with a profile that exposes the H3 listener on UDP 8443:
make run

# Send a SQLi probe over H3 (curl with --http3 needs a build that
# supports it; otherwise use any h3 client like `h2load --h3`):
curl --http3 -sk "https://127.0.0.1:8443/?q=1%27%20OR%20%271%27%3D%271" \
    -D - -o /dev/null

# Expected (per §5 + §3): X-WAF-Action: block, plus other 5 headers.
# Actual: response from upstream (200 if upstream allows), zero X-WAF-* headers.

# Tail the audit log — the H3 request will NOT appear:
tail -5 ./waf_audit.log | jq .
```

For peer-identity violation: send the same probe from two different
loopback aliases via H3 and confirm the WAF cannot distinguish them
(no peer SocketAddr captured → no rate-limit per source).

## Impact

- **Round 1 reverse-proxy criterion**: H3 traffic forwards but
  doesn't enforce — BTC may interpret as "WAF didn't block known
  attacks" (pass/fail gate).
- **Round 2 every test case**: H3 scenarios score `passed` per §7
  normalization → 0% on those test rows.
- **Round 2 §5 header contract**: every H3 response is a contract
  failure (6 headers missing).
- **§6 audit**: no correlation possible because no entry is written.
- **§10 peer identity**: H3 listener has no peer at all → rate-limit
  and risk scoring don't apply per-source.

## Suggested fix

Route H3 requests through the same `handle_data_request` as
H1/H2, with `connection.remote_address()` as the peer, and run the
response through `stamp_interop_response`:

```diff
+let peer = connection.remote_address();
 while let Some((req, mut stream)) = h3_conn.accept().await? {
+    let peer = peer;
     let mut body = bytes::BytesMut::new();
+    let mut total = 0usize;
     loop {
         match stream.recv_data().await {
             Ok(Some(mut chunk)) => {
+                total += chunk.chunk().len();
+                if total > MAX_BODY_BYTES {
+                    // return 413 via stamp; see F-HIGH-protocol H3 body cap
+                    break;
+                }
                 body.extend_from_slice(chunk.chunk());
                 ...
             }
             ...
         }
     }
     let hyper_req = Request::from_parts(parts, Full::new(body.freeze()));
-    let resp = match crate::proxy::handle_request(hyper_req, ctx).await { ... };
+    let request_start = std::time::Instant::now();
+    let (resp, decision) = crate::data_plane::handle_data_request(
+        hyper_req, peer,
+        &ctx.detectors, &ctx.mask, &ctx.risk,
+        &ctx.ip_rate_limiter, &ctx.load_gauge, &ctx.verbosity,
+        ...
+    ).await;
+    let resp = crate::admin_dispatch::stamp_interop_response(
+        resp, decision, peer, request_start, ...
+    );
     ...
 }
```

This requires plumbing the `DataPlaneCtx` (detectors, risk, rate
limiter, etc.) into `Http3Server`. The fields exist on the H1/H2
side — share them.

## Verification

After the fix:

```sh
curl --http3 -sk "https://127.0.0.1:8443/?q=1%27%20OR%20%271%27%3D%271" \
    -D - -o /dev/null | grep -i '^x-waf-' | sort
```

Should print the 6 §5 headers with `X-WAF-Action: block` and
`X-WAF-Rule-Id: sqli`. The audit log should contain a matching
entry with `request_id` equal to `X-WAF-Request-Id`.

Add a regression case in `tests/protocols/` for each detector class
exercised over H3 — duplicate the existing H2 cases against the H3
listener.

## Severity rationale

CRITICAL. The WAF advertises HTTP/3 support (`http3` Cargo feature
in `Cargo.toml`); any benchmark traffic over QUIC bypasses the
entire WAF. Single root-cause behind three §-clauses (§5 / §6 / §10)
of contract failure plus Round-1 reverse-proxy criterion failure.
