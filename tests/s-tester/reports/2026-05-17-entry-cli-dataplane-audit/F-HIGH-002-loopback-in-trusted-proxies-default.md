---
id: 2026-05-17-loopback-in-trusted-proxies-default
date: 2026-05-17T00:00Z
severity: HIGH
area: data-plane · client identity
component: crates/aegis-proxy/src/data_plane.rs (default_trusted_proxies)
interop_contract: v2.3 §10 ("127.0.0.x khác nhau là distinct clients")
status: open
test_mode: source-review
---

# F-HIGH-002 · `127.0.0.0/8` in default `trusted_proxies` collapses sandbox clients when XFF is present

## Summary

`default_trusted_proxies()` includes the loopback range `127.0.0.0/8`.
Because the loopback is trusted by default, an incoming request from
`127.0.0.5` with header `X-Forwarded-For: 1.2.3.4` makes the WAF
*believe* the real client is `1.2.3.4`. Every loopback client that
provides a different XFF gets mapped to that XFF's IP for rate-limit
and risk-score bucketing.

The v2.3 contract §10 is explicit:

> *In the sandbox: Toàn bộ traffic đến từ các địa chỉ loopback
> `127.0.0.x`. WAF BẮT BUỘC xem các địa chỉ `127.0.0.x` khác nhau là
> distinct clients (khác IP cho rate limiting, risk scoring, v.v.).*

If the OC harness sends a fixed `X-Forwarded-For: <synthetic>` from
varied `127.0.0.x` peers (a documented sandbox pattern), all those
synthetic clients collapse into one bucket and rate-limit / risk
scoring behave incorrectly.

The audit log itself is fine — `admin_dispatch.rs:1064` writes
`peer.ip()` directly, satisfying §6. The bug is on the **identity
used for stateful counters**, which comes from a different code path
that applies XFF when the immediate hop is in `trusted_proxies`.

## Observed code path

`crates/aegis-proxy/src/data_plane.rs:1948-1957` (paraphrased):

```rust
fn default_trusted_proxies() -> Vec<IpNet> {
    vec![
        "127.0.0.0/8".parse().unwrap(),
        "10.0.0.0/8".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
        "::1/128".parse().unwrap(),
        "fc00::/7".parse().unwrap(),
    ]
}
```

The XFF-promotion code reads this list to decide whether to honor
`X-Forwarded-For`. With `127/8` trusted by default, the sandbox case
described in §10 silently misroutes identity.

Bonus issue: this `Vec<IpNet>` is rebuilt on every request — see
F-MEDIUM bundle for the perf side.

## Repro

```sh
HOST="http://127.0.0.1:8080"

# 200 requests from peer 127.0.0.1 with rotating XFF — without the
# bug, each XFF would be its own bucket and none would rate-limit.
# With the bug, the WAF trusts XFF and rate-limits per-XFF IP if any
# one XFF exceeds threshold:
for i in $(seq 1 200); do
    curl -ski "$HOST/" -H "X-Forwarded-For: 10.0.0.$((i % 4))" \
        -o /dev/null -w "%{http_code} "
done; echo

# Inversion test — 200 requests with the SAME XFF should pin to one
# bucket and trip rate-limit even though the peer is loopback:
for i in $(seq 1 200); do
    curl -ski "$HOST/" -H "X-Forwarded-For: 10.0.0.99" \
        -o /dev/null -w "%{http_code} "
done; echo
# → 429s appear earlier than they would have without XFF trust
```

## Impact

- Rate-limit and risk-score per-client state misroutes whenever the
  sandbox uses loopback peer + synthetic XFF.
- §10 contract clause violated → the OC's rate-limit / risk lifecycle
  probes mis-classify because the WAF's identity doesn't match the
  benchmarker's intent.
- Trusting loopback by default is also dubious in production: anyone
  with shell on the WAF host can spoof source IPs by sending XFF
  through a localhost-bound listener.

## Suggested fix

Drop `127.0.0.0/8` (and `::1/128`) from the default trusted-proxy
list. Make XFF trust opt-in via config:

```diff
 fn default_trusted_proxies() -> Vec<IpNet> {
     vec![
-        "127.0.0.0/8".parse().unwrap(),
         "10.0.0.0/8".parse().unwrap(),
         "172.16.0.0/12".parse().unwrap(),
         "192.168.0.0/16".parse().unwrap(),
-        "::1/128".parse().unwrap(),
         "fc00::/7".parse().unwrap(),
     ]
 }
```

Operators who genuinely have an L7 LB on the same host can add the
loopback range explicitly via
`cfg.runtime.trusted_proxies: ["127.0.0.0/8"]`.

Stronger alternative (recommended for hackathon): make the default
empty and require operators to opt in to *any* XFF trust. The
benchmark harness never expects WAFs to trust XFF in the sandbox
(per §10).

```diff
-fn default_trusted_proxies() -> Vec<IpNet> {
-    vec![
-        "10.0.0.0/8".parse().unwrap(),
-        "172.16.0.0/12".parse().unwrap(),
-        "192.168.0.0/16".parse().unwrap(),
-        "fc00::/7".parse().unwrap(),
-    ]
-}
+fn default_trusted_proxies() -> Vec<IpNet> {
+    // v2.3 §10 — sandbox traffic comes from loopback with synthetic
+    // XFF. Trust no XFF by default; operator opts in via
+    // cfg.runtime.trusted_proxies.
+    Vec::new()
+}
```

Also: see F-MEDIUM bundle for caching the result in a `OnceLock`
so the vec isn't rebuilt per request.

## Verification

Repeat the burst test above with a fixed XFF: with the fix, the
WAF should treat every request as coming from peer 127.0.0.1 and
trip rate-limit based on the loopback bucket, not the XFF bucket.

A regression case belongs in `tests/contract/`:

```sh
# Two loopback peers (simulated via different src ports) with the
# same XFF — assert audit-log .ip differs.
```

## Severity rationale

HIGH. §10 violation that affects every rate-limit / risk probe in
the sandbox. Not CRITICAL because Round 1 traffic without XFF is
unaffected; the failure mode is concentrated in Round 2's identity-
sensitive tests.
