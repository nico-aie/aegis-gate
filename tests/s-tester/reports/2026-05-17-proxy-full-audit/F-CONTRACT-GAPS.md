---
id: 2026-05-17-contract-gaps
date: 2026-05-17T00:00Z
severity: contract-gap (semantic)
area: §3 action labels · §5 header presence on admin · hot-reload completeness
component: crates/aegis-proxy/src/data_plane.rs (WS error paths) · crates/aegis-proxy/src/tcp_tunnel.rs · crates/aegis-proxy/src/config_source/reload.rs · crates/aegis-proxy/src/accept.rs (admin listener stamping)
interop_contract: v2.3 §3 · §5 · Round 1 hot-reload claim
status: open
test_mode: source-review
---

# F-CONTRACT-GAPS · 3 semantic contract gaps (§3 action labels + §5 admin headers + hot-reload coverage)

These are not bugs in the "code does the wrong thing" sense — code
does what its author intended. They are gaps where the WAF's
behavior diverges from the v2.3 contract's semantic expectations.

---

## C-01 · WS "no healthy upstream member" returns `block` instead of `circuit_breaker`

**Component:** [data_plane.rs:1086-1117](../../../../crates/aegis-proxy/src/data_plane.rs#L1086-L1117) (WS error path)

When a WebSocket request matches a route whose upstream pool has no
healthy member, the WAF returns a 503 with
`DecisionTag::block("websocket_no_healthy_member")`. The 6 §5
headers then stamp `X-WAF-Action: block`.

§3 of the v2.3 contract maps "Upstream degradation detected by WAF"
to action `circuit_breaker`, not `block`:

| Threat Category | Acceptable Actions | Unacceptable Actions |
|---|---|---|
| Upstream degradation detected by WAF | `circuit_breaker` | `block`, `rate_limit` |

The same applies to:
- `websocket_upstream_forward_failed` (502 → `timeout` or
  `circuit_breaker` depending on cause).
- Any non-WS upstream-side failure returning a synthetic
  status code with `block` rule-id.

Per §7 normalization, an `X-WAF-Action: block` on a legitimate
request gets classified as `false_positive` for the team's score,
while `circuit_breaker` would be classified neutrally as "upstream
protection".

**Fix:** new `DecisionTag::circuit_breaker(rule_id)` variant. Use
it whenever the failure is caused by upstream state (no member,
forward error, connect refused, member down) and not by an
attribute of the client request.

```rust
// data_plane.rs:1086 region
let resp = build_503_with_retry_after(...);
return (resp, DecisionTag::circuit_breaker("upstream.no_healthy_member"));
```

`Decision::stamp` in `interop/headers.rs` already understands the
action enum; just add the `CircuitBreaker` variant if it doesn't
exist and wire it to `X-WAF-Action: circuit_breaker`.

---

## C-02 · CONNECT tunnel returns 200 BEFORE attempting upstream connect — never surfaces `timeout` / `circuit_breaker`

**Component:** [tcp_tunnel.rs:386-407](../../../../crates/aegis-proxy/src/tcp_tunnel.rs#L386-L407) + [data_plane.rs:1742-1745](../../../../crates/aegis-proxy/src/data_plane.rs#L1742-L1745)

The CONNECT handler returns `200 OK` to the client at
`data_plane.rs:1742` (initiating the HTTP/1.1 upgrade to raw TCP),
then spawns a task that ATTEMPTS the upstream connect. If the
upstream connect fails (timeout, refused, unreachable), the client
has already received 200 and the WAF can only close the tunnel
abruptly (TCP RST) — there's no HTTP status to relay the failure
through.

The audit chain records the failure correctly via the spawned task,
but the CLIENT-facing surface (which §3 / §5 / §7 use for
classification) shows `X-WAF-Action: allow` followed by a connection
reset. The benchmark harness's §7 classifier sees `allow` and never
classifies the request as `timeout` or `circuit_breaker`.

This is largely a CONNECT-semantic problem — HTTP CONNECT can't
return errors after the upgrade — but the WAF could:

**Option A:** Attempt the upstream connect with a short pre-upgrade
timeout (e.g. 2 s) and return 502 / 504 to the client if it fails,
delaying the 200 OK until the upstream connection is established.

```diff
 // Before sending 200 OK:
-let resp = build_200_response();
+let upstream = match tokio::time::timeout(
+    Duration::from_secs(2),
+    TcpStream::connect(dest)
+).await {
+    Ok(Ok(s)) => s,
+    Ok(Err(_)) => return (build_503(), DecisionTag::circuit_breaker("tunnel.connect_refused")),
+    Err(_)     => return (build_504(), DecisionTag::timeout("tunnel.connect_timeout")),
+};
+let resp = build_200_response();
 // ... then upgrade and copy_bidirectional ...
```

**Option B:** Document that CONNECT tunnels can never surface
post-upgrade failures via §3 actions, and ensure audit-side
attribution is comprehensive enough that BTC's post-run analysis
can recover the missing classification.

Recommend Option A — it adds 2 s worst-case latency to CONNECT
setup but recovers contract-compliant action attribution.

---

## C-03 · `cfg.upstreams` is silently skipped on file/etcd hot-reload — README's "edit YAML, no restart" claim is false

**Component:** [config_source/reload.rs:258-260](../../../../crates/aegis-proxy/src/config_source/reload.rs#L258-L260)

The README and Architecture docs claim 6 hot-reloadable surfaces:
`routes, detectors, rate_limit, tls.certificates, compliance.modes,
upstreams`. The first 5 reload correctly via notify watcher / etcd
poll. `upstreams` does NOT — `reload.rs:258-260` deliberately
SKIPS rebuilding `ctx.pools` on file/etcd reload, with a comment:

> *"operators who edit cfg.upstreams and want it live should either
> restart or PUT through the dashboard."*

An operator who edits `config/dev.yaml` to change an upstream pool
member list, then waits for the ~100 ms notify reload, sees the
config snapshot update — but `ctx.pools` still holds the OLD member
set. Requests continue routing to the old upstreams. The dashboard
shows the new config; the data plane uses the old one. Silent skew.

**Fix:** rebuild `ctx.pools` on every reload that touches
`cfg.upstreams`. Use the same audit-mutated path the dashboard PUT
uses so that hot-reload audit entries are emitted with consistent
shape.

If the SKIP exists because the pool rebuild is expensive (active
health checks need to converge), gate it on an explicit
`cfg.runtime.hot_reload_upstreams: bool` (default `true`) and emit
a `tracing::warn!` if `false`. Update the README to be honest about
which surfaces actually reload.

---

## C-04 (bonus, lower-priority) · Admin listener responses lack 6 §5 headers

**Component:** [accept.rs:875-901](../../../../crates/aegis-proxy/src/accept.rs#L875-L901)

Every response from the admin listener (`handle_admin_request`,
`admin_sse::sse_response`) is returned to the client without going
through `stamp_interop_response`. Header stamping is only applied to
data-plane responses at `accept.rs:1219, 1326`.

§5 says "every HTTP response được trả qua WAF" — strict reading
includes admin. The OC harness MIGHT probe the admin port (e.g. for
liveness, version, capabilities). If it does, those responses lack
the 6 X-WAF-* headers.

**Fix:** wrap the admin `service_fn` to stamp a constant envelope
on every response, similar to the F-CRITICAL-001 (prior audit)
recommendation for `/__waf_control/*`:

```rust
let resp = handle_admin_request(...).await;
let stamped = stamp_admin_envelope(resp, peer, request_start);
```

`stamp_admin_envelope` writes `allow / 0 / allow / none / BYPASS /
enforce` since the admin path is always "WAF's own surface, no
threat scoring applies".

---

## Severity rationale

These are CONTRACT GAPS — not crashes, not bypasses, not OOM. They
are places where the WAF's response shape disagrees with what §3 /
§5 specify. Each affects a slice of the score (per-request
classification, per-response header set, per-reload hot-swap) but
not all-or-nothing. Fixes are small per item.
