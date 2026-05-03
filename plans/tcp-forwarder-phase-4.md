# TCP Forwarder — Phase 4 Design

> **Status:** design-only, ready to implement. Track ID prefix
> `TCP-T<n>`. Closes the C-track multi-protocol upstream story
> (`UpstreamScheme::Tcp` is currently a 502 stub — see
> `crates/aegis-proxy/src/upstream/forward.rs:381`).

## 0 · One-line summary

Ship raw TCP forwarding via the **HTTP CONNECT method** on routes
whose pool is configured `scheme: tcp`, reusing the existing
WebSocket upgrade primitive (`hyper::upgrade::on` +
`tokio::io::copy_bidirectional`) so we don't grow a second
listener path.

## 1 · Why CONNECT, not "raw L4"

Three design candidates were considered:

| Candidate | Trigger | Verdict |
|---|---|---|
| **A. HTTP CONNECT** | Method = CONNECT + route's pool has `scheme: tcp` | **Pick.** Clean HTTP standard; reuses route table, detector pipeline, audit chain, identity tracker — no parallel control surface. |
| **B. Any HTTP method to a tcp pool** | Any request to a `scheme: tcp` route | Reject. No standard semantics; pretending GET = stream tunnel surprises downstream. |
| **C. Separate L4 listener** | Distinct port, no L7 in front | Reject. Doubles the surface (own listener, own readiness, own auth) for marginal value. The WAF *is* an L7 box. |

CONNECT (A) gives us:

- A real RFC (RFC 9110 §9.3.6) defining the wire shape.
- An existing client population — every HTTPS-via-proxy client
  already speaks it.
- Inspection of the CONNECT request itself (host policy, IP allow,
  mTLS) before any bytes flow.
- The same security primitives (CSRF doesn't apply, but rate
  limit, identity, tiering all do).

The post-upgrade bytes are explicitly **not** inspected — that's
the whole point of a tunnel. The WAF's value-add lives in the
admission decision, not the byte stream.

## 2 · Lifecycle

```
client                       WAF                          upstream
  │ CONNECT host:port HTTP/1.1
  ├─────────────────────────► │
  │                           │ ── route table lookup ───►
  │                           │ ── detector chain ───────► (host policy, IP rate
  │                           │                              limit, identity, tier)
  │                           │
  │                           │ allowed?  no  ─► 403/502 + audit, close
  │                           │           yes
  │                           │
  │ HTTP/1.1 200 OK (empty)   │
  │ ◄─────────────────────────┤
  │                           │
  │                           │ hyper::upgrade::on(req) ─► Upgraded
  │                           │ TcpStream::connect(addr) ─►
  │                           │                           ◄── connected
  │                           │
  │ ── ── ── ── ── ── ── ── ──┤── ── ── ── ── ── ── ── ──►
  │  copy_bidirectional, no L7 inspection, no tier check
  │                           │
  │ FIN / RST                 │
  │ ─────────────────────────►│ ─────────────────────────►
  │                           │ tunnel closes, audit emits
  │                           │   bytes_to_upstream,
  │                           │   bytes_from_upstream,
  │                           │   duration_ms
```

## 3 · Trigger conditions (admission)

A request enters the TCP tunnel path **only when all** of:

1. `req.method() == CONNECT`
2. The resolved route's pool has `scheme: UpstreamScheme::Tcp`
3. The request's authority (parsed from the CONNECT target —
   `req.uri().authority()` for HTTP/1.1) matches the route's
   `tcp_destination_allowlist` (new field — see §6).
4. All standard detectors pass (rate limit, host policy, mTLS
   identity, tier admission).

Anything else takes a non-tunnel path:

| Combination | Outcome |
|---|---|
| CONNECT, route is **not** `scheme: tcp` | 502 + `x-waf-rule-id: connect_to_non_tcp_route` |
| GET/POST/etc., route **is** `scheme: tcp` | 502 + `x-waf-rule-id: non_connect_to_tcp_route` |
| CONNECT, no route matches | 404 + `x-waf-rule-id: route_not_found` |
| CONNECT, dest authority outside allowlist | 403 + `x-waf-rule-id: connect_destination_denied` |
| CONNECT, detector fires | standard block path (e.g. 429 with rule-id) |

The 502 distinction matters — operators reading audit / metrics
want to tell config drift (route<->method mismatch) apart from
upstream failure.

## 4 · Detector contract on CONNECT

What the detector chain CAN inspect:

- Method (`CONNECT` itself)
- Headers (Host, X-Forwarded-For, Proxy-Authorization, custom
  identity headers)
- Source IP (real, after XFF validation)
- Resolved client identity (mTLS SAN, SPIFFE ID)
- Authority target of the CONNECT (`host:port` from
  `req.uri()`)
- TLS / handshake metadata (cipher, ALPN, SNI)

What it CANNOT inspect:

- Request body (CONNECT has none before upgrade)
- URL path (CONNECT request line carries `host:port`, not a path)
- Post-upgrade bytes (out of scope — that's the tunnel)

This means most existing detectors (SQLi, XSS, cmd-injection)
won't fire on CONNECT. The detectors that DO fire:

- `ip_rate_limiter` (F-T2)
- `brute_force` per-IP
- `host_policy` (host pattern matching against the authority)
- `mtls_required` (when route has `auth_required: ["mtls"]`)
- A new **`connect_destination_policy`** detector (§6) — the
  CIDR + port allowlist gate.

## 5 · Audit shape

Two audit events per tunnel — start and close — with the same
`request_id`:

```jsonc
{
  "ts": "2026-05-10T14:23:00Z",
  "request_id": "...",
  "action": "tcp_tunnel_open",
  "rule_id": "tunnel_admitted",
  "method": "CONNECT",
  "source_ip": "203.0.113.42",
  "identity": "spiffe://aegis/admin/alice",
  "destination": "internal-redis.svc:6379",
  "route_id": "internal-services",
  "pool": "private-mesh"
}

{
  "ts": "2026-05-10T14:24:31Z",
  "request_id": "...",
  "action": "tcp_tunnel_close",
  "rule_id": "tunnel_closed_normal",     // or "tunnel_closed_error"
  "duration_ms": 91234,
  "bytes_to_upstream": 4194304,
  "bytes_from_upstream": 16777216,
  "close_reason": "client_fin"           // or "upstream_fin", "timeout", "abort"
}
```

Both events flow through `AuditedMutate`-style emission so they
land on the chain in order. The close event isn't fire-and-forget
— operators need to be able to reconcile bytes-out vs.
upstream-side metrics.

## 6 · Config additions

### `aegis_core::config`

```rust
// New field on RouteConfig — the per-route CIDR/port allowlist
// for CONNECT destinations. Parallel to allowed_sans for mTLS.
pub struct RouteConfig {
    // ... existing fields ...

    /// TCP-T1 — only consulted when the resolved pool has
    /// `scheme: tcp`. Empty list = closed (no destinations
    /// allowed). Each entry: `<cidr>:<port-spec>` where
    /// port-spec is a single port, range, or `*`.
    /// Examples:
    ///   - "10.0.0.0/8:6379"      Redis private mesh
    ///   - "192.168.1.0/24:443"   only HTTPS to that subnet
    ///   - "172.16.0.0/12:*"      any port to that VPC
    pub tcp_destination_allowlist: Vec<String>,

    /// TCP-T2 — per-IP cap on concurrent open tunnels. 0 = no
    /// cap (defaults to 16). Tunnels are heavy (one socket each
    /// way + a copy task); a misbehaving client can otherwise
    /// drain FDs.
    #[serde(default = "default_max_concurrent_tunnels")]
    pub max_concurrent_tunnels_per_ip: u32,
}
```

The allowlist parses at config-load time into a typed
`Vec<(IpNet, PortSpec)>` so the hot path is two `contains` checks
(IPNet → PortSpec).

### Failure-closed defaults

- `tcp_destination_allowlist: []` rejects all CONNECTs to that
  route (operator must explicitly opt-in to destinations).
- `max_concurrent_tunnels_per_ip: 16` is the boot default; can
  be raised but not bypassed.
- `scheme: tcp` pools without a `tcp_destination_allowlist` on
  any referencing route → config validation error at load.

## 7 · Implementation slices

| Slice | Scope | Estimate |
|---|---|---|
| **TCP-T1** | `tcp_destination_allowlist` config parsing + validation + the `connect_destination_policy` detector. Pure code, no I/O. | ~3h |
| **TCP-T2** | `max_concurrent_tunnels_per_ip` counter (DashMap<IpAddr, AtomicU32> with RAII guard that decrements on drop). | ~1h |
| **TCP-T3** | The handler change in the data-plane: dispatch on `req.method() == CONNECT` after detectors, return 200 + attach upgrade hook, spawn the bridge task. | ~3h |
| **TCP-T4** | `tcp_tunnel_open` + `tcp_tunnel_close` audit events with the full byte-counter and reason payload. | ~2h |
| **TCP-T5** | Integration tests: end-to-end CONNECT through the WAF to a TCP echo server; allowlist-deny path; concurrent-tunnel-cap path; client-disconnect cleanup. | ~3h |
| **TCP-T6** | Drop the Phase 4 stub at `forward.rs:381`; flip `UpstreamScheme::Tcp` from "reserved" to "supported" in the doc table. | ~30min |

Total: ~12h. Slice order is strict — T3 needs T1 + T2; T4 needs T3.

## 8 · Test matrix

| Layer | Test | Outcome |
|---|---|---|
| Unit | `connect_destination_policy::admits_within_cidr_and_port` | true |
| Unit | `connect_destination_policy::rejects_outside_cidr` | false |
| Unit | `connect_destination_policy::rejects_outside_port_range` | false |
| Unit | `connect_destination_policy::empty_allowlist_rejects_all` | false |
| Unit | `tunnel_counter::raii_guard_decrements_on_drop` | counter returns to 0 |
| Unit | `tunnel_counter::cap_blocks_at_limit` | nth+1 admit returns false |
| Integration | `connect_through_proxy_to_tcp_echo` | bytes round-trip |
| Integration | `connect_to_non_tcp_route_returns_502` | 502 + correct rule-id |
| Integration | `get_to_tcp_route_returns_502` | 502 + correct rule-id |
| Integration | `connect_outside_allowlist_returns_403` | 403 |
| Integration | `client_disconnect_drops_upstream` | upstream socket closes within 1s |
| Integration | `audit_emits_open_and_close_events_with_byte_counters` | both events on chain |

## 9 · Out of scope (queued for later)

- **HTTP/2 extended CONNECT** (RFC 8441). Currently rare in the
  wild; h1 CONNECT covers the operator population. Designed-in
  but not implemented in T3 — the dispatch checks h1 method
  first, falls through to a 405 on h2.
- **Per-tunnel bandwidth shaping**. The `copy_bidirectional`
  primitive doesn't take rate limits today; would need a custom
  copy loop. Defer until an operator asks.
- **TLS-MITM inspection of the tunnel**. Explicitly out of scope
  forever — the whole point of CONNECT is end-to-end privacy.
  Operators who want inspection should NOT use scheme=tcp; they
  should use scheme=https where the WAF terminates.
- **Active health checks against tcp pools**. The existing pool
  health-checker assumes HTTP. A tcp pool's health is currently
  "TCP connect succeeds" — fine to reuse; no change needed.

## 10 · Operator footguns (designed-out)

- **CONNECT to localhost / link-local**: the validator rejects
  `127.0.0.0/8`, `::1/128`, `169.254.0.0/16`, `fe80::/10`,
  `0.0.0.0/8` regardless of allowlist content. Bypass requires
  setting `AEGIS_TCP_TUNNEL_ALLOW_INTERNAL=1` (intentionally
  awkward).
- **Open tunnel to 0.0.0.0**: rejected as above.
- **Allowlist drift via comma-separated**: parser rejects
  comma-separated strings; one CIDR per list entry.
- **Idle tunnel pile-up**: `max_concurrent_tunnels_per_ip` plus
  a per-tunnel idle timeout (default 5 min, configurable per
  route) bound the resource footprint.

## 11 · Done-when

- `cargo test -p aegis-proxy` passes with the new TCP-T* tests.
- `tests/api/connect-tunnel.sh` exercises the end-to-end flow
  on a brought-up gateway.
- The 502 stub at `crates/aegis-proxy/src/upstream/forward.rs:381`
  is gone; the doc-table row for `Tcp` reads "raw byte tunnel
  via CONNECT".
- `docs/data-plane/reverse-proxy.md` gains a "TCP tunneling via
  CONNECT" section pointing at this plan.
- `Implement-Progress.md` flips this track from open → closed
  with the SHA of the implementation commit.
