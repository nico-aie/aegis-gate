# DNS-resolved upstream members

> **Status (2026-05-11):** Planned, not started. Captured because
> operators want to address backends by hostname
> (`api.example.com:443`, `myservice.internal:8080`) rather than
> being forced to pin a `SocketAddr` (`10.0.1.10:8080`). This plan
> walks the design space and recommends a phased implementation.
>
> **Scope:** outbound only. Inbound `Host`-header matching is
> already supported via `RouteConfig.host: Option<String>` and the
> dashboard's Add Route modal; this plan does not touch that
> surface.

## Why operators want this

Today the dashboard's Add Route modal forces this shape:

```
Forward to:
  [ Type a new backend: IP:port (e.g. 10.0.1.10:8080) ]
```

Backed by `MemberConfig.addr: SocketAddr` in
`crates/aegis-core/src/config.rs:1003`. The Rust type is hard: serde
fails to parse `addr: api.example.com:443`. Concretely the operator
hits this when:

- **Cloud load balancers** — `*.elb.amazonaws.com`,
  `*.cloudfront.net` resolve via DNS A-record rotation; the LB
  expects clients to honor TTLs. Pinning an IP breaks ELB's
  scale-out.
- **Kubernetes Services** — in-cluster DNS (`svc.cluster.local`)
  is the load-balancing mechanism; service-IPs are stable but
  pod-IPs rotate behind them.
- **Multi-vhost shared infrastructure** — GitHub Pages,
  Cloudflare, AWS S3 static sites. The hostname *is* the
  identity; the IP can change without notice.
- **Internal service discovery** — Consul, etcd, mDNS expose
  services by name. Operators expect `myservice.internal:8080`
  to resolve at lookup time.
- **Cert validation** — TLS upstreams need the hostname for SNI
  + cert SAN match. Today operators work around with the
  `host_header` field; with DNS the hostname can default SNI
  to itself.

Today's workarounds — manually `dig` the hostname, paste the IP,
set `host_header` for SNI — are brittle. When the upstream's IP
changes the operator has to notice the failure mode and edit YAML
again.

## Current behavior

Status quo if an operator tries `addr: api.example.com:443` today:

- **YAML load**: `serde_yaml::from_str` fails with
  `invalid socket address syntax` on `MemberConfig.addr`. Hard
  parse error, boot aborts.
- **Dashboard PUT** (`POST /api/upstreams/pool/<id>`): the
  validator catches the same error and rejects the request
  with a 4xx. Operator sees "validation: invalid socket address
  syntax" with no obvious fix.
- **No DNS-resolver crate is in scope** today. `hickory-resolver`
  is *not* a dependency; `tokio::net::lookup_host` exists in std
  but is unused. Adding either is gated on this feature.

The only existing workaround that lives in code is the
`host_header` field on `MemberConfig` (line 1027 of `config.rs`),
which lets operators send `Host: api.example.com` to a backend
addressed by IP. That covers vhost / SNI but not the
"hostname rotates IPs" case.

## Code anchors

- `crates/aegis-core/src/config.rs:1003` — `MemberConfig.addr: SocketAddr`.
  Where the type widens.
- `crates/aegis-proxy/src/upstream/mod.rs:9-16` — `MemberRef.addr: SocketAddr`.
  Where the runtime uses the resolved address.
- `crates/aegis-core/src/sd.rs` — `ServiceDiscovery` trait + watch
  channel. DNS naturally slots in here as another `sd::Source`.
- `crates/aegis-control/assets/dashboard/src/pages.jsx:9548-9553` —
  Add Route modal's "Forward to" input + placeholder.

## Design space

### Dimension 1 — Storage / wire shape

Two options:

- **(a) Tagged enum** — `MemberConfig.addr: MemberAddr` where
  `MemberAddr` is `Ip(SocketAddr) | Hostname { host: String, port: u16 }`.
  Strict serde validation; ambiguity-free. **Recommended.**

- **(b) Single `String`** — parse at load time, infer IP vs.
  hostname. Smaller diff, but conflates the two cases and loses
  type-system help in `aegis-proxy`. Rejected.

The enum can serialize as a string with serde-flavored union
parsing (try `SocketAddr::parse`, fall back to
`Hostname::parse`) so YAML still reads as the single-string
operators expect:

```yaml
upstreams:
  api:
    members:
      - addr: api.example.com:443    # hostname
      - addr: 10.0.1.10:8080         # IP — still works
```

### Dimension 2 — Resolution timing

Four options ordered by complexity:

- **(a) Boot-time only** — resolve once at config load, freeze
  the resolved `SocketAddr`. Simplest. Breaks rolling deploys,
  loses DNS TTL semantics. Rejected for prod use cases, but
  acceptable for a Phase 1 "we accept hostnames now" milestone.

- **(b) Per-connection** — `lookup_host` before every dial.
  Adds DNS RTT to every connection (typically 1-10 ms over a
  local resolver, longer cold). Rejected — too costly.

- **(c) TTL-cached on-connect** — first connection resolves and
  caches; subsequent connections within TTL reuse the cached IP;
  expired entries trigger refresh. Reasonable middle ground;
  doesn't need a background task.

- **(d) Background refresh** — periodic resolver task per
  hostname; pushes updates into the existing `sd::watch::Receiver`
  pipeline (so the pool's member list updates atomically).
  **Recommended for prod.** This is what Envoy / nginx /
  HAProxy do.

Path: Phase 1 ships (a), Phase 2 adds (d).

### Dimension 3 — Multi-A-record handling

A single hostname can resolve to N IPs (ELB rotation, K8s
Endpoints). Three options:

- **(a) First record wins** — pick `result[0]`, ignore the rest.
  Simple. Loses DNS round-robin / failover semantics. Rejected.

- **(b) Expand into N synthetic members** — each resolved IP
  becomes a `MemberRef` with the same weight + zone. The pool's
  existing load-balancing strategies (round-robin, least-conn,
  p2c) handle distribution. **Recommended.** Matches Envoy's
  STRICT_DNS / LOGICAL_DNS shapes.

- **(c) Random selection per request** — pick a random IP at
  connection time. Cheap to implement; surprises operators who
  expect their LB strategy to apply uniformly. Rejected.

### Dimension 4 — SRV record support

Out of scope for v1. Most operators address services via A/AAAA
records; SRV adds priority + weight + port semantics that need
their own UX. Captured as a follow-up:
- New `MemberConfig` variant: `Srv { name: String }` (e.g.
  `_http._tcp.api.example.com`).
- Resolver expands SRV into multiple members with the priorities
  + weights the DNS records carry.
- Skip for v1; revisit when an operator asks.

### Dimension 5 — Failure modes

Operator-visible behaviors when DNS goes wrong:

| Scenario | Today (IP-only) | DNS upstream (proposed) |
|---|---|---|
| First boot, hostname unresolvable | n/a | Phase 1: log warn, hold member out of the pool until next refresh. Phase 2: same, plus circuit-breaker behavior identical to "all members down". |
| Mid-flight, record dropped from DNS | n/a | Background refresh stops re-adding the IP; pool's existing health probes catch unreachable IPs and shed them via the breaker. |
| Resolver outage | n/a | Cache last-known-good IPs for the lookup TTL; after that, treat as "all members down" and trip the breaker. |
| Hostname resolves to a known-bad IP (e.g. blacklisted) | n/a | Pool consults the access-list as today — outbound DNS doesn't bypass inbound blacklists. |

### Dimension 6 — SNI / Host header

With hostname-addressed members, the natural default for SNI +
`Host:` is the hostname itself. Today operators set
`host_header` manually; under this design:

- If `MemberConfig` is `Hostname { host, port }` and
  `host_header` is unset, default SNI + outbound `Host` to
  `host`. Saves a YAML field for the common case.
- `host_header` still wins when explicitly set (operators who
  need a different SNI than the address).

## Recommended design (v1)

Pick **tagged enum + background-refresh + multi-A-expand +
A/AAAA-only**.

### Wire shape

```rust
// aegis-core/src/config.rs
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MemberAddrSpec {
    /// IP:port literal — exactly today's behavior.
    Ip(std::net::SocketAddr),
    /// Hostname + port. Resolved via DNS, refreshed in the
    /// background, expanded to N members when the A/AAAA record
    /// set has multiple entries.
    Hostname {
        host: String,
        port: u16,
        /// Override the DNS-honored TTL refresh cadence
        /// (seconds). `None` honors the record's TTL.
        #[serde(default)]
        refresh_seconds: Option<u32>,
    },
}

pub struct MemberConfig {
    pub addr: MemberAddrSpec,   // was: SocketAddr
    pub host_header: Option<String>,
    // ... other fields unchanged
}
```

YAML stays a single string in the common case:

```yaml
upstreams:
  api-elb:
    members:
      - addr: api.example.com:443   # hostname — new
      - addr: 10.0.1.10:8080        # IP — unchanged
```

The expanded shape (`{ host, port, refresh_seconds }`) is
available for operators who want to override TTL.

### Runtime architecture

Wire DNS as a new `sd::Source` implementation. The proxy already
has a `ServiceDiscovery` trait and watch-channel plumbing; we
write `DnsSource` that:

1. Reads the pool's hostname-shaped members on construction.
2. Spawns one resolver task per unique hostname.
3. Each task: `lookup_host` → expand to N `MemberAddr`s → send on
   the watch channel → sleep `min(record_ttl, refresh_seconds)` →
   repeat.
4. On lookup failure: log + emit an unhealthy `MemberAddr`-less
   update (members are held out); retry on the next tick.

The pool's existing member-update path consumes the watch
channel and atomically rebuilds the member ring. Health probes,
breaker state, load-balancing strategy all flow naturally.

### Dashboard

Add Route modal placeholder + helper updates:

```
Forward to:
  [ api.example.com:443  or  10.0.1.10:8080 ]
  Hostnames resolve via DNS and refresh on TTL.
```

Pool detail view adds a "Resolved IPs" expandable for hostname
members:

```
api.example.com:443
  ├── 52.84.150.17:443  (TTL 300s, last refreshed 12s ago)
  ├── 52.84.150.42:443  (TTL 300s, last refreshed 12s ago)
  └── 52.84.150.99:443  (TTL 300s, last refreshed 12s ago)
```

### New crate dep

Add `hickory-resolver` (or upstream `trust-dns-resolver`):

- Pure-Rust resolver — avoids C-glibc resolver footguns
  (NXDOMAIN caching, /etc/resolv.conf parsing quirks).
- Honors TTLs natively.
- Already battle-tested in the Rust ecosystem (used by Tokio's
  HTTP clients, Pingora, etc.).
- ~80 KB compiled; acceptable footprint vs. shelling out.

## Phases

### Phase 1 — Accept hostnames at boot (~2 days)

Smallest viable cut. Operators can use hostnames; resolution
happens once at config load.

- [ ] `MemberAddrSpec` enum + serde untagged variants.
- [ ] Boot-time resolver: `Hostname → SocketAddr` via
      `tokio::net::lookup_host` (no new dep yet).
- [ ] Multi-A-record → N `MemberRef` expansion at load time.
- [ ] Dashboard Add Route placeholder + helper text update.
- [ ] Unit tests: serde round-trips, multi-IP expansion,
      unresolvable-hostname error.
- [ ] Hard error on unresolvable hostname at boot (Phase 2 will
      soften this).

**Outcome**: operators can use hostnames; DNS is honored at
boot only. Stale IPs survive until next config reload / restart.

### Phase 2 — Background refresh + soft failure (~3 days)

Production-grade.

- [ ] Add `hickory-resolver` dependency.
- [ ] `DnsSource: ServiceDiscovery` implementation.
- [ ] Per-hostname resolver task wired to the pool's
      `sd::watch::Receiver`.
- [ ] Soft-failure: unresolvable hostname at boot logs warn,
      pool starts with no resolved members (breaker open until
      first successful resolution).
- [ ] Configurable refresh cadence (`refresh_seconds` override,
      else DNS TTL).
- [ ] Audit events on resolution changes (`pool_dns_resolved`
      with before/after IP set, similar to existing
      `pool_member_replaced`).
- [ ] Tests: resolver outage, record drop, TTL respect, soft
      failure boot.

**Outcome**: operators can hot-rotate upstream IPs through DNS
without touching the WAF. Cloud LBs, K8s Services, Consul work
out of the box.

### Phase 3 — Dashboard polish (~1 day)

- [ ] "Resolved IPs" expandable on the pool detail view.
- [ ] DNS health badge on hostname members (resolved / stale /
      failed).
- [ ] Tooltip on the "Forward to" input clarifying that
      hostnames refresh via DNS TTL.
- [ ] Help & Guide glossary entry "DNS upstream" + workflow
      "Wire a cloud LB by hostname".

## Test plan

Unit:

- Serde round-trips for `MemberAddrSpec` (IP, hostname, expanded
  hostname with `refresh_seconds`).
- Multi-A-record expansion: a hostname that resolves to 3 IPs
  produces 3 `MemberRef`s with the same weight + zone.
- TTL respect: a record with TTL=60s gets refreshed in
  61-70s, not earlier.
- Failure isolation: one hostname failing to resolve doesn't
  break siblings in the same pool.

Integration (mock resolver):

- Pool with one hostname member, resolver returns 2 IPs →
  pool sees 2 members.
- Resolver flips from 2 IPs to 1 → pool drops the missing
  member; in-flight requests on the dropped IP complete normally.
- Resolver outage → cache last-known-good for TTL, then trip
  breaker.
- Resolver returns NXDOMAIN → all members held out, audit event
  emitted.

E2E (real resolver):

- Boot with `api.example.com:443` in the YAML; verify the pool
  has the expected number of resolved members.
- Force a DNS rotation (point a local resolver at a fresh
  record set); verify the pool's member list updates within
  the TTL.

## Open questions

1. **Resolver choice**: hickory vs. async-std resolver vs.
   `tokio::net::lookup_host` (synchronous wrapper around glibc).
   Plan recommends hickory in Phase 2.
2. **IPv6 preference**: when a hostname resolves to both A and
   AAAA, which wins? Or both? Need an explicit policy.
3. **Resolver caching at OS level**: if the operator has nscd /
   systemd-resolved running, our TTL might be shorter than
   theirs. Document that hickory bypasses the OS resolver to
   avoid this.
4. **Per-pool resolver config**: should the resolver be
   process-wide or per-pool? Process-wide is simpler;
   per-pool could let an operator point a single pool at an
   internal DNS server. Skip for v1, revisit if asked.

## References

- Envoy DNS clusters: STRICT_DNS vs. LOGICAL_DNS semantics —
  `https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/service_discovery#arch-overview-service-discovery-types`
- nginx `resolver` directive — periodic refresh, soft-failure.
- HAProxy `runtime API` `set server` with hostname source.
- Code anchors above (`config.rs:1003`, `upstream/mod.rs:9-16`,
  `sd.rs`).
