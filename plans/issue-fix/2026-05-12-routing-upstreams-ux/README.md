---
id: 2026-05-12-routing-upstreams-ux-fix-plan
date: 2026-05-12
status: ready
source_report: tests/n-tester/reports/2026-05-12-routing-upstreams-ux/
prior_sprint: plans/issue-fix/2026-05-12-admin/README.md
---

# Fix plan — 2026-05-12 Routing & Upstreams UX deep-dive

## Headline

Operator wired their first real backend (`znews.vn:443`) through
Add Route and got a silently-broken upstream forwarding 400 from
the upstream. The dashboard saved the route + pool correctly; the
data-plane HTTPS handshake never landed. The QA pass split the
failure into two HIGHs (one dashboard, one data-plane) and one
MEDIUM design-debt finding (the Add Route modal silently creates
a pool, which masks both HIGHs).

The MED-ADM-01 3-sprint ack-overlay regression from the previous
plan **is closed** — first time the round-trip closes in QA.

## Findings recap

| ID | Sev | Area | One-line |
|---|---|---|---|
| HIGH-RU-01 | HIGH | dashboard · add-route | Pool saved with `scheme: https` + `tls: false`; operator sees a working pool but a 400 from the upstream |
| HIGH-RU-02 | HIGH | data-plane · upstream | Flipping `scheme`/`tls` via hot-reload doesn't rebuild the per-pool HTTP client; restart-only |
| MED-RU-03 | MEDIUM | dashboard · add-route | Add Route silently creates a pool — operator confused about which resource failed |

## Verified-fine (from previous sprint)

- **MED-ADM-01** percent-decode incident path segments — ✅
  closed. After 3 sprints, the ack round-trip finally lands:
  Acknowledged KPI 0 → 1, status flips to `acknowledged`,
  `acked_by`/`acked_at` populated on the next GET.
- **LOW-ADM-01..06** polish bundle — ✅ spot-checked, no
  regressions observed.

## Root-cause analysis

### HIGH-RU-01 — dashboard sends `tls: false` even when scheme is https

Verified by reading
`crates/aegis-control/assets/dashboard/src/pages.jsx:10557` —
`poolBodyFromInlineForm` (used by the Add Route inline-pool
path):

```js
function poolBodyFromInlineForm(np) {
  return {
    members: [...],
    lb: 'round_robin',
    connection: {
      scheme: np.scheme || 'auto',
      keep_alive: true,
      max_idle_per_host: 32,
      idle_timeout: '30s',
      // tls field omitted
    },
  };
}
```

The body has no `tls` field at all. Server's
`ConnectionPoolConfig::tls` is `#[serde(default)] pub tls: bool`
so it parses to `false`. The saved pool has
`{scheme: "https", tls: false}` — exactly what QA observed.

Why this matters even though `Https.uses_tls(false) == true`
(verified in
`crates/aegis-core/src/config.rs::explicit_https_uses_tls_regardless_of_legacy_flag`):

- The Edit Pool modal at `pages.jsx::poolConfigFromForm` line
  6916 sends `tls: !!d.connection?.tls` but *does not* include
  the `scheme` field. So an operator who edits the pool to flip
  `tls: true` actually resets `scheme` back to `Auto` (the
  serde default), which then DOES depend on the `tls` flag.
  The two modals collectively make `tls` and `scheme` look like
  independent toggles when they should be one source of truth.
- The QA operator sees `{scheme: "https", tls: false}` and reads
  it as a contradiction — even if the data plane handles it
  correctly, operator trust takes a hit.

**Fix.** Derive `tls` from `scheme` at the dashboard boundary:

```js
function tlsFromScheme(scheme, fallback) {
  switch (scheme) {
    case 'https':
    case 'grpc':
      return true;
    case 'http':
    case 'h2c':
    case 'tcp':
      return false;
    case 'auto':
    default:
      return !!fallback;
  }
}
```

Apply in both `poolBodyFromInlineForm` (Add Route inline pool)
and `poolConfigFromForm` (Edit Pool modal). Edit Pool modal
also needs to send `scheme` (it currently omits it; same field
should round-trip).

### HIGH-RU-02 — `PoolKey` cache doesn't invalidate on scheme change

Verified by reading
`crates/aegis-proxy/src/upstream/forward.rs:300-317`:

```rust
struct PoolKey {
    max_idle_per_host: usize,
    idle_timeout_ms: u64,
    keep_alive: bool,
    tls: bool,
    // scheme field MISSING
}
```

The pool's upstream HTTP client is cached process-wide by this
key. The QA's empirical observation: after flipping `tls: true`
the data plane still does plain HTTP. Two compounding factors:

1. **`PoolKey` lacks `scheme`.** Flipping `scheme: Auto →
   Https` while `tls` stays constant (or vice-versa) hits the
   stale cache entry. The cached client was built with the
   prior `cfg.scheme` and its `advertise_h2` / `forces_http2`
   bits are now wrong.

2. **`build_client` consumes `cfg.scheme`** (lines 258-260, 291)
   to decide ALPN advertisement and `http2_only`. So the
   in-built client embeds a scheme-dependent shape; cache keys
   must include that shape.

The fix is to add `scheme` to `PoolKey` so cache lookup
invalidates whenever the scheme axis moves. `PoolRegistry::apply`
already builds a fresh `Pool` struct from the new `PoolConfig`
on every PUT; once the cache key matches the build axes, the
hot-reload path closes correctly.

**Fix.**

```rust
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PoolKey {
    max_idle_per_host: usize,
    idle_timeout_ms: u64,
    keep_alive: bool,
    tls: bool,
    scheme: UpstreamScheme,   // new
}

impl From<&ConnectionPoolConfig> for PoolKey {
    fn from(c: &ConnectionPoolConfig) -> Self {
        Self {
            max_idle_per_host: c.max_idle_per_host,
            idle_timeout_ms: c.idle_timeout.as_millis().min(u64::MAX as u128) as u64,
            keep_alive: c.keep_alive,
            tls: c.tls,
            scheme: c.scheme,   // new
        }
    }
}
```

Requires `UpstreamScheme` to derive `Hash` + `Eq` (it already
derives `Copy, Clone, Debug, Default, Serialize, Deserialize,
PartialEq, Eq` per config.rs:910 — need to add `Hash`).

Plus a regression test that does:
1. Build client with `{scheme: Auto, tls: false}`.
2. Build client with `{scheme: Https, tls: false}`.
3. Assert the cache stored two distinct entries (or the
   second `pooled_client` call missed the cache).

### MED-RU-03 — Add Route modal silently authors two resources

Verified at `pages.jsx:10693-10717` — the Add Route modal's
"Forward to" composite control either picks an existing pool
from a dropdown OR creates a new pool inline. The inline-pool
path is hidden behind an address input; operators reading the
modal think they're authoring one route, but the modal silently
also creates a pool. Combined with HIGH-RU-01, this turns a
debug session into "wait, did the route fail or the pool?"

**Recommended fix (defer to Phase 3, larger PR).** Decouple
pool creation from route creation in the UI — two separate
modals, with the Add Route modal's "Forward to" dropdown
listing existing pools and a "+ Create new pool" link that
opens the second modal.

Out of scope for this fix plan — Phase 1 + 2 alone close the
HIGH operator-visible failure mode; the design-debt cleanup is
a follow-up.

## Phases & ship order

### Phase 1 — HIGH-RU-01 (dashboard tls-from-scheme) ★ ship first

Dashboard-only. ~30 min.

**Files**
- `crates/aegis-control/assets/dashboard/src/pages.jsx`:
  - Add `tlsFromScheme(scheme, fallbackTls)` helper near
    `poolBodyFromInlineForm` (around line 10550).
  - `poolBodyFromInlineForm` — derive `tls` from `np.scheme`
    and include it in the connection body.
  - `poolConfigFromForm` (Edit Pool modal, line 6897) — also
    include `scheme: d.connection?.scheme || 'auto'` and derive
    `tls` from it. Today the Edit Pool form takes scheme via a
    separate select but doesn't ship it on save.
  - Edit Pool modal scheme `<select>` (line 7318) — when the
    operator picks a scheme, auto-toggle the `tls` checkbox to
    the derived value (still editable when scheme is `auto`).

**Verify**
- `make dashboard` regenerates the bundle.
- Manual: Add Route with `znews.vn:443` + scheme `https` →
  saved pool has `{scheme: "https", tls: true}`.
- Manual: Edit Pool form, flip scheme to `http` → tls checkbox
  visually toggles off; save → server shows `{scheme: "http",
  tls: false}`.

### Phase 2 — HIGH-RU-02 (PoolKey includes scheme) ★ ship together

Server-only. ~30 min including tests.

**Files**
- `crates/aegis-core/src/config.rs` — add `Hash` to the
  `UpstreamScheme` derive list (already has `Copy, Clone,
  PartialEq, Eq`).
- `crates/aegis-proxy/src/upstream/forward.rs`:
  - `PoolKey` struct (line 300) — add `scheme: UpstreamScheme`
    field.
  - `PoolKey::from` (line 308) — set the new field from
    `c.scheme`.
- Test: `pooled_client_distinguishes_schemes` — call
  `pooled_client(cfg_auto)` and `pooled_client(cfg_https)`
  back-to-back; assert distinct `Arc<PooledClient>` (via
  `Arc::ptr_eq` returning false).

**Verify**
- `cargo test -p aegis-core --lib -- upstream_scheme_tests`
- `cargo test -p aegis-proxy --lib -- forward::tests`
- Manual: drive `znews.vn:443` repro with Phase 1 dashboard
  fix; `GET /news` → 200 from znews.vn (no more 400).
  Optional sanity-check: flip scheme `https → http` via Edit
  Pool, watch the next request 400 from znews.vn's edge tag
  (different failure mode — confirms the cache picked up the
  scheme change).

### Phase 3 — MED-RU-03 + UX proposals (deferred)

- **MED-RU-03**: decouple pool / route creation in the Add Route
  modal. Two modals or a multi-step flow. Larger UX work — own
  PR.
- **RU-P1..P8** UX proposals: prioritise per the QA report's
  ordering — RU-P3 (scheme drives TLS UI, partial overlap with
  Phase 1), RU-P5 (TLS-mismatch warning chip on route rows),
  RU-P4 (live "is this working?" probe on Pool detail), RU-P2
  (decouple — same as MED-RU-03), RU-P6 (test-route button at
  the page top), RU-P1 (page split into Pools + Routes columns),
  RU-P7 (per-resource audit timeline), RU-P8 (rename "Pools
  without routes" → "Unrouted pools" with a CTA).

## Risk register

- **`PoolKey` change forces a one-time client-cache rebuild
  after deploy.** Acceptable — the cache is process-wide and
  rebuilds lazily; first request per pool pays one
  `build_client` call. No traffic blip beyond what a normal
  process restart already incurs.
- **`UpstreamScheme: Hash` derive may require `chrono` /
  `serde` upgrades.** Unlikely — the enum is plain.
  `cargo build -p aegis-core` catches any incompatibility.
- **Dashboard auto-toggle of tls when scheme changes.** Should
  only fire on user-driven scheme changes, not on initial form
  hydration; otherwise the form would mark itself "dirty" on
  open. Apply via an `onChange` handler that updates both
  fields atomically.
- **Edit Pool modal scheme field already exists.** Phase 1
  changes the existing modal's submit body to include `scheme`
  — operators who never touched the field would now send their
  current selected value (which is correct, but it's a wire-
  shape diff worth calling out in the PR description).

## Out of scope

- Telemetry probe on Pool detail (RU-P4 — separate PR).
- TLS-mismatch warning chip (RU-P5 — depends on Phase 1+2 to
  define what "mismatch" means after the derivation lands).
- Decoupling pool/route creation (MED-RU-03 + RU-P2 — deferred).
- Removing the legacy `tls` flag from the wire shape (server-
  side deprecation path — separate refactor, needs config-
  version bump).
