# Implementation sequence — the living execution tracker

**Status:** Living tracker — drafted 2026-06-23. This is the **forward execution
order** across every plan in `plans/`: it arranges the capability tiers + the
operational/infra backlog into dependency-ordered waves, and is **updated as items
ship.** Distinct from its two neighbours:

- [`plan.md`](./plan.md) — assistant protocol + repo conventions (*how we work*).
- [`implementation-matrix.md`](./implementation-matrix.md) — per-doc
  Implemented / Partial / Designed / Deferred status (*what exists in code*).
- **this file** — *what order to build next & what blocks what* (the plan of record).
- [`future/world-class-waf-roadmap.md`](./future/world-class-waf-roadmap.md) — the
  *what & why* of the capability tiers; this file is the *what-order*.

**Tracking legend:** ☐ not started · ◐ in progress · ✅ done · ⛔ blocked · ⏸ deferred (research-gated).
Update the Status column (and flip to ✅ with a commit / date) as work lands.

---

## ⏩ Resume here (as of 2026-06-24)

**Wave 0 — ✅ complete.** **Wave 1 — ✅ complete:** config H1·P0 (#74),
config H1·P1+P2 dual-authority fix (#77), PREREQ-B LB fail-open (#78), and
Tier-1A GraphQL caps (#79) all shipped.

**Foundation/durability pulled forward (operator decision 2026-06-24) — ✅ DONE:**

- **Track A — `redis-interim-durability` P1–P3 — ✅ shipped** (#80 A0 hash-ops
  seam + A1 incidents, #81 A2 RiskTracker, #82 A3 counters). Restart-fragile
  control state (incidents / lifetime strikes / lifetime counters) is now durable
  on the existing Redis under the `control:waf:*` keyspace; hot path unchanged.
- **Track B — config H2a (`BootstrapConfig`/`DynamicConfig` split) — ✅ shipped**
  (#83 the types + watcher reconstruction; doc-canonicalization PR = strip-on-
  store + merge-on-load + boot migration). Both safety properties hold: a
  bootstrap field can't be stored in the doc, and the doc can't override
  bootstrap at runtime. [[project_config_h2a_split_progress]].

**Active — next up (Wave 2 capability/availability, foundation now done):**
1. **`passive-upstream-health`** + **`zone-aware-load-balancing`** — do **together**
   (share the `LbStrategy::pick` touchpoint; both unblocked by PREREQ-B).
2. **`ddos-cross-node-rps-aggregation`** (standalone; slot by capacity).

> **AI/LLM firewall (Tier 2) — deferred, research-gated** (decided 2026-06-23).
> Architecture + 2A scope are settled in [[ai-llm-firewall]], but it needs
> dedicated research first (signature corpus, FP calibration, the SSE
> response-inspection decision, embeddings trigger — see that doc §8). Do the
> foundation LB items above first; promote 2A to an active build once the
> research resolves. **Not** the same as the existing `ai` ONNX detector.

> Tier-1A scope note (settled): the token/HMAC half stays *deprioritized* by the
> WAF-vs-gateway boundary call ([[project_waf_vs_gateway_boundary]]); only the
> GraphQL caps half shipped, which is uncontested WAF surface.

> **Enterprise identity (new, drafted 2026-06-24) — [[admin-accounts-rbac-sso]].**
> Control-plane admin auth today = one hard-coded `admin`, every session
> `Scopes::FULL`. Plan takes it to multi-user + RBAC + OIDC SSO. **P1**
> (self-service hardening: wire the dormant password/TOTP/session-revoke/recovery
> endpoints, fleet-wide rate-limit, remove committed default creds) is a
> standalone Wave-3 win — prereq PREREQ-A ✅, no new datastore, **not blocked by
> etcd** (rides the same StateBackend/config-doc seam). Slot by capacity.

**Config arc:** H1 (single-writer correctness), **H2a** (the structural
`BootstrapConfig`/`DynamicConfig` split), and **H2b** (etcd source of truth) are
**all DONE**. H2b shipped 2026-06-25 (PR #86, archived → [[config-etcd-source-of-truth]])
**constraint-respecting**: config **and** control plane on etcd behind the
default-off `etcd_config` cargo feature (built distinct from the SD `etcd`
feature; needs `protoc`), runtime knob **`config_plane.store: shared_state |
etcd`** (default `shared_state`), plus the `waf migrate-config-plane` Redis→etcd
cutover tool. The shipped default keeps the single Redis dependency; etcd
relocates only the config+control doc, Redis stays mandatory for the data plane.
The P2 dual-read shadow-soak was dropped (the direct verify-then-copy migration
covers cutover safety). **Remaining: H3** — config control plane (canary /
GitOps / multi-region). Small config-UX follow-ups (mark Tier-1/restart-only
fields read-only in the API; bootstrap/dynamic banners shipped 2026-06-24).

---

## 1. The two streams

Work in `plans/` splits into two streams that proceed in parallel, each with its
own internal order:

- **Capability stream** — the roadmap Tiers 0–6 (API security → AI firewall →
  Page Shield → bot mgmt → ML → managed rulesets). Market/compliance-driven,
  largely additive, few cross-dependencies. The roadmap already orders these.
- **Foundation stream** — the operational / infra / durability plans in
  `future/`. These have **real hidden dependencies** the roadmap flattens into
  "interleave by capacity." This doc untangles them.

The two streams compete only for engineering capacity, not for code — they touch
mostly disjoint subsystems. Run both; the waves below interleave them.

---

## 2. Foundation stream — dependency graph

Two hard prerequisites gate most of the foundation work. Do them first or the
dependents are unsafe / pointless:

```
[PREREQ-A] Redis data volume mounted (redis-interim-durability P0, S)
   │  without it, every "durability" plan is a no-op — restart still wipes state
   ├─ config-auto-restore            (premise: store came back empty)
   ├─ redis-interim-durability P1-P3 (durable control state / counters)
   └─ persistent-datastore + security-analytics (the ClickHouse/Postgres endgame)

[PREREQ-B] LbStrategy::pick fails OPEN, not closed (small enabling change)
   ├─ passive-upstream-health   (marks members down from real failures → LB)
   └─ zone-aware-load-balancing (also needs node self-zone identity)

[CONFIG] config-single-source-of-truth
   H1 (P0 seed boot→doc v0, S)  ──standalone correctness win, no prereq   ✅
     └─ H1 (P1-P3 single writer, M)                                       ✅
          └─ H2a (BootstrapConfig/DynamicConfig type split, M)            ✅
               └─ H2b = config-etcd-source-of-truth (L)                   ✅ shipped behind default-off etcd_config feature
                    └─ H3 config control plane (canary/GitOps/multi-region, L+)   ← next
   (config-auto-restore's durability half is now SUPERSEDED by the shipped H2b;
    only its fleet-reconciliation idea survives, and only for shared_state-on-non-durable-Redis)

[STANDALONE] (no prereqs, slot anytime by capacity)
   ├─ ddos-cross-node-rps-aggregation (M)
   ├─ smart-caching Phase 4 (stale-if-error + ETag revalidation, S)
   └─ admin-accounts-rbac-sso (enterprise identity)
        P1 self-service hardening (S/M, prereq PREREQ-A ✅) ── standalone win
          └─ P2 multi-user store → P3 RBAC → P4 per-user audit → P5 OIDC SSO
        (no new datastore — rides config doc + control:waf:*/session seams;
         NOT blocked by etcd; only P5 wants a secret resolver for client_secret)
```

**Constraint gate:** the heavy infra plans were deferred until the *hackathon
one-dependency constraint lifts*. **etcd (H2b) is now shipped constraint-
respecting** — the code is built/tested behind a **default-off `etcd_config`
feature**, so the shipped default still pulls only Redis; the gate lifts simply
by shipping the feature build when a second dependency is acceptable. Still
gated: the **ClickHouse + Postgres** datastore (persistent-datastore-tracking-data
+ security-analytics P2+). `redis-interim-durability` remains the deliberate
**dependency-light bridge** for the durability those plans give, using the Redis
already in the stack, until then.

---

## 3. Recommended waves

Each wave is independently shippable and leaves `develop` green. Capability and
foundation items run in parallel within a wave.

### Wave 0 — Hygiene + zero-dependency wins (do first) · ~1 wk

| ✓ | Item | Stream | Effort | Why now |
|---|---|---|---|---|
| ✅ | Roadmap **Tier 0** — `state_select` was already green (stale note); `dashboard_polish` bundle budgets bumped per policy (raw 780→840 KB, app.js 600→640 KB; feature growth, no new deps) → suite green. H3 stays `--features http3`-gated. | Capability | S | Branch must be green before stacking features |
| ✅ | ~~Verify/close the 2 open `issues/`~~ — both archived (`BUG-dns-refresh`, `BUG-whitelist`) in `dc72211` | Foundation | S | Done |
| ✅ | **PREREQ-A**: Redis data volume mounted on `/data` in both compose files + Helm persistence expectation documented (`redis-interim-durability` P0 infra half) | Foundation | S | Hard prereq for ALL durability work; pure ops, no behavior change |
| ✅ | **config-single-source-of-truth H1 · P0** (seed boot file → doc v0) — shipped PR #74 (`2fd2316`); ticket archived | Foundation | S | Standalone correctness win; closes the boot/first-edit divergence; unblocks the config arc |

### Wave 1 — Highest-leverage capability + the dual-authority fix · ~2 wk

| ✓ | Item | Stream | Effort | Why now |
|---|---|---|---|---|
| ✅ | Roadmap **Tier 1A (GraphQL caps)** — `api_security::graphql` depth/complexity/introspection guard wired onto the data path (config-driven, hot-reloadable, log-only-aware) — shipped PR #79 (`1570de5`). `api_keys` + `hmac_sign` half deprioritized (gateway concern). | Capability | S | Gartner #1 priority; code existed, just unwired |
| ✅ | **config-single-source-of-truth H1 · P1–P2** (invert file watcher → publisher; one applier; one guard) — `config_plane.file_watch` flag (default `publish`), file watcher now publishes to `config:waf:doc`, shared-store watcher is sole applier | Foundation | M | Kills the dual-authority bug class (the "one key moves another" report); converges the cluster for free |
| ✅ | **PREREQ-B**: `LbStrategy::pick` fails open — an all-unhealthy pool falls back to the full member set (real 502 from the attempt) instead of returning `None`; `None` only for a genuinely empty pool | Foundation | S | Tiny enabling change that unblocks two availability plans |

> **Note on Tier 1A:** the WAF-vs-gateway boundary call ([[project_waf_vs_gateway_boundary]])
> deprioritized the token/HMAC half. Re-confirm scope before starting — the
> GraphQL caps half is uncontested WAF surface and can go regardless.

### Wave 2 — Availability hardening (foundation-first; capability Tier 2 deferred) · ~2–3 wk

| ✓ | Item | Stream | Effort | Why now |
|---|---|---|---|---|
| ✅ | **passive-upstream-health** — **P2+P3+P4 shipped** (per-member passive accounting + hysteresis marking; both forward-result sites wired; P3 half-open TCP recovery; **P4** default-on for pools without an active `health:` block + folded the TCP observer into one `spawn_passive_health_monitor`). Plan complete → [[passive-upstream-health]] | Foundation | M | Real-failure member health → LB; correctness |
| ✅ | **zone-aware-load-balancing** — **P1–P4 shipped, plan complete** (P1 self-zone; P2 same-zone preference; P4 capacity gate; **P3** observability — zone data in `/api/upstreams`, `waf_upstream_zone_routing_total` metric, "this node: az-a" dashboard readout). Deferred polish: per-member local badge/per-zone card (API ready; routes-page render path) → [[zone-aware-load-balancing]] | Foundation | M | Locality routing; shares the `LbStrategy::pick` touchpoint |
| ✅ | **ddos-cross-node-rps-aggregation** — **P1–P4 shipped, plan complete** (testable `tick_with_current` seam; fleet RPS aggregation via `ddos:fleet:rps:<sec>` buckets behind `ddos.spike_scope: per_node\|fleet`, default off, fail-safe to per-node; `fleet_rps` getter + dashboard panel scope tile/select + fleet-vs-node readout; docs). **Closes the Wave 2 availability theme** → [[ddos-cross-node-rps-aggregation]] | Foundation | M | Cluster-wide spike signal |
| ⏸ | Roadmap **Tier 2** — AI/LLM firewall — **deferred, research-gated** → [[ai-llm-firewall]] | Capability | M | Net-new differentiator (2A prompt-injection first; 2B/2C behind the SSE decision). NOT the `ai` ONNX detector. Needs research (signature corpus / FP calibration / streaming decision) before build — see plan §8 |

### Wave 3 — Durability bridge + config structural cleanup · ~2–3 wk
*Pulled forward to active (2026-06-24) — foundation-first.*

| ✓ | Item | Stream | Effort | Why now |
|---|---|---|---|---|
| ✅ | **redis-interim-durability P1–P3** — Track A shipped (#80 A0+A1, #81 A2, #82 A3): durable incidents / risk strikes / lifetime counters on `control:waf:*`, hot path unchanged → [[redis-interim-durability]] §10 | Foundation | M | Restart-fragile control state is durable *now* on existing Redis; forward-compatible seams for the Postgres endgame |
| ✅ | **config-single-source-of-truth H2a** (BootstrapConfig / DynamicConfig split) — Track B shipped (#83 types + watcher reconstruction; doc-canonicalization PR strip-on-store + merge-on-load + boot migration) → [[config-single-source-of-truth]] §11, [[project_config_h2a_split_progress]] | Foundation | M | Compiler-enforces the split; doc holds dynamic-only; a bootstrap field can't be stored in or override from the doc. Prereq for etcd (H2b) |
| ✅ | **smart-caching Phase 4** (stale-if-error + ETag revalidation, L1) — shipped 2026-06-27: `pool.cache.stale_if_error` (default off), retain-past-TTL + `CacheLookup::Stale`, serve-stale-on-5xx/error, `If-None-Match`→304 refresh. L2 stale-serve deferred → [[smart-caching]] | Foundation | S | Finishes a shipped feature |
| ✅ | **grpc-aware-proxying P1** — shipped 2026-06-27: gRPC responses forced onto the streaming path (`content_type_is_grpc`) so `grpc-status`/`grpc-message` trailers survive (buffered `.collect()` dropped them); 503-on-exhaustion guard (never buffer-degrade); wrapper-stack trailer survival verified. Unblocks unary + server-streaming, no request-side change. P2 (stream request body) onward deferred → [[grpc-aware-proxying]] | Foundation | S | Corrects the "gRPC already works" overstatement; makes 05-grpc.sh real |
| ☐ | **admin-accounts-rbac-sso P1** (self-service hardening — wire dormant password/TOTP/session-revoke/recovery endpoints, fleet-wide rate-limit, remove committed default creds) → [[admin-accounts-rbac-sso]] | Foundation | S/M | Standalone enterprise-readiness win on the single-admin model; prereq PREREQ-A ✅; no new infra. P2–P5 (multi-user → RBAC → audit → OIDC SSO) follow by capacity |
| ☐ | Roadmap **Tier 3 / 4** (Page Shield if PCI deadline; else bot-classifier enforcement Tier 4A) | Capability | M/M-L | PCI jumps the queue if a tenant deadline is live; otherwise 4A is an S win on existing scaffolding |

### Wave 4 — Scale-up endgame (constraint-gated) · L, multi-cycle
*Only once the one-dependency constraint lifts and scale justifies the second/third store.*

| ✓ | Item | Stream | Effort | Why gated |
|---|---|---|---|---|
| ✅ | **config-etcd-source-of-truth (H2b)** — shipped PR #86 (`d562a0d`) **constraint-respecting**: config+control plane on etcd behind the default-off `etcd_config` feature (`config_plane.store: shared_state \| etcd`, native Txn/Watch/Lease, `waf migrate-config-plane` cutover). Default build still Redis-only. Archived → [[config-etcd-source-of-truth]]. Next = **H3** control plane | Foundation | L | Inherited H1 single-writer + H2a dynamic-only doc, so it was a clean second implementor of the seam. Dual-read shadow-soak dropped (direct verified migration) |
| ☐ | **H3 config control plane** (canary / GitOps / multi-region) | Foundation | L+ | The config-arc tail; etcd (H2b) makes multi-region tractable |
| ☐ | **persistent-datastore-tracking-data** + **security-analytics-and-reporting** P2+ (ClickHouse firehose + Postgres durable control) | Foundation | L | Second/third infra dependency; redis-interim bridge holds until scale forces this |
| ☐ | Roadmap **Tier 5 / 6** (ML positive-security learning; managed ruleset / virtual patching) | Capability | L / M-L | Highest-effort capability; do once the foundation + earlier tiers are solid |

---

## 4. Critical-path callouts

- **Two prerequisites unlock disproportionately:** PREREQ-A (Redis volume, ~hours
  of ops) gates the *entire* durability theme; PREREQ-B (LB fail-open, small)
  gates both LB plans. Both are cheap and belong in Wave 0/1 — doing them early
  removes "blocked" from four downstream plans.
- **config-single-source-of-truth P0 is the cheapest high-value item** in the
  whole backlog (seed boot→doc v0, ~½–1 d) and unblocks the rest of the config
  arc. Treat it as Wave 0.
- **Touch the LB once:** sequence `passive-upstream-health` and
  `zone-aware-load-balancing` together (Wave 2) — they share `LbStrategy::pick`
  and the fail-open change.
- **etcd is shipped, the datastore decision remains:** etcd (H2b) landed
  behind a default-off feature, so it no longer waits on the constraint — the
  feature build ships when a second dependency is acceptable. The **ClickHouse +
  Postgres** datastore is still the open "lift the one-dependency constraint"
  call; until then, `redis-interim-durability` is the answer.
- **config-auto-restore:** don't build it standalone — its durability half is
  now **superseded by the shipped etcd config plane** (etcd removes the
  empty-store root cause), and its premise is softened by PREREQ-A. Revisit only
  for a fleet on `store: shared_state` over non-durable Redis; then it's just the
  split-brain / fleet-reconciliation design.

---

## 5. Strategic fork (decide before Wave 1)

The capability and foundation streams can run in parallel, but if capacity forces
a single focus, the roadmap and this backlog point different directions:

- **Capability-first** (roadmap's recommendation): Tier 1A → Tier 2. Maximizes
  *market/marketing* differentiation; ships visible WAAP-leader parity features.
- **Foundation-first** (this session's thread): the config arc + durability +
  LB correctness. Maximizes *operational trust* — removes silent config clobber,
  restart data-loss, and false upstream health.

**Recommendation:** run Wave 0 regardless (it's all cheap prereqs + green-branch
hygiene + the config P0), then **interleave** — one capability item + one
foundation item per wave, as the tables above show. Pick a single stream only if
a hard external deadline (PCI for Tier 3, a marketing window for Tier 2, or a
production durability incident) forces it.
</content>
