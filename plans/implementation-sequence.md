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

## ⏩ Resume here (as of 2026-06-23)

**Wave 0 — ✅ complete.** **Wave 1 — ✅ complete:** config H1·P0 (#74),
config H1·P1+P2 dual-authority fix (#77), PREREQ-B LB fail-open (#78), and
Tier-1A GraphQL caps (#79) all shipped.

**Next up — Wave 2 foundation first (capability Tier 2 deferred):**
1. **`passive-upstream-health`** + **`zone-aware-load-balancing`** — do **together**
   (both unblocked by PREREQ-B; they share the `LbStrategy::pick` touchpoint, so
   touch the LB once). **Recommended next.**
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

**Config arc:** the near-term correctness work (H1) is done; the long-term
structural split (H2a `BootstrapConfig`/`DynamicConfig`) and etcd (H2b) sit in
Wave 3 / Wave 4 — not started.

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
   H1 (P0 seed boot→doc v0, S)  ──standalone correctness win, no prereq
     └─ H1 (P1-P3 single writer, M)
          └─ H2a (BootstrapConfig/DynamicConfig type split, M)
               └─ H2b = config-etcd-source-of-truth (L, constraint-gated)
                    └─ H3 config control plane (canary/GitOps/multi-region, L+)
   (config-auto-restore is superseded for its durability half by H2b;
    keep only its fleet-reconciliation idea, and only if etcd slips)

[STANDALONE] (no prereqs, slot anytime by capacity)
   ├─ ddos-cross-node-rps-aggregation (M)
   └─ smart-caching Phase 4 (stale-if-error + ETag revalidation, S)
```

**Constraint gate:** the heavy infra plans — **etcd** (H2b) and the **ClickHouse +
Postgres** datastore (persistent-datastore-tracking-data + security-analytics P2+)
— are explicitly deferred until the *hackathon one-dependency constraint lifts*.
`redis-interim-durability` is the deliberate **dependency-light bridge** that
buys the durability those plans give, using the Redis already in the stack, until
then.

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
| ☐ | **passive-upstream-health** (after PREREQ-B) — **next** | Foundation | M | Real-failure member health → LB; correctness |
| ☐ | **zone-aware-load-balancing** (after PREREQ-B + node self-zone) — **do with passive-health** | Foundation | M | Locality routing; shares the `LbStrategy::pick` touchpoint with passive-health — do together to touch the LB once |
| ☐ | **ddos-cross-node-rps-aggregation** | Foundation | M | Cluster-wide RPS; standalone; slot by capacity |
| ⏸ | Roadmap **Tier 2** — AI/LLM firewall — **deferred, research-gated** → [[ai-llm-firewall]] | Capability | M | Net-new differentiator (2A prompt-injection first; 2B/2C behind the SSE decision). NOT the `ai` ONNX detector. Needs research (signature corpus / FP calibration / streaming decision) before build — see plan §8 |

### Wave 3 — Durability bridge + config structural cleanup · ~2–3 wk

| ✓ | Item | Stream | Effort | Why now |
|---|---|---|---|---|
| ☐ | **redis-interim-durability P1–P3** (durable control state: incidents, RiskTracker strikes/trust, block counters) | Foundation | M | Makes restart-fragile state durable *now* on existing Redis; forward-compatible seams for the Postgres endgame |
| ☐ | **config-single-source-of-truth H2a** (BootstrapConfig / DynamicConfig type split) | Foundation | M | Compiler-enforces the §3 split; retires the file-vs-doc staleness class for good; prereq for etcd |
| ☐ | **smart-caching Phase 4** (stale-if-error, ETag revalidation) | Foundation | S | Finishes a shipped feature; slot by capacity |
| ☐ | Roadmap **Tier 3 / 4** (Page Shield if PCI deadline; else bot-classifier enforcement Tier 4A) | Capability | M/M-L | PCI jumps the queue if a tenant deadline is live; otherwise 4A is an S win on existing scaffolding |

### Wave 4 — Scale-up endgame (constraint-gated) · L, multi-cycle
*Only once the one-dependency constraint lifts and scale justifies the second/third store.*

| ✓ | Item | Stream | Effort | Why gated |
|---|---|---|---|---|
| ☐ | **config-etcd-source-of-truth** (H2b) + then **H3** control plane | Foundation | L / L+ | Adds etcd; clean now because it inherits H1 single-writer + H2a dynamic-only doc |
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
- **etcd vs ClickHouse/Postgres are the same decision:** both are "lift the
  one-dependency constraint." If that decision lands, Wave 4's infra items can be
  planned as one infra epic; until then, `redis-interim-durability` is the answer.
- **config-auto-restore:** don't build it standalone — its durability half is
  superseded by etcd (H2b) and its premise is softened by PREREQ-A. Revisit only
  if etcd slips and a fleet wipe is still a live risk; then it's just the
  split-brain/fleet-reconciliation design.

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
