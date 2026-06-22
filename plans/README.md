# Plans

Simplified 2026-06-01 to focus on the **main plan**. The top level
holds the operating plan + the status matrix; forward-looking work is
the roadmap + the open backlog; everything closed or parked lives in
[`archive/`](./archive/). (Updated 2026-06-10: the cluster-sync, unified
zero-trust/mTLS, and multi-node-consistency plans all shipped/dropped and
moved to `archive/`; both `issues/` entries resolved → `issues/archived/`.
`future/` now holds the world-class roadmap and `smart-caching.md` (Phase 4
open). 2026-06-14: `sse-streaming-support.md` shipped and the
`ws-global-mode-and-cluster-config-sync` PLAN shipped — both → `archive/`.
**2026-06-19:** the hand-maintained `Implement-Progress.md` + `docs/progress/`
were removed (stale, contradicted git) — **status now = git history +
[`issues/`](./issues/README.md)**; 7 resolved issues archived → `issues/archived/`
(per-route monitor QC, btc-miss recon, FP-precision round 2, css/jwt gap reports,
the superseded 06-14 sec-regression triage, the host security audit).)

## Layout

```
plans/
├── README.md                  ← this file (entry point)
├── plan.md                    ← MAIN PLAN — assistant protocol + repo conventions
├── implementation-matrix.md   ← doc-by-doc Implemented / Partial / Designed / Deferred
├── future/
│   ├── world-class-waf-roadmap.md         ← strategic ordering (Tiers 0–6)
│   └── smart-caching.md                    ← only active forward track (Phase 4 open)
├── issues/                    ← field-found issues (Open / Resolved-archived); see its README
└── archive/                   ← closed / shipped / parked plans (read-only history,
                                  incl. issue-fix/ QA sprints)
```

## Start here

1. **[`plan.md`](./plan.md)** — the main plan. Assistant protocol + repo
   conventions. Read this when picking up any task.
2. **[`implementation-matrix.md`](./implementation-matrix.md)** — what's
   actually shipped vs specified, per doc.
3. **[`issues/README.md`](./issues/README.md)** + recent **git history** —
   the current state of play (open backlog, what shipped, by when). There
   is no hand-maintained progress snapshot; git + the issues board are the
   source of truth.

## `future/`

- **[`world-class-waf-roadmap.md`](./future/world-class-waf-roadmap.md)** —
  the north-star plan: the ordering document that grades Aegis against the
  2025–2026 WAAP leaders, names code-verified gaps, and sequences them into
  Tiers 0–6. Read it before picking up new capability work; slot any new
  net-new capability into a tier.
- **[`smart-caching.md`](./future/smart-caching.md)** — the one feature track
  with work still open: Phases 1–3 shipped (per-upstream L1 + L2/Redis-Cluster
  cache); **Phase 4 remaining** (`stale-if-error`, ETag revalidation).
- **[`config-auto-restore.md`](./future/config-auto-restore.md)** — deferred
  follow-up to the shipped config-loss *detect+alert* fix: auto re-publish the
  last-known-good config after a Redis wipe. Blocked on a fleet split-brain
  decision (single-writer election). Not started.
- **[`config-etcd-source-of-truth.md`](./future/config-etcd-source-of-truth.md)** —
  durability/infra: move the config source of truth (`config:waf:doc` +
  `control:waf:*`) from Redis to **etcd** for native Txn/Watch/Lease and Raft
  durability. A trait split (durable config plane → etcd; hot ephemeral keyspace
  stays Redis), additive and opt-in (default stays Redis). Deferred until the
  hackathon one-dependency constraint lifts. Not started.
- **[`passive-upstream-health.md`](./future/passive-upstream-health.md)** —
  deferred follow-up (3.2a) to the shipped *honest upstream badge* fix: derive
  member health from real traffic and feed the LB. Must ship with a fail-open
  LB change first (`LbStrategy::pick` currently fails closed). Not started.
- **[`security-analytics-and-reporting.md`](./future/security-analytics-and-reporting.md)** —
  enterprise **analytics + reporting**: durable, historical, queryable security-event
  store (today the dashboard analytics are a 15-min in-memory ring, lost on restart) +
  Analytics Query API + time-range dashboards + scheduled/compliance reports + cold
  Parquet tier. Cloudflare / AWS-WAF / GCP-Cloud-Armor parity. Designed-only; start at
  P0+P1. Not started.
- **[`persistent-datastore-tracking-data.md`](./future/persistent-datastore-tracking-data.md)** —
  the **"should we add PostgreSQL?"** infra decision, grounded in an audit of where WAF
  data lives today (Redis hot tier / Redis config plane / local JSONL — no RDBMS). Verdict:
  yes, **off the hot path only** — **ClickHouse** for the analytics firehose (shares the
  analytics plan above) + **PostgreSQL** for durable control state that currently dies on
  restart (`RiskTracker` strikes/trust, incident lifecycle). Feature-gated off by default.
  Designed-only; start at P0+P1. Not started.
- **[`redis-interim-durability.md`](./future/redis-interim-durability.md)** —
  the **dependency-light bridge** to the plan above: reuse the Redis we already
  ship to make the restart-fragile state durable *now* instead of standing up
  ClickHouse+Postgres. Split: **control state + small lifetime counters → durable
  `control:waf:*` Redis** (incidents, `RiskTracker` strikes/trust via debounced
  off-path flush, `blocks_total`); **analytics rings/timeseries wait for
  ClickHouse**. Hard prereqs: a mounted Redis data volume + reset-path wiring.
  Hot path stays `DashMap`-only (no per-request I/O); RiskTracker flush is
  coalesced + batched (pipelined `HSET`) and **strictly yields to enforcement**
  (single-conn-skip so it can't starve the shared Redis pool under DDoS).
  Acceptance gated on the existing `tests/load/` k6 suite (`risk-strikes`,
  `ddos-burst`, `failover-burst`, `loadmode-degradation`) — persistence on-vs-off
  must be latency-neutral. Designed-only; start at P0+P1. Not started.
- **SSE / streaming support** — ✅ **SHIPPED 2026-06-14**, archived to
  [`archive/sse-streaming-support.md`](./archive/sse-streaming-support.md).
  Streams `text/event-stream` through the data plane instead of buffering
  (`UnsyncBoxBody` body, media-type branch in `forward()`, raw-byte idle
  timeout, max-concurrent-streams cap, audited inspection bypass). Only the
  Option C incremental chunk-inspection item is deferred. Docs:
  [`../docs/data-plane/sse-streaming.md`](../docs/data-plane/sse-streaming.md).

> **Archived 2026-06-12.** [`archive/jwt-and-smuggling-detection.md`](./archive/jwt-and-smuggling-detection.md)
> shipped and left `future/`: the `jwt_inspection` detector (alg:none, jku/x5u
> SSRF, x5c/jwk inline, kid traversal/SQLi, time-claim forge → block;
> role-escalation log_only) plus the `header_injection` smuggling-hygiene rules
> (`smuggling_cl_te`/`_multi_cl`/`_multi_te`/`_h2_forbidden`, attribution +
> defense-in-depth). The two security-team source reports it answered also
> resolved → [`issues/archived/`](./issues/archived/) (`JWT_ATTACK_REPORT.md`,
> `HTTP_SMUGGLING_REPORT.md`), along with the velocity / detector-toggle /
> config-lag fix and the Zero Trust page simplify. `future/` is now just the
> world-class roadmap + `smart-caching.md`.

> **Archived 2026-06-11.** The two design-only forward tracks shipped and moved
> to `archive/`: [`archive/proxy-protocol.md`](./archive/proxy-protocol.md)
> (PROXY-protocol real client IP behind an L4 LB — PR #26) and
> [`archive/websocket-message-inspection.md`](./archive/websocket-message-inspection.md)
> (WebSocket text-frame inspection, `WS-MSG` — PR #27). The cluster-QC v1/v2 fix
> plans + QC reports also resolved → [`issues/archived/`](./issues/archived/); the
> only carry-over is **F14** (audit/since latency, pending live telemetry — see the
> issues README). `future/` is now the world-class roadmap + `smart-caching.md`.

> **Archived 2026-06-10.** Three docs left `future/`/`plans/` once their work
> shipped or was dropped:
> [`archive/cluster-mode-multinode-sync.md`](./archive/cluster-mode-multinode-sync.md)
> (cluster console sync — all phases shipped),
> [`archive/zero-trust-unified-mtls.md`](./archive/zero-trust-unified-mtls.md)
> (the unified `zero_trust` downstream+upstream mTLS rebuild — P1–P5 shipped;
> was `future/mTLS.md`), and
> [`archive/multi-node-consistency-implementation.md`](./archive/multi-node-consistency-implementation.md)
> (C-1…C-5 shipped or dropped). The two `plans/issues/` entries also resolved
> and moved to [`issues/archived/`](./issues/archived/).

> **Trimmed 2026-06-06.** The two detailed backlog specs that used to live
> here moved to `archive/` so `future/` stays a single north-star doc:
> [`archive/observability-otel-and-alerts.md`](./archive/observability-otel-and-alerts.md)
> (OTLP export — traces + SLO-message P1 shipped 2026-06-02; metrics/logs
> live smoke, app-side push, SIGTERM flush, and alert P2–P4 remain) and
> [`archive/routing-upstream-improvements.md`](./archive/routing-upstream-improvements.md)
> (Routing & Upstreams UX + feature backlog). They remain valid designs —
> the status matrix points at their archive paths.

> **AI Operator Copilot — ✅ SHIPPED (P0–P4 + YAML-config centralization),
> 2026-06-02/03.** The build plan moved to
> [`archive/ai-operator-copilot.md`](./archive/ai-operator-copilot.md);
> the feature spec lives at
> [`../docs/control-plane/ai-operator-copilot.md`](../docs/control-plane/ai-operator-copilot.md).

> **Trimmed 2026-06-01.** The per-feature backlog specs (alerts-refactor,
> bot-classifier-enforcement, compliance-profiles, smart-caching,
> audit-*, rule-non-block-actions, risk-composite-key-data-plane,
> unwired-stubs-catalog, advanced-features intake) were moved into
> [`archive/`](./archive/) to keep `future/` focused. They remain valid
> designs — the roadmap still references them by their archive paths. The
> API-security guard wire-up (old Tier 1A / B1) is **deprioritized**
> pending a WAF-vs-gateway boundary call (see the matrix `api-security`
> row).

## `archive/`

Closed, shipped, or parked plans kept for history — don't restart them;
write a new plan that references the archived one. Notable subfolders:
[`archive/issue-fix/`](./archive/issue-fix/) (older QA sprints),
[`archive/phase-b-2026/`](./archive/phase-b-2026/) (B1..B6 packaging),
[`archive/dashboard-enterprise/`](./archive/dashboard-enterprise/).

## Working with plans

1. **Search `archive/` first** — existing-feature context is usually there.
2. **New multi-step work** — drop a plan in `plans/` (or `plans/future/`
   for a net-new capability; also slot it into a tier in the roadmap),
   then move it to `archive/` once it ships.
3. **Don't restart `archive/`** — closed plans are reference only.
