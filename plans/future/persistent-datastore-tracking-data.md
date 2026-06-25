# Persistent datastore for tracking data — durable control state + queryable history

**Status:** Future / designed-only (no production code yet)
**Filed:** 2026-06-22
**Origin:** Infra/enterprise-level question — *"should we use a persistent
database (PostgreSQL, …) to store the tracking data?"* This doc answers that
with a grounded audit of where WAF data lives today and a phased plan to add
persistence **off the request hot path only**.
**Decisions locked (2026-06-22):** ClickHouse for analytics + Postgres for
durable control state · full Phases 1–4 · feature-gated, **off by default**
(mirrors the existing `redis` Cargo feature).
**Related:** [`security-analytics-and-reporting.md`](./security-analytics-and-reporting.md)
(the ClickHouse warm-analytics tier in depth — this plan reuses it for the
analytics half and does **not** duplicate it),
[`config-etcd-source-of-truth.md`](../archive/config-etcd-source-of-truth.md),
[`config-auto-restore.md`](./config-auto-restore.md),
[`world-class-waf-roadmap.md`](./world-class-waf-roadmap.md),
[[project_cache_l2_single_node]], [[feedback_two_score_model]],
[[project_health_signals_reported_not_gating]].

---

## 1. Where WAF data lives today (the audit)

Aegis-Gate has **no relational database anywhere** — zero SQL crates in
`Cargo.lock`. Storage is a deliberate **three-tier split**, each tier justified
by latency in the architecture docs:

| Tier | Holds | Durability | Why this tier |
|---|---|---|---|
| **Redis hot state** | rate-limit windows (`g:rl:sw:*`), token buckets (`g:rl:tb:*`), per-IP risk (`g:risk:*`), auto-block flags (`g:block:*`), nonces (`g:nonce:*`), leader lease (`g:lease:*`) | Ephemeral by design; all wiped by `/__waf_control/reset_state` | p99 ≤ 1 ms; degrades to in-memory on Redis loss so a request never fails |
| **Redis config plane** | `config:waf:doc` (fleet source of truth), `config:waf:v:<n>` snapshots, `control:waf:modes` / `:reset_epoch` / `:access_list:*` | Durable-ish (CAS, no TTL, RDB on) but **no off-box volume mounted in shipped compose** → fragile | strong cross-node consistency, changes rarely |
| **Local-disk JSONL audit** | `./waf_audit.log` (contract record, 8 fixed fields), daily SHA-256 hash-chain `audit-YYYY-MM-DD.ndjson` (30-day TTL) | Survives restart | append-only forensic durability |

Getting raw events *out* is already strong (9 SIEM sinks: jsonl, syslog,
splunk_hec, kafka, cef, leef, ecs, ocsf). What is missing is **in-product
durability + queryability** for two distinct classes of "tracking data".

### 1a. The real gaps — ephemeral today, arguably should be durable

| Data | Current sink | Survives restart? | Queryable history? | Class |
|---|---|---|---|---|
| **`RiskTracker` strikes + trust** (`aegis-security/src/risk/tracker.rs`) | in-process `DashMap` | **No** | No | control state |
| **Incident lifecycle** ack/snooze/resolve/notes (`aegis-control/src/api/incidents.rs`) | `Mutex<HashMap>` | **No** | No | control state |
| Attack distribution / Top Attackers (`api/attacks.rs`) | in-mem 15-min ring | **No** | No | analytics |
| Overview stats + ~1 h timeseries (`api/stats.rs`) | in-mem aggregator | **No** | No | analytics |
| Per-request decisions / security events | `waf_audit.log` (**231 MB** at repo root) + NDJSON chain | Yes | **grep-only** — `/api/analytics/query` range returns `503 no_history_backend` | analytics |
| Per-IP cumulative risk (`RiskEngine`, `g:risk:*`) | Redis, no TTL | Redis: yes | current value only | hot state — *leave on Redis* |

Two failure modes stand out:
- **`RiskTracker` loses lifetime strike counters on every restart** → the
  "permanent block" guarantee the module advertises silently evaporates.
- **Incident acknowledgements/notes vanish on restart** → operator workflow
  state is not durable.

### 1b. The hard constraint

This is an **inline reverse proxy at ~5k RPS/pod** with a documented sub-ms
posture (`X-WAF-Overhead-Latency`, p99 ≤ 1 ms Redis tier). **A synchronous DB
call per request is architecturally incompatible.** Every storage choice in the
codebase is latency-justified; any new persistence must be **off the hot path**.

## 2. Decision

**Yes — add persistence, but only as an off-hot-path durability + analytics
layer. The Redis hot tier and the data plane are untouched.**

Two purpose-built stores, both behind Cargo features that are **off by default**
(exactly like today's `redis` feature):

- **ClickHouse** — the high-volume, append-only **analytics** firehose
  (decisions, security events, attack rollups). OLAP, columnar, native TTL
  retention. *This is the warm tier already designed in
  [`security-analytics-and-reporting.md`](./security-analytics-and-reporting.md)
  — that plan owns the depth; this plan adopts it as the analytics half.*
- **PostgreSQL** — the low-volume, mutable, **must-survive-restart control
  state** (incidents lifecycle, RiskTracker strikes/trust) where transactional
  correctness matters and volume is tiny.

Neither is ever called synchronously from a request.

### Why two stores, not one

| | ClickHouse | PostgreSQL |
|---|---|---|
| Workload | append-only, 5k-RPS firehose, OLAP top-N over 100s of M rows | small mutable rows, frequent UPDATE, transactional |
| Volume | very high | very low (incidents, capped 1M risk keys) |
| Query | analytics/range/aggregate | point read/update by key |
| Wrong tool because | row-level UPDATE is painful in CH | high-cardinality event analytics is heavy in PG |

A single Postgres+TimescaleDB engine was considered (and is the fallback if
operating two stores is unacceptable) but ClickHouse is the better OLAP fit at
this event volume and the repo already has a `clickhouse-io` skill.

## 3. Target architecture

```
   in-mem ring (exists) ◄── live "last N hours" view  ── stays the hot read tier
        ▲                    (api/attacks.rs, api/stats.rs — never depends on a DB)
        │
   AuditBus (in-memory) ──┬─ (exists) Kafka / Splunk / Syslog / jsonl sinks
   [aegis-core/audit.rs]  │
                          └─ NEW: ClickHouse sink ──► ClickHouse ──OLAP──► /api/analytics, /api/audit, history
                                  async · batched ·   ▲          (waf_decisions, waf_security_events, waf_attack_rollup)
                                  bounded queue ·     │
                                  drop-on-full ·  severity-routed + redacted at write
                                  + metric        (full / sampled / counts-only / drop)

   Control-plane state ─── write-through + load-on-boot ──► PostgreSQL ── incidents lifecycle, RiskTracker strikes/trust
   [incidents.rs, risk/tracker.rs]                          (source of truth; in-mem = read cache)
```

**Wire-in seam already exists:** the in-memory `AuditBus`
(`aegis-core/src/audit.rs:312`) already fans out to pluggable sinks
(`AuditSinkConfig` variants: Kafka/Splunk/Syslog). The ClickHouse writer is just
one more subscriber — **no new emit sites on the data plane.** Control-plane
state is mutated in only a handful of low-frequency admin handlers, so
write-through there is trivially off the hot path.

**Two-tier read model (from AWS/Cloudflare/Fastly — see §9):** the existing
in-memory ring stays the *live* tier (instant "recent events", sampled under
load); ClickHouse is the *durable history* tier. The live view must never block
on or depend on the DB — exactly today's behaviour, now with history added
behind it rather than replacing it.

**Severity-routed persistence (Fastly's "signals" model — see §9):** do **not**
store full detail for every request. Route by detection severity, reusing the
existing `is_attack` / detector-tag logic in `api/attacks.rs`:
`attack/CVE → full row` · `anomaly/bot → sampled full + always counts` ·
`informational → counts-only (rollup)` · `clean allow → drop` (or low-rate
sample). This one rule bounds storage without losing forensic value. Redact
secrets/PII (passwords, tokens, cookies, matched-value fields) **at write time**
— directly relevant given this repo's prior scanned-secrets-in-a-dump incident.

## 4. Schemas

### ClickHouse (canonical row = `AuditEvent`, `aegis-core/src/audit.rs:185`)
- `waf_decisions` — `MergeTree`, `PARTITION BY toDate(ts)`, `ORDER BY (ts, ip)`,
  `TTL ts + INTERVAL 30 DAY` (align with existing audit retention). Columns
  mirror `MinimalAuditEntry` (request_id, ts_ms, ip, method, path, action,
  risk_score, mode, rule_id, tier).
- `waf_security_events` — `class=Detection` rows + `detector`, `rule_id`,
  `risk_score`, `route_id`.
- `waf_attack_rollup` — `AggregatingMergeTree` **materialized view** over the
  above (per detector / route / tier / action / geo / ASN, 1-min/1-h/1-day
  buckets) → replaces the in-memory 15-min ring + 1 h timeseries with real
  history. CH MVs do the rollup natively (no separate leader-only job).

### PostgreSQL (low volume, mutable)
- `incidents` — id, status, ack_by, ack_at, snooze_until, resolved_at,
  notes (jsonb), updated_at. Backs `api/incidents.rs`.
- `ip_risk` — risk_key, ip, device_fp, session, score, strikes, trust, blocked,
  first_seen, last_seen. Durable backing for `RiskTracker`.
- `schema_migrations`.

## 5. Phased plan

| Phase | Scope | Effort |
|---|---|---|
| **P0 — Schema + config + features** | `AuditSinkConfig::ClickHouse { url, batch, queue_depth, ttl_days }` and `[persistence.postgres]` section in `aegis-core/src/config.rs`, both validated + default-disabled. Cargo features `clickhouse` + `postgres` in `aegis-control`, re-exposed in `aegis-bin` (mirror the `redis` feature plumbing). Deps: `clickhouse` (HTTP batch) + `sqlx` (postgres, compile-time-checked), both optional. DDL/migration files. **No behavior change.** | **S–M** |
| **P1 — ClickHouse async event sink + read path** (the 80% win) | New `aegis-control/src/audit/sinks/clickhouse.rs` modeled on `kafka.rs`: bus subscriber, bounded channel, batched async insert, drop-on-full + Prometheus drop counter. **No data-plane coupling.** Add the **severity router + write-time redaction** (see §3). Keep the in-mem ring as the live tier; wire read side: `/api/analytics/query` range path (`api/analytics.rs`, currently `503 no_history_backend`) and `/api/audit` history read from CH for ranges beyond the live window. | **M** |
| **P2 — Postgres durable control state** | `aegis-control/src/persistence/postgres.rs` (pool, migrate-on-boot). `IncidentState`: write-through on every ack/snooze/resolve/note + load-on-boot; in-mem `Mutex<HashMap>` becomes a read cache. `RiskTracker`: debounced write-through of strike/trust + hydrate on boot so "permanent block" survives restart (the **fail2ban/CrowdSec pattern** — relational store is system of record, enforcer reads it; see §9); DashMap stays the hot read cache (cache-aside, **Redis/PG never the per-request lookup**). | **M** |
| **P3 — Analytics rollups + dashboard history** | ClickHouse materialized views for attack distribution / Top Attackers / threat time-series; point `api/attacks.rs` + `api/stats.rs` chart endpoints at them so the dashboard shows real history beyond the live window. (Subsumed by / shared with `security-analytics-and-reporting.md` P1–P2.) | **M** |
| **P4 — Ops hardening** | Migrations runner; CH table TTL + PG retention aligned with GDPR export (`residency.rs`); backup notes; **optional** managed-CH/managed-PG wiring in Helm (not provisioned in-chart — same posture as Redis today); rotation for the 231 MB `waf_audit.log`. | **S–M** |

**Start at P0+P1** — self-contained, delivers queryable history, zero risk to
the data plane. P2 is the independent "durability of control state" win.

## 6. Non-goals / boundaries

- **Not** on the request hot path — every write is async/batched off the audit
  bus or in a low-frequency admin handler. The data plane never blocks on a DB.
- **Not** a replacement for Redis hot state — rate limits, risk scores, nonces,
  leases stay ephemeral on Redis by design ([[feedback_two_score_model]]).
- **Not** a replacement for customer SIEM — the 9 existing egress sinks remain;
  this is in-product durability/analytics.
- **WAF-vs-gateway boundary respected** — observability of WAF decisions and
  WAF control state, not business-event storage.

### Deliberately NOT building (over-engineering the research flagged — see §9)

The hyperscaler pipelines carry machinery that only exists to serve multi-tenant
planetary scale. For a single-org self-hosted WAF these are YAGNI; defer each
until a single node is genuinely saturated (same logic as the existing
"Redis Cluster deferred until one Redis outgrows memory" stance,
[[project_cache_l2_single_node]]):

- **A Kafka/Firehose ingestion tier** — a bounded in-process channel + batched
  writer replaces it. Add Redpanda/Kafka only if one writer node saturates.
- **Cloudflare-style full ABR** (7 resolution tables + a resolution-selecting
  query planner) — one raw table + one minute-rollup MV is enough.
- **Multi-node ClickHouse sharding / 3× replication** — single-node + backups
  first.
- **A GraphQL analytics façade** — query ClickHouse over SQL directly; Grafana
  reads it.
- **A multi-destination "diagnostic settings" routing fabric** — one durable
  sink, not a router (the 9 SIEM egress sinks already cover forwarding).
- **Cross-tenant reputation exchange** (Cloudflare NLX / Fastly NLX) —
  meaningless for one org; local reputation + optional public threat feeds.

## 7. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Any sink stalls the request path | **CRITICAL** | Async bounded-queue, drop-on-full + metric, never back-pressure the bus — same contract as the existing Kafka/JSONL sink |
| Two new stateful deps to operate (HA, backup) | HIGH | Both feature-gated off; managed CH/PG externalizes ops; single-node builds untouched |
| 5k-RPS write volume | MEDIUM | ClickHouse is built for it; batch inserts + daily partitions + TTL; bounded top-N + "other" bucketing for rollups |
| PG dual-write inconsistency (P2) | MEDIUM | PG = source of truth, in-mem = cache, reconcile on boot |
| Cross-store read consistency (a decision reads Redis counters + PG reputation at different instants) | MEDIUM | Accept eventual consistency; keep the per-request hot path on Redis/in-mem only, treat PG as the durable backing it hydrates from — never a synchronous cross-store read mid-decision |
| PII / retention / compliance | MEDIUM | events carry IP/headers — honor DLP/verbosity model; **redact at write time**; configurable retention + field redaction per compliance modes |
| ClickHouse weak at ad-hoc full-text incident hunting | LOW | aggregation is the dominant WAF query (top IPs/rules/risk over time) — CH's strength; accept SQL `LIKE`/token search, or add an OpenSearch index only if free-text hunting becomes a hard requirement |
| Scope creep across 4 phases | MEDIUM | P1 is independently shippable; P2 independent of P1 |

## 8. Wire-in points (already exist)

- **Audit bus** (`AuditBus`, `aegis-core/src/audit.rs:312`) — the CH writer is
  another subscriber next to the SIEM sinks. No new emit sites.
- **`AuditSinkConfig`** (`aegis-core/src/config.rs`) — add a `ClickHouse`
  variant alongside Kafka/Splunk/Syslog.
- **`api/incidents.rs` / `risk/tracker.rs`** — the only mutation points for the
  control state being made durable; small, low-frequency surfaces.
- **Cargo feature plumbing** — copy the existing `redis` feature pattern
  (`crates/aegis-proxy/Cargo.toml` → `aegis-bin/Cargo.toml`) for `clickhouse`
  and `postgres`.
- **Helm** — managed-datastore wiring mirrors how Redis is left to the operator
  (`deploy/helm/aegis-gate/values.yaml`), not provisioned in-chart.

## 9. How the industry does this (research validation, 2026-06-22)

Researched Cloudflare, Fastly, AWS WAF, GCP Cloud Armor, Azure WAF, and the
open-source field (Coraza/ModSecurity/CRS, SafeLine, BunkerWeb, CrowdSec,
fail2ban). **The proposed Redis + PostgreSQL + ClickHouse split is the validated,
mainstream shape — not a novel bet.**

### The one pipeline everyone converges on

```
hot-path emits structured event  →  async/best-effort ingest  →  columnar/partitioned store  →  SQL query  →  dashboards + alerting
   (decision made locally,           (sampled/redacted at         (TTL retention, ~30d hot       (Athena / BigQuery /
    never blocks on storage)          source, drop-on-overflow)    default everywhere)            KQL / ClickHouse SQL)
```

| Vendor | Ingest | Durable store | Query |
|---|---|---|---|
| Cloudflare | edge → Kafka | **ClickHouse** (MergeTree + rollup MVs, ABR sampling) | GraphQL Analytics API |
| Fastly NGWAF | agent → cloud (async 30s, redacted, **signal-severity routed**) | time-series + sampled request data, ≤30d | console |
| AWS WAF | CloudWatch / Firehose | S3 (gzip→Parquet, date-partitioned) | Athena / Logs Insights |
| GCP Cloud Armor | Cloud Logging | BigQuery (partitioned) / GCS | BigQuery SQL / Log Analytics |
| Azure WAF | Azure Monitor | Log Analytics (Kusto) / Storage | KQL / Sentinel |

Cross-vendor invariants that shaped this plan: decision path **decoupled** from
storage; emission **async + best-effort, drop-under-load** (AWS explicitly
accepts dropped records); **sample/filter/redact at source**; **append-only
immutable** event rows; **columnar + time-partitioning** as the cost lever;
**~30-day hot retention** then cold archive; and **reputation/rate-limit state
kept OUT of the log pipeline** in a separate fast store — logs only *record* the
outcome.

### Why ClickHouse for the analytics tier (concrete numbers)

- **Cloudflare** moved HTTP analytics off Postgres+Citus (which "couldn't scale")
  to ClickHouse; for *security/error logs* they replaced Elasticsearch and cut
  per-row storage **600 B → 60 B (~10×)** and insert CPU/mem **~8×**, letting
  them **stop sampling and store 100%**.
- **Uber** moved logging ELK → ClickHouse: ~10× ingest/node, >50% hardware
  saving, because ">80% of queries are aggregations" — exactly the WAF profile
  (top IPs/rules/risk over time). Corroborated by Zomato, Didi, Exabeam SIEM
  (~1.2M events/s on ClickHouse).
- The aggregation-dominated WAF query profile is precisely where ClickHouse beats
  Elasticsearch and Postgres on cost+speed. OpenSearch only wins if free-text
  SIEM hunting is a hard requirement; **Postgres+TimescaleDB stays the documented
  fallback** if operating two stores is unacceptable.

### Why Postgres-as-source-of-truth for durable control state

- **fail2ban** persists bans in **SQLite** so it can reinstate them after
  restart; **CrowdSec** stores decisions/bans in **SQLite default → MySQL/Postgres
  at scale**, and enforcers read the relational store. This is exactly the P2
  model for `RiskTracker` "permanent block" survival.
- **Redis is positioned below a relational DB for durability** by its own docs
  (RDB = lossy, AOF `everysec` ≈ ≤1 s loss; "use both" only to *approach*
  Postgres-level safety). So: keep durable control state authoritative in PG,
  treat Redis/DashMap as **cache-aside**. This also reframes the existing
  fragile `config:waf:doc`-in-Redis durability ([[project_config_plane_doc_vs_file]]).

### Closest shipped analogs + a real three-store production system

- **BunkerWeb** ships the same split: relational DB (config/UI) + **Redis/Valkey
  for bans, reports, rate-limit counters, sessions** — and its docs state Redis
  is *how you make bans/reports survive restart* (default in-memory store is lost
  on restart — the exact gap this plan closes for Aegis).
- **SafeLine CE** = single PostgreSQL for both config and attack events (no
  Redis) — proof a relational store alone is viable at smaller volume.
- **Coraza v3 (the leading Go WAF) has NO persistent collections** — cross-request
  state is "your problem." A Rust WAF must build this layer; there's no library
  to lean on, which is *why* this plan exists.
- **Langfuse** (open-source, security-adjacent observability) runs **Postgres
  (transactional) + ClickHouse (OLAP traces) + Redis (queue/cache)** tier-for-tier
  — external proof the exact three-store shape works self-hosted.

This is recognized as **polyglot persistence** (Fowler): choose the store by
access pattern, with Redis/DashMap as cache-aside and the DBs as systems of
record. Full source URLs are in the research thread for this plan (2026-06-22).

---

**See also:**
[`security-analytics-and-reporting.md`](./security-analytics-and-reporting.md)
(the authoritative deep-dive for the ClickHouse analytics tier — this plan's
P1/P3 are the same work, scoped here alongside the Postgres control-state half),
[`config-etcd-source-of-truth.md`](../archive/config-etcd-source-of-truth.md) (the
parallel "move the *config* plane off Redis" track),
[`docs/observability/siem-log-forwarding.md`](../../docs/observability/siem-log-forwarding.md)
(existing egress sinks).
