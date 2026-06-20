# Security Analytics & Reporting — durable, historical, queryable

> **Status:** Designed-only / future track (2026-06-19). No production
> code yet. This is the plan for turning Aegis's *ephemeral, 15-minute,
> in-memory* analytics into an enterprise-grade analytics + reporting
> surface comparable to Cloudflare Security Analytics, AWS WAF logging +
> CloudWatch/Athena, and GCP Cloud Armor + BigQuery.
>
> Deliberately deferred for the hackathon (time/resource) — the in-memory
> ring is correct and benchmark-neutral for the contest. This doc is the
> "do it properly for a product" plan.

---

## 1. Where we are today (the gap)

| Surface | Today | Limitation |
|---|---|---|
| Attack distribution / Detector breakdown / Top attackers / Bot mix | `AttacksAggregator` — in-memory `VecDeque`, **900 s window**, count-capped, **per-node**, **lost on restart** (`crates/aegis-control/src/api/attacks.rs`) | No history beyond 15 min; no cross-node view; nothing survives a redeploy |
| Reports page | Stub — CSV/JSON export of the audit ring (capped ~200), "scheduled delivery not built yet" (`assets/dashboard/src/pages.jsx` `PageReports`) | Can't produce an executive/compliance report or a 30-day trend |
| Audit forwarding | **Strong** — 9 sinks (jsonl, syslog, splunk_hec, kafka, cef, leef, ecs, ocsf) | This is *egress to someone else's analytics*, not in-product analytics |
| Metrics | Prometheus + OTel→SigNoz | Operational metrics, not security-event analytics |

**Conclusion:** getting raw events *out* is solved. What's missing is the
**warm analytical layer** — a durable, queryable store of security events
that powers historical dashboards, ad-hoc investigation, and scheduled
reports *inside the product*. That's the enterprise differentiator.

## 2. What the reference products do

| | Hot / sampled | Durable store | Query surface | Reports |
|---|---|---|---|---|
| **Cloudflare** | Security Events (live, sampled) | Logpush → S3/GCS/Splunk/Datadog | **GraphQL Analytics API** (rollups, top-N, filters) | Scheduled + Security Analytics insights |
| **AWS WAF** | Sampled requests (last 3 h) | Full logs → CloudWatch Logs / S3 / Kinesis | CloudWatch Logs Insights, **Athena** over S3 | CloudWatch dashboards |
| **GCP Cloud Armor** | Cloud Logging live | → **BigQuery** | Logs Explorer + BigQuery SQL | Looker / Security Command Center |

Common shape: **hot path emits structured events → durable analytical
store → query/analytics API → dashboards + scheduled reports + alerting.**
Aegis already has the first arrow (the audit bus + sink abstraction); this
plan adds the rest.

## 3. Target architecture — a 3-tier data model

```
                 audit bus (exists)
                        │
        ┌───────────────┼────────────────────────────┐
        ▼               ▼                              ▼
  TIER 1 HOT      TIER 2 WARM (new)              TIER 3 COLD (mostly exists)
  in-mem ring     durable analytical store        object store + SIEM
  ~15 min         30–90 day rollups + raw          Parquet on S3/GCS,
  real-time       queryable (OLAP)                 the 9 existing sinks
  (unchanged)            │
                         ▼
                 Analytics Query API  ──►  dashboards (any time range)
                 (rollups, top-N,          + scheduled reports (PDF/CSV)
                  filters, drill-down)      + analytics-driven alerting
```

- **Tier 1 (hot)** — keep `AttacksAggregator` exactly as-is for the live
  feed and sub-second cards. It stays the real-time path; nothing on the
  data plane changes.
- **Tier 2 (warm, the core of this work)** — a durable analytical store
  fed by a **new audit-bus subscriber → writer** (off the hot path, in a
  spawn_blocking / batched task, same pattern as the JSONL sink). Holds
  pre-aggregated time-series rollups (1-min / 1-h / 1-day buckets per
  detector / route / tier / action / client-geo / ASN) **plus** a
  sampled/full raw-event table for drill-down. Retention configurable
  (default 30 d rollups, 7 d raw).
- **Tier 3 (cold)** — long-term, compliance retention: partitioned
  Parquet to object storage + the already-shipped SIEM sinks. Closes the
  "cold-tier export (deferred)" stub.

### Store decision (open, with a recommendation)

| Option | For | Against |
|---|---|---|
| **ClickHouse** *(recommended)* | Purpose-built OLAP; the repo already has a `clickhouse-io` skill; columnar = cheap rollups + fast top-N over 100s of M rows; TTL-based retention native | One more stateful dependency to operate |
| Postgres + TimescaleDB | Already-familiar SQL; one fewer new system if Postgres is already in the stack | Heavier at high-cardinality security-event volume |
| DuckDB + Parquet on object store | Zero server, great for the cold/Athena-style ad-hoc tier | Not a live multi-writer warm store |

**Recommendation:** ClickHouse for Tier 2 (warm), Parquet/object-store for
Tier 3 (cold), keep Redis only for the hot ephemeral state. Single-node
ClickHouse first; cluster later (mirrors the L2-cache single-node stance).

## 4. Capabilities this unlocks (the product surface)

1. **Historical dashboards** — every existing card gains an arbitrary time
   range (24 h / 7 d / 30 d / custom), not a fixed 15 min. Trends:
   attack volume over time, detector efficacy drift, top attackers /
   countries / ASNs / targeted routes over weeks.
2. **Investigation / log search** — a filtered query API over the raw
   table (by IP, rule, route, action, time, geo) — the Cloudflare
   "firewall events" / AWS "Logs Insights" equivalent, wired into the
   Investigation page.
3. **Analytics Query API** — a typed REST (later GraphQL) endpoint
   exposing rollups + top-N + filters, so dashboards, reports, and
   external tooling read one contract.
4. **Scheduled & on-demand reports** — executive summary (PDF) + raw
   export (CSV/Parquet); **compliance reports** (PCI-DSS, SOC 2, HIPAA
   access summaries) leveraging the existing compliance-mode tags; emailed
   / chat-delivered digests via the existing alert receivers.
5. **Fleet-wide analytics** — the warm store is shared (or rolled up), so
   analytics span the cluster, not one node's RAM.
6. **Analytics-driven alerting** — anomaly / threshold alerts on the
   warm-store series (e.g. "SQLi attempts on /login up 10× vs 7-day
   baseline"), feeding the existing alert pipeline.

## 5. Phased plan

| Phase | Scope | Effort |
|---|---|---|
| **P0 — Schema + warm writer** | Define the event + rollup schema; add an audit-bus subscriber that batches into the warm store (ClickHouse), off the hot path. Retention/TTL config. Feature-flagged, default off. | **M** |
| **P1 — Analytics Query API** | Typed REST over rollups (time-bucketed series, top-N, filters). Back the *existing* dashboard cards with it when a time range > the hot window is selected (hot ring stays the default/live path). | **M** |
| **P2 — Historical dashboards** | Time-range picker on Overview / Top Attackers / Detector / Investigation; drill-down from a card to the filtered raw events. | **M** |
| **P3 — Reports** | Replace the stub `PageReports`: on-demand + scheduled PDF executive summary + CSV/Parquet export; compliance report templates; delivery via alert receivers. | **M–L** |
| **P4 — Cold tier** | Partitioned Parquet → S3/GCS for long retention; closes `audit-cold-tier-export`. | **S–M** |
| **P5 — Analytics alerting** | Baseline + anomaly alerts on warm-store series into the existing alert pipeline. | **M** |
| **P6 — Fleet rollup + GraphQL** | Cluster-wide aggregation; GraphQL analytics API for parity with Cloudflare. | **L** |

Start at **P0+P1** — that alone turns "15-minute amnesia" into real
history and is the unlock everything else builds on.

## 6. Non-goals / boundaries

- **Not** a replacement for customer SIEM — Tier 3 keeps forwarding via
  the 9 existing sinks; this adds *in-product* analytics, not a Splunk
  competitor.
- **Hot path stays untouched** — the data plane never blocks on analytics;
  all writes are async/batched off the audit bus (same contract as today's
  JSONL sink).
- **WAF-vs-gateway boundary respected** — this is observability of WAF
  decisions, not business-event analytics.

## 7. Risks

- **Cardinality / cost** — per-IP × per-route × per-minute rollups can
  explode. Mitigate with bounded dimensions (top-N + "other" bucketing,
  already a pattern in `AttacksAggregator`) and ClickHouse TTL.
- **PII & retention/compliance** — raw events carry client IP / headers.
  Honor the existing DLP/verbosity model; make retention + field
  redaction configurable per the compliance modes.
- **Hot-path safety** — the writer must fail open and never back-pressure
  the audit bus; drop-on-overflow with a metric, like the ring's cap.
- **Operational surface** — one more stateful service; gate behind a
  feature flag and keep single-node-first.

## 8. Wire-in points (already exist)

- **Audit bus** (`AuditBus`) — the warm writer is just another subscriber,
  next to the SIEM sinks. No new emit sites.
- **Aggregator semantics** — reuse the `is_attack` / detector-tag model
  from `attacks.rs` (incl. the 2026-06-19 detected-but-allowed change) so
  warm-store counts match the live cards.
- **Alert receivers** + **compliance modes** + **config plane** — report
  delivery, compliance templates, and feature-flagging all have homes.

---

**See also:** [`world-class-waf-roadmap.md`](./world-class-waf-roadmap.md)
(Operational backlog), the archived
[`audit-cold-tier-export.md`](../archive/audit-cold-tier-export.md) (the
~30-LoC JSONL v1 this supersedes for the cold tier), and
[`docs/observability/siem-log-forwarding.md`](../../docs/observability/siem-log-forwarding.md)
(the existing egress sinks).
