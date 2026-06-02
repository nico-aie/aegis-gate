# Observability improvements — OTel Collector export + richer alerts

> **Status:** Drafted 2026-06-02. Active observability track alongside
> [`ai-operator-copilot.md`](./ai-operator-copilot.md). Two independent
> deliverables; ship in either order.

Two gaps in how Aegis-Gate is *observed today*:

1. **OTel export is structural-only** — traces have a feature-gated OTLP
   exporter but the deps aren't wired and nothing actually leaves the
   process; metrics are Prometheus-scrape only; logs aren't exported.
2. **Alert messages are terse and hard to read** — the SLO breach
   message dumps raw numbers (`Budget consumed: 97727.3%`, nanosecond
   UTC timestamps) with no service identity, impact, or links.

---

## Part 1 — Real OTel Collector integration

### Where we stand (verified in code)

- `crates/aegis-bin/src/otel.rs` ships a **complete OTLP trace exporter**
  behind `--features otel`, but per the "list deps, don't add them" rule
  the four `opentelemetry*` crates are **not in `Cargo.toml`** — the
  feature compiles a warning-only stub. So: **0 spans actually leave the
  process today.**
- It exports **traces only**. Metrics are exposed as a **Prometheus
  scrape** endpoint (`metrics/exporter.rs`); logs go to **stdout JSON**.
- `cfg.observability.otel = { endpoint, headers, sample_ratio }` exists.

### Goal

Push **all three signals** (traces, metrics, logs) over **OTLP** to an
**OpenTelemetry Collector**, which fans them out to whatever backend the
operator runs. The Collector is the decoupling layer — the WAF config
never changes when the backend does.

```
                         OTLP gRPC :4317 / HTTP :4318
 aegis-gate ──────────────────────────────────▶  OTel Collector  ──┬──▶ traces backend
   • traces  (tracing-opentelemetry)                                 ├──▶ metrics backend
   • metrics (OTLP push, or Collector scrapes /metrics)              └──▶ logs backend
   • logs    (OTLP log exporter)
```

Low-friction option for metrics: keep the existing `/metrics` endpoint
and let the **Collector's `prometheus` receiver scrape it** — then only
traces + logs need new push exporters, and the metrics pipeline is
unchanged.

### Where to export — suggestions

The Collector can fan out to one or many. Pick by ops appetite:

| Tier | Option | Why | Signals |
|---|---|---|---|
| **OSS, all-in-one (recommended default)** | **SigNoz** | OTel-native, single ClickHouse-backed backend for traces+metrics+logs, one thing to run, has a UI. Lowest friction for this project. | T M L |
| **OSS, best-of-breed** | **Grafana LGTM** — Tempo (traces) + Mimir/Prometheus (metrics) + Loki (logs) + Grafana | De-facto standard; pairs with the Prometheus already here. More moving parts. | T M L |
| **OSS, traces-first** | **Jaeger** (+ keep Prometheus for metrics) | Simplest if you only want distributed traces now. | T |
| **Managed, zero-ops** | **Grafana Cloud** / **Honeycomb** (superb trace querying) / **Datadog** / **New Relic** / **Axiom** (cheap logs+traces) | No backend to run; send OTLP + an API key. | T M L |
| **Cloud-native** | **AWS** (ADOT Collector → X-Ray + AMP + CloudWatch) / **GCP Cloud Operations** | If already on that cloud. | T M L |

**Recommendation:** default to **SigNoz** for a single OTel-native pane
(easiest to stand up and demo); document **Grafana LGTM** as the
alternative for shops already on Prometheus/Grafana, and **Grafana Cloud
/ Honeycomb** as the managed zero-ops path. Ship a `deploy/otel/`
Collector config + a compose profile so it's runnable out of the box.

### Guardrails (WAF telemetry is sensitive)

- **Redaction before export** — spans/logs can carry request URIs,
  headers, and bodies (PII, tokens). Run them through the existing
  `dlp::redact` + header/cookie masking before the exporter, or configure
  the Collector's `attributes`/`redaction` processor. Hard requirement.
- **Cardinality** — never put IP / session / full-URI as metric labels;
  they belong on spans/exemplars, not metric dimensions.
- **Sampling** — keep `sample_ratio` low in prod (tail-sampling in the
  Collector for error/attack traces is the better lever).
- **Egress posture** — same as any external sink: opt-in, documented in
  network policy; air-gapped deploys keep the Collector on-box.

### Phases

| Phase | Scope | Est. |
|---|---|---|
| **P1** | Add the `opentelemetry*` deps (operator-approved), flip `otel.rs` from stub → live OTLP **trace** export; `deploy/otel/collector.yaml` + compose profile pointing at SigNoz. | S–M |
| **P2** | **Metrics** to the Collector — easiest via the Collector's `prometheus` receiver scraping `/metrics`; optional OTLP metric push. | S |
| **P3** | **Logs** via an OTLP log exporter (or ship stdout JSON → Collector `filelog` receiver). | M |
| **P4** | Redaction processor + tail-sampling + a documented backend matrix; `shutdown_tracer_provider` flush on SIGTERM (the `OTEL_PROVIDER` OnceLock is already parked for this). | M |

---

## Part 2 — Richer, "full" alert messages

### The problem (today's output)

```
[Page] SLO breach: DataPlaneAvailability
Burn rate: 977.27× over 1h window
Budget consumed: 97727.3%
Fired at: 2026-06-01T23:29:47.326425114+00:00
Runbook: https://runbooks.aegis.local/slo/DataPlaneAvailability/1h
(+1 suppressed since last alert)
```

Produced by `crates/aegis-control/src/slo/dispatch.rs::format_alert_text`.
What's wrong:

- **`Budget consumed: 97727.3%`** — nonsensical to a human; budget
  consumed should be clamped to 100% (with the raw multiplier expressed
  as the burn rate, not the budget).
- **Nanosecond UTC timestamp** — `…326425114+00:00` is unreadable; no
  local timezone, no "how long ago".
- **No identity** — which service / node / environment / region?
- **No impact** — what does 977× actually mean? What's broken for users?
- **No measured-vs-target** — the actual availability vs the SLO target.
- **Only a runbook link** — no dashboard, no trace/log deep-link.
- **No likely cause** — no correlation with recent events (config
  version, upstream pool, top error class).

### Target ("full") message

```
🔴 PAGE · SLO breach — Data-plane availability
aegis-gate · node aegis-prod-2 · env production · ap-southeast-1

Data-plane availability has collapsed. At the current error rate the 1h
error budget is fully exhausted and burning ~977× faster than sustainable.

  Availability   12.3%        (target 99.90%)
  Burn rate      977×         over 1h   (page threshold ≥ 14×)
  Error budget   100% spent   (1h window)
  Requests       8,412 errors / 9,600 in the last 1h

Started  2026-06-02 06:29:47 +07  (6 minutes ago)
Likely   upstream pool "api" 0/3 healthy since 06:24; config v412 active

→ Dashboard  https://waf.aegis.local/#/slo/DataPlaneAvailability
→ Runbook    https://runbooks.aegis.local/slo/DataPlaneAvailability/1h
→ Traces     https://signoz.aegis.local/traces?service=aegis-gate&...

(2 more breaches suppressed in the last 5 min)
```

### What to add / fix

1. **Severity glyph + plain label** (`🔴 PAGE` / `🟠 TICKET` / `🔵 INFO`).
2. **Service identity line** — service, node id, environment, region
   (from `cfg` / `node.id`).
3. **Plain-language impact sentence** — one line a non-expert understands.
4. **Sane numbers** — clamp budget-consumed to 100%; round burn rate to a
   readable integer with the page threshold beside it; add measured-vs-
   target availability and raw error/total counts.
5. **Humanized timestamps** — second precision, operator-local timezone,
   plus a relative "(N minutes ago)".
6. **Likely cause** — correlate with recent `AlertEvent`s (upstream pool
   degraded, hot-reload, active config version) when available.
7. **Links** — dashboard deep-link + runbook + trace/log deep-link.
8. **Per-channel rendering** — plain text for chat today; add a
   `format_*_markdown` / rich-card variant for VipTalk/Slack and a
   structured payload for PagerDuty/Alertmanager (they want fields, not
   prose). Keep `format_*_text` as the fallback.

This applies to **every** `AlertEvent` variant in `format_event_text`,
not just SLO — the same identity/timestamp/links treatment lifts the
DDoS, cert-expiry, upstream-degraded, leader-lost, audit-chain-break
messages too.

### Phases

| Phase | Scope | Est. |
|---|---|---|
| **P1** | Fix the embarrassing bits in `format_alert_text`: clamp budget %, humanize timestamps (local tz + relative), add service/node/env line, add measured-vs-target + raw counts. Pure function → unit-test the exact wire format. | S |
| **P2** | Extend the identity/timestamp/links treatment to all `AlertEvent` variants in `format_event_text`; add a dashboard deep-link builder. | S–M |
| **P3** | Per-channel renderers — markdown/rich-card for chat, structured JSON for PagerDuty/Alertmanager. | M |
| **P4** | "Likely cause" correlation — thread recent `AlertEvent`s / active config version into the message. | M |

> Note: the archived [`alerts-refactor.md`](../archive/alerts-refactor.md)
> covered alert **routing / dedup / severity** (shipped: `AlertEvent`
> router + `AlertDedupCache` + per-severity receivers). This track is
> specifically about message **content quality**, which that refactor
> left as terse formatters.

---

## Coupling

- **[`ai-operator-copilot.md`](./ai-operator-copilot.md)** — the same
  telemetry (and the richer alert events) are inputs to the LLM
  situational summary; the "likely cause" correlation here is a
  deterministic precursor to what the copilot does generatively.
- **`dlp`** — the OTel redaction gate reuses it (same dependency as the
  copilot's egress gate).

## Non-goals

- Not replacing Prometheus scrape (the Collector can scrape it).
- Not building a metrics backend — we export; operators host the backend.
- No alerting-logic changes (routing/dedup already shipped) — content only.
