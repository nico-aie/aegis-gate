# AI Operator Copilot

> **Status:** Partial — `aegis-control/src/copilot/`. **Phase 0 + P1
> shipped** (`LlmProvider` trait + `CostGuard` + `redact_for_egress`
> gate + `summarize()` orchestrator + OpenAI-compatible & Anthropic
> adapters + snapshot adapter + `GET /api/copilot/summary` endpoint,
> behind the `llm` feature). **Live-verified end-to-end 2026-06-02**
> against an OpenAI-compatible vLLM endpoint (Qwen3.6-35B): the endpoint
> returned an accurate situational brief over live telemetry. Pending:
> the dashboard panel (P2) + smart-catch triage (P3) — all shipped +
> all live-verified 2026-06-02 — including P4 (scheduled briefings →
> alerts pipeline). The copilot track (P0–P4) is complete; per-event
> clustering (vs the aggregate snapshot) is the documented follow-up.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status)
> for the full matrix and
> [`../../plans/future/ai-operator-copilot.md`](../../plans/future/ai-operator-copilot.md)
> for the build plan.

A generative-LLM layer that reads the WAF's **own telemetry** (audit
chain, metrics, risk buckets, detector hits) and turns it into:

1. **Situational summaries** — a plain-language "what's happening right
   now" briefing an operator reads at a glance.
2. **Smart-catch triage** — reasoning over borderline / clustered events,
   with **human-in-the-loop** rule suggestions.

## What it is — and is NOT

| | This feature | Not this |
|---|---|---|
| Model | Generative LLM (Claude), reasoning over *aggregated* data | The inline ONNX **attack detector** ([`../security/detectors/ai-detector.md`](../security/detectors/ai-detector.md)) |
| Runs | **Off** the request hot path — async, reads stored telemetry | The detector runs inline per request |
| Authority | **Advisory only** — never blocks traffic or mutates config | Detectors can block inline |
| Egress | Calls an external LLM API (opt-in, PII-redacted) | Local, no egress |

It is **also not** a firewall for a tenant's *own* LLM endpoints
(prompt-injection defence) — that's a separate roadmap tier. This is an
operator-facing copilot for the WAF itself.

## Architecture

```
            read-only
 audit chain  ─┐
 metrics       ├─▶ TelemetrySnapshot ─▶ redact_for_egress ─▶ LlmProvider ─▶ Brief
 risk top()    │     (aggregator)        (dlp egress gate)     (trait)        (advisory)
 detector hits ┘                                                 │
                                                       Anthropic adapter (feature `llm`)
```

- **`copilot` module** (`aegis-control/src/copilot/`) — provider-agnostic
  core. Lives in the control plane because it owns the admin-API surface
  and the audit/metrics read access.
- **`LlmProvider` trait** — `async fn complete(LlmRequest) -> LlmResponse`.
  Default adapter: **OpenAI-compatible** (`/v1/chat/completions` — works
  with vLLM, Ollama, LiteLLM, OpenAI). An **Anthropic** Messages-API
  adapter is also available. Both behind the `llm` Cargo feature;
  pluggable for a local/self-hosted model in air-gapped deploys.
- **`summarize()`** — the orchestrator: render prompt → `redact_for_egress`
  → `CostGuard.try_admit` → `provider.complete` → record actual usage →
  `Brief` (prose + the snapshot echoed for operator verification).
- **`CostGuard`** — per-window token + request budget; reserve-on-estimate,
  true-up on the provider's actual usage.
- **`redact_for_egress`** — the **mandatory** PII/secret scrub
  (`aegis_security::dlp::redact`) every prompt passes through before it
  leaves the process.

## Hard guardrails

1. **Off by default.** Enabling is an explicit opt-in that documents the
   external egress (network policy + CSP `connect-src`).
2. **PII redaction before egress** — telemetry → `redact_for_egress`
   (cards / SSN / IBAN / emails / cloud + VCS + Stripe / Slack tokens)
   before any prompt is sent. Unit-tested as a hard gate.
3. **Advisory only** — no copilot output blocks traffic or mutates config
   without an operator action; rule suggestions land in a review queue.
4. **Cost + rate budget** — `CostGuard` caps per-window tokens + request
   rate; every call is auditable (prompt hash, tokens, model, latency).
5. **Reproducible** — the redacted prompt hash + response are written to
   the audit chain so a summary is explainable after the fact.

## API surface (planned)

| Endpoint | Phase | Purpose |
|---|---|---|
| `GET /api/copilot/summary?minutes=15` | ✅ P1 | On-demand situational brief (admin-only; 503 when disabled) |
| `GET /api/copilot/ask?q=…` | ✅ P2 | Free-form operator question over the current snapshot (400 on empty `q`) |
| `GET /api/copilot/suggestions` | ✅ P3 | Smart-catch triage — campaign clusters + candidate rules (advisory review queue) |

All under the admin listener auth (see [`dashboard-auth.md`](./dashboard-auth.md)).

## Configuration

The OpenAI-compatible adapter reads `LLM_*` environment variables
(operators wire these from their secret manager — the key is read at
runtime, never persisted):

```bash
LLM_ENABLED=true
LLM_BASE_URL=https://host/v1        # /chat/completions is appended
LLM_API_KEY=sk-...                  # sent as: Authorization: Bearer
LLM_MODEL=Qwen3.6-35B-A3B           # any model the endpoint serves
LLM_TIMEOUT_MS=4000
LLM_BRIEFING_INTERVAL_SECS=0   # >0 (≥60) enables scheduled briefings → alerts
```

When `LLM_ENABLED` isn't `true`, or the base URL / key / model are
missing, the provider reports `Disabled` and the copilot degrades to
off (never errors the WAF). The per-window cost/rate budget is set on
the `CostGuard` at construction (token cap, request cap, window). The
Anthropic adapter alternatively reads `ANTHROPIC_API_KEY`.

## Phases

| Phase | Scope | Status |
|---|---|---|
| **P0** | Provider core: trait + `CostGuard` + redaction gate + OpenAI-compatible & Anthropic adapters | ✅ shipped 2026-06-02 |
| **P1** | `summarize()` core + snapshot adapter (RiskTracker/SloEngine/detectors) + `GET /api/copilot/summary` endpoint; live-verified end-to-end | ✅ shipped 2026-06-02 |
| **P2** | Dashboard Copilot panel — summary card + ask box (Security Ops → Copilot); `GET /api/copilot/summary` + `GET /api/copilot/ask`. Live-verified. | ✅ shipped 2026-06-02 |
| **P3** | Smart-catch triage: campaign clustering + rule-suggestion queue (`GET /api/copilot/suggestions` + panel card); live-verified | ✅ shipped 2026-06-02 |
| **P4** | Scheduled briefings → alerts pipeline (`AlertEvent::OperatorBriefing`, Info; `LLM_BRIEFING_INTERVAL_SECS`, floor 60s, off by default); live-verified | ✅ shipped 2026-06-02 |

## Related

- Build plan + risks: [`../../plans/future/ai-operator-copilot.md`](../../plans/future/ai-operator-copilot.md)
- Observability inputs: [`../observability/audit-logging.md`](../observability/audit-logging.md),
  [`../observability/prometheus-otel.md`](../observability/prometheus-otel.md)
- Egress redaction: [`../security/dlp.md`](../security/dlp.md)
