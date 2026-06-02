# AI Operator Copilot

> **Status:** Partial (Phase 0 shipped) — `aegis-control/src/copilot/`
> (`LlmProvider` trait + `CostGuard` + `redact_for_egress` gate +
> Anthropic adapter behind the `llm` feature). Telemetry aggregator +
> `/api/copilot/*` endpoints + dashboard panel are pending (P1–P3).
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
  First adapter: **Anthropic Claude** (Messages API), behind the `llm`
  Cargo feature. Pluggable for a local/self-hosted model in air-gapped
  deploys.
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
| `GET /api/copilot/summary?since=15m` | P1 | On-demand situational brief (CSRF-gated, admin-only) |
| `POST /api/copilot/ask` | P2 | Free-form operator question over the current snapshot |
| `GET /api/copilot/suggestions` | P3 | Smart-catch rule-suggestion review queue |

All under the admin listener auth (see [`dashboard-auth.md`](./dashboard-auth.md)).

## Configuration (planned)

```yaml
copilot:
  enabled: false                 # off by default
  provider: anthropic            # | local
  model: "claude-haiku-4-5"      # cost/latency sweet spot for summaries
  api_key: "${secret:anthropic_api_key}"
  budget:
    max_tokens_per_window: 200000
    max_requests_per_window: 60
    window_seconds: 3600
```

The Anthropic key resolves through the standard secret resolver
([`secrets-management.md`](./secrets-management.md)); when unset the
provider reports `Disabled` and the copilot degrades to off.

## Phases

| Phase | Scope | Status |
|---|---|---|
| **P0** | Provider core: trait + `CostGuard` + redaction gate + Anthropic adapter | ✅ shipped 2026-06-02 |
| **P1** | `TelemetrySnapshot` aggregator + `GET /api/copilot/summary` (read → redact → prompt → structured brief) | next |
| **P2** | Dashboard Copilot panel (summary card + ask box) | planned |
| **P3** | Smart-catch triage: event clustering + rule-suggestion review queue | planned |
| **P4** | Scheduled briefs → alerts pipeline (`OperatorBriefing` event class) | planned |

## Related

- Build plan + risks: [`../../plans/future/ai-operator-copilot.md`](../../plans/future/ai-operator-copilot.md)
- Observability inputs: [`../observability/audit-logging.md`](../observability/audit-logging.md),
  [`../observability/prometheus-otel.md`](../observability/prometheus-otel.md)
- Egress redaction: [`../security/dlp.md`](../security/dlp.md)
