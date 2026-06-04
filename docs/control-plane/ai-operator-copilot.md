# AI Operator Copilot

> **Status:** ✅ **Implemented (P0–P4)** — `aegis-control/src/copilot/`,
> behind the `llm` feature. The full track shipped + was live-verified
> end-to-end **2026-06-02** against an OpenAI-compatible vLLM endpoint
> (Qwen3.6-35B): provider core + `redact_for_egress` gate + `CostGuard`
> (P0); `summarize()` + snapshot adapter + `GET /api/copilot/summary`
> (P1); dashboard Copilot panel + `GET /api/copilot/ask` (P2);
> smart-catch triage + `GET /api/copilot/suggestions` (P3); scheduled
> briefings → alerts pipeline (P4); plus per-event clustering of
> audit-ring events (detector → connected IPs + paths) fed into triage.
>
> **Config centralized into YAML (2026-06-03):** configured under
> `observability.copilot` (`CopilotConfig` in `aegis-core`) with the API
> key as a `${secret:...}` reference resolved per-node, and
> **hot-reloadable via the config plane** (the `apply_cfg_change_to_copilot`
> fold swaps the live service on apply — no restart). Legacy `LLM_*` env
> stays as a back-compat fallback.
>
> See [`../../plans/implementation-matrix.md`](../../plans/implementation-matrix.md)
> for the full status matrix and
> [`../../plans/archive/ai-operator-copilot.md`](../../plans/archive/ai-operator-copilot.md)
> for the (archived) build plan.

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

## API surface

| Endpoint | Phase | Purpose |
|---|---|---|
| `GET /api/copilot/summary?minutes=15` | ✅ P1 | On-demand situational brief (admin-only; 503 when disabled) |
| `GET /api/copilot/ask?q=…` | ✅ P2 | Free-form operator question over the current snapshot (400 on empty `q`) |
| `GET /api/copilot/suggestions` | ✅ P3 | Smart-catch triage — campaign clusters + candidate rules (advisory review queue) |

All under the admin listener auth (see [`dashboard-auth.md`](./dashboard-auth.md)).

## Configuration

The copilot is configured in YAML under `observability.copilot`, like
every other subsystem — and it is **hot-reloadable via the config plane**
(`PUT /api/config` / cluster activation; no restart). The API key is
**never inline**: `api_key_ref` is a `${secret:...}` reference each node
resolves at boot/apply (env / file / vault / aws / gcp / azure), so the
secret never sits in the config file or transits the cluster doc.

```yaml
observability:
  copilot:
    enabled: true
    provider: openai_compatible          # or: anthropic
    base_url: "https://host/v1"          # /chat/completions is appended
    model: "Qwen3.6-35B-A3B"             # any model the endpoint serves
    timeout_ms: 20000
    briefing_interval_secs: 0            # >0 (≥60) enables scheduled briefings → alerts
    api_key_ref: "${secret:env:LLM_API_KEY}"   # resolved per-node; never inline
```

The referenced secret is supplied out-of-band — e.g. `LLM_API_KEY` in the
gitignored `.env` (sourced by `make run-copilot`) for the `env:` backend,
or a vault path for `${secret:vault:...}`. Rotating the key is then a
secret-store update + a config re-apply (the fold re-resolves the ref on
every node); the WAF never needs the raw key in config.

When `enabled` is false, or the key / model (and `base_url` for the
OpenAI-compatible provider) don't resolve, the provider reports
`Disabled` and the copilot degrades to off (never errors the WAF). The
per-window cost/rate budget is set on the `CostGuard` at construction
(token cap, request cap, window).

**Back-compat:** if `observability.copilot.enabled` is not set, the
copilot falls back to the legacy `LLM_*` env vars (`LLM_ENABLED`,
`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`, `LLM_TIMEOUT_MS`,
`LLM_BRIEFING_INTERVAL_SECS`) — and the Anthropic adapter to
`ANTHROPIC_API_KEY` — so pure-env deployments keep working. New
deployments should prefer the YAML model above.

## Phases

| Phase | Scope | Status |
|---|---|---|
| **P0** | Provider core: trait + `CostGuard` + redaction gate + OpenAI-compatible & Anthropic adapters | ✅ shipped 2026-06-02 |
| **P1** | `summarize()` core + snapshot adapter (RiskTracker/SloEngine/detectors) + `GET /api/copilot/summary` endpoint; live-verified end-to-end | ✅ shipped 2026-06-02 |
| **P2** | Dashboard Copilot panel — summary card + ask box (Security Ops → Copilot); `GET /api/copilot/summary` + `GET /api/copilot/ask`. Live-verified. | ✅ shipped 2026-06-02 |
| **P3** | Smart-catch triage: campaign clustering + rule-suggestion queue (`GET /api/copilot/suggestions` + panel card); live-verified | ✅ shipped 2026-06-02 |
| **P4** | Scheduled briefings → alerts pipeline (`AlertEvent::OperatorBriefing`, Info; `LLM_BRIEFING_INTERVAL_SECS`, floor 60s, off by default); live-verified | ✅ shipped 2026-06-02 |

## Related

- Build plan + risks: [`../../plans/archive/ai-operator-copilot.md`](../../plans/archive/ai-operator-copilot.md)
- Observability inputs: [`../observability/audit-logging.md`](../observability/audit-logging.md),
  [`../observability/prometheus-otel.md`](../observability/prometheus-otel.md)
- Egress redaction: [`../security/dlp.md`](../security/dlp.md)
