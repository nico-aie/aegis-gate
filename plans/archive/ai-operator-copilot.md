# AI Operator Copilot — LLM situational summary + smart-catch triage

> **Status:** ✅ **P0–P4 SHIPPED + live-verified 2026-06-02** (behind
> `--features llm`). Implementation lives in `aegis-control/src/copilot/`
> + the `/api/copilot/*` endpoints + the dashboard Copilot panel; feature
> spec at `docs/control-plane/ai-operator-copilot.md`. Remaining
> per-event clustering also shipped (audit-ring events grouped by
> detector → connected IPs + paths, fed into the triage prompt).
> This doc is the build plan kept for the decision trail.
>
> **One-liner:** a generative-LLM layer that reads the WAF's own
> telemetry (audit chain, metrics, risk buckets, detector hits) and
> turns it into (a) plain-language situational summaries operators can
> read at a glance, and (b) reasoning-assisted triage of borderline /
> clustered events with human-in-the-loop rule suggestions.

## What this is — and what it is NOT

| | This feature | Not this feature |
|---|---|---|
| **Model kind** | Generative LLM (Claude API), reasoning over *aggregated* data | The existing ONNX **attack classifier** (`detectors/ai/`) — a fast per-request binary verdict |
| **Where it runs** | **Off** the request hot path — async, reads stored telemetry | The ONNX detector runs inline per request |
| **Latency budget** | Seconds; on-demand or scheduled | Sub-millisecond inline |
| **Authority** | **Advisory only** — never auto-blocks; operator promotes suggestions | Detectors can block inline |
| **Egress** | Calls an external LLM API (operator opt-in, PII-redacted) | Local, no egress |

It is **also not** Tier 2 of the roadmap ("LLM firewall" — *protecting*
customer LLM endpoints from prompt injection). That defends a tenant's
AI app; **this** is an operator-facing copilot for the WAF itself. They
share the `llm` provider plumbing but nothing else.

## Why now

- The cluster config-plane + multi-node metrics aggregation just landed,
  so there's a **cluster-wide, queryable telemetry surface** worth
  summarizing (audit chain, `RouteActivityWindow`, risk buckets,
  detector-hit counters, DDoS / rate-limit events).
- Operators today read raw audit rows + Prometheus panels and
  reconstruct the story by hand. "What is happening right now, in one
  paragraph?" is the single most common SOC ask and nothing answers it.
- The `dlp::redact` module already exists — we can scrub PII **before**
  any egress, which is the gating safety requirement for sending WAF
  data to an external model.

## Two capabilities

### 1. Situational summary ("AI summary")

On demand (and optionally on a schedule), digest the last *N* minutes of
telemetry into a briefing:

> *"Elevated SQLi probing in the last 15 min: 412 blocks, 90% from
> 3 ASNs (AS-1234 leading). Top target `/api/v2/search`. One IP
> (203.0.113.10) escalated to strike-block. Rate-limit gate fired 1.8k
> times — within normal range. No upstream health degradation."*

- Inputs (all **read-only**, no hot-path coupling): audit events since
  `t`, risk `top()` buckets, detector-hit deltas, DDoS / rate-limit
  counters, upstream health, traffic RPS.
- Output: a short structured brief (headline + bullet findings +
  suggested next action), rendered in the dashboard and optionally
  pushed into the **alerts** pipeline (`plans/future/alerts-refactor.md`)
  as an `OperatorBriefing` event class.

### 2. Smart-catch triage assist

The deterministic engine flags some traffic with **low confidence** or
in **clusters** that no single rule explains. The copilot reasons over a
bundle of related events and:

- **Explains** — "these 30 requests share a crafted `Referer` + a
  rotating JA4; looks like a single actor behind a proxy pool."
- **Suggests** — proposes a candidate rule (in the existing rule DSL)
  the operator can preview in `POST /api/rules/simulate` and promote.
  **Never auto-applied.**
- **Clusters** — groups the noisy long-tail into a handful of
  named "campaigns" for the Investigation page.

This is decision *support*, not a detector. The fast path stays
deterministic; the LLM adds a slow reasoning layer an operator drives.

## Architecture

```
            read-only
 audit chain  ─┐
 metrics       ├─▶  TelemetrySnapshot  ─▶  dlp::redact  ─▶  LlmProvider  ─▶  Brief / Suggestion
 risk top()    │      (aggregator)         (PII scrub)      (trait)          (advisory)
 detector hits ┘                                              │
                                                     Anthropic adapter (default)
                                                     [OpenAI / local pluggable]
```

- **New crate or module**, feature-gated `llm` (off by default):
  `aegis-control/src/copilot/` is the likely home (it already owns the
  dashboard + audit read surface). A standalone `aegis-llm` crate is the
  alternative if Tier 2 wants to share it.
- **`LlmProvider` trait** — `async fn complete(&self, prompt) -> Result<Completion>`.
  First adapter: **Anthropic Claude** (matches the build environment;
  see the `claude-api` skill — include prompt caching). Pluggable so a
  local/self-hosted model can be dropped in for air-gapped deploys.
- **Secrets** — API key via the existing secrets resolver
  (`env`/`file`/`vault`/`aws`/`gcp`/`azure`), validated at boot when the
  feature is on.
- **`TelemetrySnapshot` aggregator** — read-only adapters over the audit
  store, metrics, and `RiskTracker`. No new data-plane code; zero
  regression risk to live traffic.

## Hard guardrails (a WAF sending data to an external model)

1. **Off by default.** Enabling is an explicit opt-in that documents the
   external egress (network policy + CSP `connect-src`).
2. **PII redaction before egress** — every snapshot passes through
   `dlp::redact` (cards/SSN/emails/tokens) **and** header/cookie
   masking before it reaches a prompt. Unit-tested as a hard gate.
3. **Advisory only** — no copilot output can block traffic or mutate
   config without an operator action. Rule suggestions land in a
   review queue, not the live ruleset.
4. **Cost + rate budget** — per-window token cap, request rate limit,
   and a kill-switch; every call audited (prompt hash, tokens, cost,
   model, latency).
5. **Audit + reproducibility** — the redacted prompt hash + the model
   response are written to the audit chain so a summary is explainable
   after the fact.

## Surfaces

- `GET /api/copilot/summary?since=15m` — on-demand brief (CSRF-gated,
  admin-only).
- `POST /api/copilot/ask` — free-form operator question over the
  current snapshot.
- Dashboard **Copilot** panel — summary card + "ask" box + suggestion
  review queue.
- Optional scheduled brief → `alerts` pipeline as `OperatorBriefing`.

## Phases

| Phase | Scope | Est. |
|---|---|---|
| **P0** | ✅ **DONE 2026-06-02.** `crates/aegis-control/src/copilot/`: `LlmProvider` trait + types; `CostGuard` (per-window token + request budget, true-up on actual usage); `redact_for_egress` mandatory gate (reuses `aegis_security::dlp::redact`); `MockProvider`. Adapters behind the `llm` feature: **OpenAI-compatible** (`copilot::openai`, default — `/v1/chat/completions`, vLLM/Ollama/LiteLLM/OpenAI, config from `LLM_*` env) **+ Anthropic** (`copilot::anthropic`, `ANTHROPIC_API_KEY`). Builds clean with + without `llm`. | M |
| **P1** | ✅ **DONE + live-verified end-to-end 2026-06-02.** `summary.rs` orchestration (render → redact → budget-admit → provider → record-usage → `Brief`); snapshot adapter (`admin_get::build_copilot_snapshot` — `risk.top` + `attacks_agg.by_detector` + `tracking.active_slo_alert_labels`); `CopilotService` global (env-built provider + `CostGuard`); `GET /api/copilot/summary?minutes=N` async admin endpoint (`llm` feature; 503 disabled / 502 provider-error). 14 unit tests. **Live e2e:** logged in, drove attack traffic, the endpoint returned an accurate brief from the vLLM endpoint (Qwen3.6-35B). Fixed a UX bug found in the smoke (omit `total_requests` when unknown so the model doesn't read 0 as an outage). | M |
| **P2** | ✅ **DONE + live-verified 2026-06-02.** Dashboard `PageCopilot` (Security Ops → Copilot): on-demand "Generate brief" + window selector (brief prose beside snapshot numbers) **and** an "Ask the copilot" box (free-form Q&A). Backend `GET /api/copilot/summary` + `GET /api/copilot/ask?q=…` (shared `run()` pipeline; question redacted too; 400 on empty q). LLM text rendered as plain text (no HTML injection). 15 unit tests; bundle under budget; both endpoints live-verified against the vLLM endpoint. | M |
| **P3** | ✅ **DONE + live-verified 2026-06-02.** `triage.rs`: `triage()` asks the LLM to cluster the snapshot into campaigns + ONE candidate rule each (strict JSON; lenient parse tolerant of prose/fences; raw-text fallback when unparseable). `GET /api/copilot/suggestions` + dashboard "Smart-catch triage" card (clusters + confidence + suggested rule in `<code>`, advisory/human-in-the-loop). 4 triage unit tests. Live: `[]` on a thin snapshot; 5 grounded suggestions on a richer one. **Per-event clustering shipped** (`copilot/cluster.rs` + `AuditRing::recent`): recent audit events grouped by detector → connected IPs + paths, included in the snapshot fed to triage (live-verified: 2 real clusters). Promote stays manual (operator previews via Rules → simulate). | L |
| **P4** | ✅ **DONE + live-verified 2026-06-02.** `AlertEvent::OperatorBriefing` (Info) + format arm; a scheduler task in `accept.rs` (next to the SLO eval loop) builds a snapshot every `LLM_BRIEFING_INTERVAL_SECS` (floor 60s, off by default), asks the copilot for a brief, and `dispatch_event`s it into the alerts pipeline (no dedup — distinct content). Live: "scheduler started" at boot → "briefing dispatched" one tick later. | S |

## Risks / open questions

- **Hallucination** — the brief must cite the underlying counts (every
  claim links back to an audit query); the UI shows the numbers beside
  the prose so an operator can verify. Suggestions are always preview-
  then-promote.
- **Egress in regulated deploys** — air-gapped / FIPS / data-residency
  tenants can't call an external API. The provider trait + a local-model
  adapter is the answer; the feature stays off where egress is barred.
- **Cost drift** — caching + budget cap + scheduled-vs-on-demand toggle;
  summaries are cached per snapshot window.
- **Snapshot fidelity** — start with audit + metrics + risk; expand
  inputs only as the brief proves useful.

## Coupling with other tracks

- **B1 / API-security** (deferred): when those guards land, their block
  events become another `TelemetrySnapshot` input — design the copilot's
  event taxonomy to absorb new event classes without schema churn.
- **`alerts-refactor.md`**: P4 reuses the `AlertEvent` router + dedup.
- **`dlp`**: the egress redaction gate is a hard dependency.
- **`claude-api` skill**: the Anthropic adapter should follow it
  (Messages API + prompt caching).

## Non-goals (v1)

- No auto-blocking or auto-rule-application from LLM output.
- No fine-tuning / training — inference against a hosted model only.
- Not a replacement for the ONNX inline detector or the rule engine.
- Not the Tier 2 customer-LLM-endpoint firewall (separate track).
