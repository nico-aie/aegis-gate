# AI/LLM firewall (Roadmap Tier 2) — implementation plan

**Status:** **Deferred — research-gated** (decided 2026-06-23). Architecture +
scope are settled below, but the feature is intentionally **pushed to a later
wave**: it needs dedicated research before build (signature-corpus sourcing,
the streaming-inspection decision, and whether/when to escalate to embeddings —
see §8). The foundation Wave 2 items (`passive-upstream-health` +
`zone-aware-load-balancing`, then `ddos-cross-node-rps-aggregation`) are
sequenced **ahead** of this. When research resolves §8, the 2A slice below is
ready to promote to an active build plan — it does **not** need a second plan
file until then.

Scoped after a code-grounded surface map. **First deliverable (when picked up):
2A only** (request-side prompt-injection / jailbreak). 2B (response inspection)
and 2C (token/cost limits) are **further deferred** behind a
streaming-architecture decision captured in §6.

> **Read this first — what this is NOT.** This is *not* the existing `ai`
> detector. That feature (`crates/aegis-security/src/detectors/ai/`,
> `--features ai`) is an **ONNX request classifier** answering "is this HTTP
> request a generic web attack (SQLi/XSS/…)?" from 29 tabular features. The
> LLM firewall is **endpoint protection for LLM-backed apps** — a
> content/semantic problem over prompt + response bodies, scoped to routes an
> operator marks as LLM endpoints. The roadmap's own capability table says the
> existing `ai` infra contributes "**Nothing**" to it
> ([[world-class-waf-roadmap]] Tier-2 row). They share a name and nothing else.

---

## 1. Why carefully — the trap

The roadmap one-liner says 2B response inspection "rides the existing
`on_body_frame` response-filter hook." **It cannot, for the case that
matters.** LLM responses stream token-by-token as **SSE**, and the data plane
returns early for `ResponseMode::Streaming` (`data_plane.rs:2892`) **before**
`on_body_frame` runs — streamed responses are header-inspected only
(`response_inspection_skipped`). So response-side features (2B) and
response-token counting (2C) hit a wall that request-side detection (2A) does
not. Splitting 2A out keeps the first slice clean and unblocked; bundling
2B/2C in now drags the hard streaming-wiring decision into the critical path.

---

## 2. Reuse map (code-grounded)

| Surface | Anchor | Verdict for the firewall |
|---|---|---|
| `ai` ONNX detector | `detectors/ai/mod.rs`, `AiConfig` `config.rs:667` | **Distinguish, don't reuse.** Loader / `ArcSwap` hot-swap / batch executor / metrics-sink scaffold are reusable *if* we later ship an embedding model; the tabular feature pipeline + model are not. |
| `dlp/` module | `dlp/mod.rs:112` `scan`, `:169` `redact` | **Reusable as-is** for 2B egress (operates on any `&str`). |
| `on_body_frame` hook | core `pipeline.rs:80`; impl `pipeline.rs:214`; call `data_plane.rs:2955`; **SSE skip `data_plane.rs:2892`** | **Reusable for buffered responses only**; streaming/SSE needs net-new per-frame wiring (§6). |
| Rate limiter | `rate_limit/ip_limiter.rs`; rich schema `config.rs:3802` (`RlKey::Header`, token bucket) is **schema-only/unwired** | **Extend** (key on API-key header); token/cost counting is **net-new** (§6). |
| Per-route opt-in flag | `RouteConfig config.rs:1977`; **`ws_inspect: Option<WsInspectConfig>` `:2063` is the exact model** | **Reusable pattern.** Add `llm: Option<LlmFirewallConfig>`; `RouteConfig` is not `deny_unknown_fields`, so it's backward-compatible. |

No prompt-injection / jailbreak / toxicity / LLM-protection code exists today.

---

## 3. Scope of this plan — 2A only

**2A · Prompt-injection / jailbreak detection (request-side).** On a request
to an LLM-flagged route, extract the prompt content from the JSON body and
score it against a heuristic + signature engine; block (or log-only) on a
match. Deterministic, fast, explainable, no model artifact. This is the same
shape as the just-shipped GraphQL guard (`graphql_guard.rs`) — that is the
template to mirror end-to-end.

**Decisions locked (2026-06-23):**
- Method: **heuristic + signature first**; embeddings deferred (would need a
  new model artifact + an embedding path that doesn't exist today).
- Gating: **per-route `llm` flag** — the firewall runs only where an operator
  opts in, never globally.
- Streaming (2B/2C): **decide later**; tradeoff captured in §6.

---

## 4. 2A design

### 4.1 Route flag + config (`aegis-core`)
- New `RouteConfig.llm: Option<LlmFirewallConfig>` (mirror `ws_inspect`).
  `None` = firewall off for that route (default; backward-compatible).
- `LlmFirewallConfig` (own struct, `deny_unknown_fields`, serde defaults +
  hand-written `Default`, the `GraphqlGuardConfig` convention):
  - `enabled: bool` (within a route that sets the block, lets it be toggled).
  - `body_format: LlmBodyFormat` — how to find the prompt. Start with
    `openai_chat` (`messages[].content`) and `raw_prompt` (`prompt` /
    `input`); an `auto` that tries known shapes and falls back to scanning
    the whole body. **Fail-open:** an unparseable body is *skipped*, not
    blocked (same contract as the GraphQL guard).
  - `action: enforce | log_only` (route `mode` already exists; this is the
    feature-local default, foldable into the global `set_profile` mode map).
  - Optional `max_prompt_bytes` cap to bound scan cost (defer to global body
    cap if unset).
- Validation: if any route sets `llm.enabled: true`, the signature set must be
  non-empty (loud-fail a misconfig), mirroring the graphql empty-paths guard.

### 4.2 Detection engine (`aegis-security`, new `llm_firewall` module)
- A signature/heuristic scorer over the extracted prompt string. Categories
  to seed (curated, versioned — keep the list in one place so it can grow):
  - **Instruction override:** "ignore (all )?previous instructions",
    "disregard the above", "forget your rules", system-prompt-override phrasing.
  - **Role / persona jailbreak:** "you are now DAN", "developer mode",
    "act as … with no restrictions".
  - **Delimiter / injection framing:** fake `system:` / `</system>` /
    role-tag injection, prompt-leak asks ("repeat the text above",
    "print your system prompt").
  - **Obfuscation signals:** base64/hex-encoded instruction blobs, excessive
    zero-width / homoglyph density (heuristic, score-only).
- Output mirrors the detector contract: a result enum (`Allowed` /
  `Flagged { category, reason, score }`) plus a tag (`prompt_injection`) so it
  slots into the existing audit / `X-WAF-*` machinery. Unit-tested in isolation
  (the `graphql.rs` test style: known-bad → flagged, benign → allowed,
  unparseable → skipped).
- **Reuse note:** keep the engine a pure function over `&str`; the data-plane
  wrapper (in `aegis-proxy`, like `graphql_guard.rs`) owns body extraction,
  the route-flag gate, and the block/log-only decision. Core owns the YAML
  config struct; conversion at the proxy boundary.

### 4.3 Data-path insertion (`aegis-proxy`)
- Wrapper module `llm_firewall.rs` (sibling of `graphql_guard.rs`):
  `from_config` + `check(route_llm_cfg, body) -> Outcome`.
- Insert in `handle_data_request_inner` after body buffering, gated by
  `!bypass_detectors` AND the resolved route carrying an `llm` config —
  exactly where/how the GraphQL guard sits. On `Flagged` → `blocked_response`
  (hard 403, audited) unless log-only / Dry-Run, then stash `log_only_intent`
  and forward. Tag `prompt_injection`.
- Hold the per-route compiled config on the resolved route (it already flows
  through `RouteCtx`); no new `ProxyContext` global needed unless we want a
  hot-swappable global signature set (likely yes — see 4.4).

### 4.4 Hot-reload + interop
- If the signature set is global+hot-swappable, store it behind `ArcSwap` on
  `ProxyContext` and add `apply_cfg_change_to_llm_firewall` to `reload.rs` +
  the `apply_and_swap` call (the structural-guard test forces this — same as
  the graphql wiring). Per-route enable/disable rides the normal route reload.
- Map `prompt_injection` → a `rules_engine` policy in
  `interop/rule_map.rs` + advertise it in `capabilities` (so Dry-Run /
  `set_profile` govern it), mirroring the `graphql` mapping just added.

### 4.5 Docs + tests
- `config/REFERENCE.md` + a `routes[].llm:` example in a shipped config.
- Tests: engine unit suite; config round-trip/validation; data-plane e2e
  (flagged prompt on an LLM route → 403; benign → forward; non-LLM route →
  untouched; log-only → forward) — the `graphql_guard_blocks_*` e2e is the
  template.

### 4.6 Effort
**M (smaller end).** The data-path/ config / hot-reload / interop wiring is a
near-clone of the GraphQL guard (proven, ~1 day of that shape). The real work
is the **signature corpus** — curating and maintaining a credible
injection/jailbreak pattern set, and its false-positive discipline. Budget the
bulk of the time there, not the plumbing.

---

## 5. Risks (2A)

- **False positives** — benign prompts legitimately contain "ignore the
  above" etc. Mitigations: score-and-threshold (not single-keyword block),
  ship **log-only by default** so operators bake the signal before enforcing,
  per-route tuning, and a clear `reason` on every flag.
- **Fail-open discipline** — a body the extractor can't parse must *skip*, never
  block (proven contract from the GraphQL guard).
- **Signature rot / evasion** — jailbreak phrasing evolves; the corpus is a
  living asset. Version it and keep it in one module so updates are cheap. This
  is the honest ceiling of a heuristic approach and the reason embeddings are
  the documented escalation path — not a v1 requirement.
- **Scope creep into the `ai` detector** — keep the two modules and configs
  strictly separate; do not fold prompt-injection signals into the ONNX
  classifier's risk contribution.

---

## 6. Deferred: 2B / 2C and the streaming decision (capture, don't resolve)

2B (response inspection: system-prompt leak, PII/secret egress via `dlp/`,
toxicity) and 2C (token/cost-aware limits per key/route) **both depend on
inspecting LLM responses**, which today are SSE and bypass body inspection
(`data_plane.rs:2892`). Three directions, to be decided when we plan 2B/2C:

- **(i) Buffer LLM routes** — force LLM-flagged routes to buffer the full
  response before inspecting. Simplest reuse of `on_body_frame`; **adds
  latency / removes token-streaming UX** on those routes.
- **(ii) Per-frame SSE inspection** — new wiring in the streaming path
  (`upstream/streaming.rs`, `data_plane.rs:2898`) to inspect each SSE frame.
  Preserves streaming; **must handle cross-frame patterns** (a secret or
  leaked system-prompt split across two frames → needs a sliding buffer).
- **(iii) Hybrid** — stream to the client but mirror frames to an async
  inspector that can *alert / cut the stream* on a hit (no added first-token
  latency, can't pre-redact).

Supporting facts for that future plan: `dlp::scan`/`redact` are reusable as-is
(`dlp/mod.rs`); the rich `RateLimitRule` schema (`config.rs:3802`,
`RlKey::Header`, token bucket) is **defined but unwired** — 2C must wire the
multi-bucket evaluator *and* build net-new token counting (no token metering
exists; the Copilot budget guard `aegis-control/src/copilot/mod.rs:70` is the
closest reference). Token counting on streamed responses inherits the same
SSE decision.

---

## 7. Sequencing

1. **2A** (this plan) — request-side prompt-injection, per-route flag,
   heuristic/signature, log-only default. Net-new but plumbing-light.
2. **Streaming decision** — a short design note resolving §6 (i/ii/iii). Gates
   everything response-side.
3. **2B** — response inspection on the chosen streaming substrate (DLP egress
   first, it's the highest-value + lowest-novelty; toxicity later).
4. **2C** — token/cost limits (needs the §6 substrate + token metering + the
   rate-rule evaluator).

In [[implementation-sequence]] this sits in a **later wave (research-gated)**;
the foundation Wave 2 items run first. Promote 2A to an active build plan once
§8 is resolved.

---

## 8. Open research questions (resolve before build)

This is the homework that gates promotion. Until these are answered, the plan
above is architecturally sound but not buildable with confidence.

1. **Signature corpus — sourcing & licensing.** Where does the
   injection/jailbreak pattern set come from? Candidates: public datasets
   (e.g. jailbreak/prompt-injection corpora, OWASP LLM Top-10 examples,
   garak/rebuff-style rule sets), vendor write-ups, our own red-teaming.
   Check licensing before vendoring anything. Output: a seed corpus + a
   maintenance cadence. **This is the bulk of the real work.**
2. **False-positive calibration.** What benign-traffic baseline do we test
   against to set the score threshold? Need a corpus of *legitimate* LLM
   prompts (incl. ones that innocently contain "ignore the above", meta-
   discussion of prompts, code, etc.) to measure FP rate before enforce is
   credible. Defines the "log-only-by-default → bake → enforce" rollout.
3. **Embeddings: if/when.** Is heuristic+signature enough for v1, and what is
   the concrete trigger to escalate to embedding-based intent scoring? If yes:
   which model artifact, does it ride the existing `--features ai` loader, and
   what's the embedding/runtime cost per request on the hot path?
4. **Body-format coverage.** Which LLM request shapes must `body_format` cover
   at launch (OpenAI chat, Anthropic Messages, raw completion, custom
   gateways)? Survey the actual upstreams we expect to protect.
5. **The streaming decision (§6).** The big one for 2B/2C — buffer vs
   per-frame vs hybrid. Needs its own short design note; gates everything
   response-side. Independent of 2A, so 2A can ship first regardless.
6. **Market/positioning check.** Brief competitive scan (Cloudflare Firewall
   for AI, Lakera, Prompt Security, Impart) to confirm the 2A feature bar and
   avoid shipping below table stakes.

When 1–4 + 6 are answered, 2A is ready to build; 5 unblocks 2B/2C separately.
