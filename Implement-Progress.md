# Aegis-Gate Implementation Progress

> **How to maintain this file.** It is a *living snapshot*, not a
> changelog. The Completed Tasks Log at the bottom is the only
> append-only section. Every other section is overwritten in place.
> See [`plans/plan.md`](./plans/plan.md#03-progress-file-protocol-strict)
> §0.3 for the protocol; the rules in short:
>
> - **Last Completed** holds the *current* task in full detail.
> - **Recent History** holds the previous 5 tasks in 1–2 lines each.
> - **Next Task** holds the immediate next item.
> - All other sections (tracks, carry-overs, future phases) are
>   durable summaries — update only when the underlying state
>   changes, not on every task.
> - Append a row to **Completed Tasks Log** when a task closes.
>
> **For at-a-glance track priority** see
> [`plans/README.md`](./plans/README.md). For per-doc Implemented /
> Partial / Designed-only status see
> [`plans/implementation-matrix.md`](./plans/implementation-matrix.md).

---

## Status (snapshot)

- **As of:** 2026-06-02 (AI Operator Copilot P0–P4 + Observability
  OTel→SigNoz + SLO-message-quality P1 — all shipped + live-verified).
- **Workspace tests:** **~3 350 across 18 binaries** (all green;
  prior 3 300 baseline + composite-key RiskKey suite + v2.5
  PoW token roundtrip + loopback control-gate tests). `cargo
  test -p aegis-proxy --lib`: 679 passed. `-p aegis-security
  --lib`: 1467 passed. `-p aegis-core --lib`: 262 passed.
- **Dashboard bundle:** 479 485 bytes — `app.js` rebuilt
  2026-05-19 after the mockup sweep (dropped SSE/Audit-chain
  demo pills, Live-Feed CSV, Overview Export/Open-Grafana).
- **Headline perf** (`tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/`):
  prod-balanced profile sustained **4 891 RPS k6 / 6 392 RPS WAF-internal**
  for 2 min with **legit p99 1.03 ms, legit median 0.13 ms, legit OK 100 %,
  detection 80 %**. v2.5 changes are header-only on the hot path; no
  re-measurement required.
- **Active track:** **none mid-build.** AI Operator Copilot (P0–P4) +
  Observability (OTel→SigNoz traces + SLO-message-quality P1) both
  closed 2026-06-02. The prior **Cluster config sync & scaling** track
  closed 2026-05-27 (Phase 0+A+B+C+D). Pick the next track from
  "Next Task" / the deferred backlog. Plans:
  [`plans/future/ai-operator-copilot.md`](./plans/future/ai-operator-copilot.md),
  [`plans/future/observability-otel-and-alerts.md`](./plans/future/observability-otel-and-alerts.md).
- **v2.5 interop contract:** **shipped** —
  `challenge_token`/`submit_url`/`submit_method` wire shape,
  public `/challenge/verify` on data plane, loopback-gated
  `/__waf_control/*` on both mounts, `prod-balanced.yaml` ships
  `audit_path: ./waf_audit.log` + `control_secret:
  waf-hackathon-2026-ctrl`.
- **Composite-key risk:** **shipped end-to-end** (storage +
  data-plane wire-up + dashboard view). `RiskKey { ip,
  device_fp?, session? }`. `tenant_id` axis retired 2026-05-19.
  Remaining JA4 device-FP populate work tracked at
  [`plans/archive/risk-composite-key-data-plane.md`](plans/archive/risk-composite-key-data-plane.md).
- **AI detector:** **shipped** (AI-T1..T9, see history). Live on
  Detectors page; metrics back `AiDetectorRow`. Default OFF
  pending per-deploy calibration (current ONNX over-fires
  below 0.95 threshold).
- **DDoS posture:** **enforce by default** (`cfg.ddos.observe_only:
  false`). Operator opt-out via dashboard or YAML.
- **Response filtering:** **shipped** — stack-trace scrub +
  RFC 1918 mask + DLP redact rungs over every upstream response.
- **TierCache:** **removed 2026-05-11**; `X-WAF-Cache` stamps
  `BYPASS` per contract §9. Restoration spec in
  [`plans/archive/smart-caching.md`](plans/archive/smart-caching.md).
- **Operator UX:** every config defaults to **Redis state**; the
  Makefile auto-starts the dev Redis on `run-*` targets.
  `make build && make stage && ./waf run` is the v2.5 §8 binary-
  contract boot path.

---

## Last Completed

**Task:** 2026-06-03 — Centralize AI Operator Copilot config into
YAML (`observability.copilot`) with a `${secret:...}` key reference
and config-plane hot-reload. On `develop`, green (5 commits).

**Headline:** the copilot was the only subsystem still configured by
raw `LLM_*` env. It now lives under `observability.copilot` like every
other subsystem, the API key is a `${secret:...}` reference resolved
per-node (never inline, never in the cluster doc), and the live service
hot-reloads via the config plane — enable/disable/model/key-rotation
take effect cluster-wide with no restart. Legacy `LLM_*` env stays as a
back-compat fallback.

### What shipped

1. **Config schema** (`aegis-core/config.rs`, Phase 1). `CopilotConfig`
   under `ObservabilityConfig` — `enabled` / `provider`
   (`openai_compatible` | `anthropic`) / `base_url` / `model` /
   `timeout_ms` / `briefing_interval_secs` / `api_key_ref`. 4 unit tests
   (defaults, absent-key default, full block with the secret-ref
   preserved un-resolved, anthropic variant).

2. **`CopilotService::from_config` + live-swap global** (`aegis-control
   copilot/service.rs`, Phase 2). Builds the provider from config (key
   passed in by the caller — the secrets resolver stays out of
   aegis-control). `OnceLock<CopilotService>` → `ArcSwap`; `global()`
   returns an `Arc` (safe across `.await`) + `set_global()` for hot-swap.
   `from_env` retained as the lazy fallback. 5 unit tests.

3. **Boot wiring + secret resolution + briefing-from-cfg** (`aegis-proxy
   run.rs` / `accept.rs`, Phase 3). `run()` resolves
   `observability.copilot.api_key_ref` via `resolve_copilot_api_key`
   (env / file / vault / cloud) and installs the config-built service;
   disabled block → `from_env` fallback. The P4 briefing scheduler reads
   `observability.copilot.briefing_interval_secs` (env only as fallback).

4. **Config-plane fold** (`aegis-proxy config_source/reload.rs`,
   Phase 4). `apply_cfg_change_to_copilot(new_cfg)` re-resolves the key +
   rebuilds + `set_global`, wired into `apply_folded_stores` so both the
   redis-source watcher and file-reload paths hot-swap the copilot on
   apply. 3 llm-gated tests incl. `${secret:env:...}` resolution.

5. **Docs + config** (Phase 5). `observability.copilot` example in
   `config/dev.yaml`; `ai-operator-copilot.md` Configuration section
   rewritten YAML-first; `.env`/`.env.example` reduced to just the
   key (backing the `${secret:env:LLM_API_KEY}` ref) sourced by
   `make run-copilot`; matrix + this file updated.

### Verification

- `cargo test -p aegis-core --lib copilot_config` → 4 passed.
- `cargo test -p aegis-control --features llm --lib copilot::service`
  → 6 passed (4 without `llm`).
- `cargo test -p aegis-proxy --features "redis geoip ai affinity llm"
  --lib config_source::reload::tests::copilot` → 3 passed.
- Builds clean: aegis-proxy with/without `llm`; `aegis-bin` with
  `redis geoip alerts ai affinity otel llm`.

### Prior milestone (2026-06-02)

AI Operator Copilot P0–P4 shipped + live-verified end-to-end against a
vLLM endpoint (Qwen3.6-35B): summary, ask, smart-catch triage (5
grounded campaigns), scheduled briefings, per-event clustering.
Observability: OTel→SigNoz traces smoke-verified (full action spread in
ClickHouse) + SLO-message-quality P1 (`slo/dispatch.rs`). Secure-env
`.env` workflow added to `make run-copilot`.

---

## Recent History

| Date | Task | Outcome |
|---|---|---|
| 2026-06-03 | Copilot config centralized into YAML + config-plane hot-reload | See Last Completed. `observability.copilot` (`CopilotConfig`) + `${secret:...}` key ref + `ArcSwap` live-swap + `apply_cfg_change_to_copilot` fold. 5 commits, 12 new tests. Legacy `LLM_*` env back-compat retained. |
| 2026-06-02 | AI Operator Copilot P0–P4 + Observability (OTel→SigNoz, SLO msg P1) | Copilot summary/ask/triage/briefings/clustering shipped + live-verified (vLLM Qwen3.6-35B). OTel traces → SigNoz smoke-verified; SLO alert messages P1; secure `.env` workflow in `make run-copilot`. |
| 2026-06-01 | Tier A "completionist warmup" (A1–A4) | AI-row feature-off UI polish (R2-009 sub-A/B); 2 pre-existing red tests fixed (reaper runtime-guard + bundle-budget); JA4 `device_fp` axis test; `threat_intel` subdomain walk. Candidates doc archived. |
| 2026-05-19 | v2.5 contract compliance + bind hardening + dashboard mockup sweep + plans cleanup | Two merges: `150f3cb` (loopback gate) + `fd587db` (challenge wire shape, prod-balanced, dashboard sweep, SUBMISSION/STAGING docs). 13 issue-fix sprints + `dns-upstream-resolution.md` archived. |
| 2026-05-18..19 | Composite-key RiskKey data-plane wire-up (Phase E) + Top Attackers Composite view | Storage layer + 8 data-plane `*_with_key` swaps + dashboard "Composite RiskKey" tab + per-bucket reset (`POST /api/risk/reset_key`). `tenant_id` axis retired. |

For full chronological detail see `git log` and the
`plans/archive/issue-fix/` sprint READMEs.

---

## Next Task

**▶ NEXT: pick a track — no build in flight.** The AI Operator Copilot
(P0–P4 + YAML-config centralization + config-plane hot-reload) and the
Observability P1 (OTel→SigNoz traces + SLO message quality) are both
closed. Candidate next tracks, smallest-first:
- **Observability P2–P4** (`plans/future/observability-otel-and-alerts.md`):
  remaining `AlertEvent` variants beyond SLO, dashboard/trace deep-links,
  likely-cause hints; metrics+logs live smoke through the Collector;
  optional app-side OTLP push; SIGTERM batch flush.
- **✅ AI Operator Copilot — SHIPPED 2026-06-02/03.** P0–P4 live-verified;
  config now YAML + `${secret:...}` ref + hot-reload. Plan:
  [`plans/future/ai-operator-copilot.md`](./plans/future/ai-operator-copilot.md).
- Cluster polish backlog (Redis keyspace-notify fast path, Console
  fleet-view, `redis_cluster` backend) — all optional.

**⏸ DEPRIORITIZED: B1 · Tier 1A — wire the API-security guards.** The
`api_keys` / `hmac_sign` / GraphQL modules are built + unit-tested but
dormant. Wire-up is parked on an open **concept question**: API-key
verification + HMAC + business-rule/schema validation arguably belong in
the **API gateway / router** layer, not the WAF. (GraphQL depth/
complexity limits are more clearly WAF-shaped — resource-exhaustion.)
Revisit the WAF-vs-gateway boundary before building. Matrix row
`api-security.md` is marked **Partial (built, dormant)**, not Implemented.

**✅ Tier A "completionist warmup" — CLOSED 2026-06-01.** Four sub-day
debts swept (all on `develop`, green): **A1** R2-009 sub-A+sub-B AI-row
feature-off polish; **A2** both pre-existing red tests fixed
(`spawn_reaper` runtime-guard + documented bundle-budget bump,
`assets/dashboard/bundle-budget.md`); **A3** JA4 `device_fp` axis (was
already wired — added the missing isolation test + fixed a stale
comment); **A4** `threat_intel::check_domain` subdomain suffix walk.
Candidate trail archived at
[`plans/archive/next-step-candidates-2026-06-01.md`](./plans/archive/next-step-candidates-2026-06-01.md).

---

**Cluster config sync & scaling — ✅ TRACK COMPLETE** (2026-05-27): Phase 0
(KV primitives) + Phase A (config plane) + Phase B (folded ALL console
toggles/CRUD: AI, response_filter, tier, detectors, rules, upstreams) + Phase C
(multi-node metrics aggregation) + Phase D (HAProxy single-VIP — was already
shipped as HA-T1). Full plan + per-fold technical notes in
[`plans/archive/cluster-config-sync-and-scaling.md`](./plans/archive/cluster-config-sync-and-scaling.md).
**No remaining work on this track.** Optional polish backlog (P2): Redis
keyspace-notification fast path, Console fleet-view, `redis_cluster` backend.
Pick the next track from "Tracks in flight" / the deferred backlog below.

**Follow-ups since (post-track):**
- **File/etcd reload parity** (`8be7c14`) — the file watcher now re-derives the
  folded stores (rules/upstreams/tiers/ai/response-filter) via
  `reload::apply_folded_stores`, matching the config plane.
- **Dashboard 409 auto-retry** (`38d6fb2`) — `csrfMutate` retries on
  `version_conflict`.
- **etcd config *source* removed** (this session) — `config_source/etcd_source.rs`,
  the `ConfigReloadSource::Etcd` variant, `AEGIS_CONFIG_SOURCE=etcd`, and
  `deploy/etcd/` deleted; redundant with file + the redis config plane. Config
  now loads only from the YAML file (+ config plane). **etcd remains a
  service-discovery adapter** (`sd/etcd.rs`, under the same `etcd` feature) —
  untouched.
- *Pre-existing red tests — ✅ FIXED 2026-06-01 (Tier A · A2):*
  `aegis-bin state_select::in_memory_selects_in_memory_backend` (reaper
  `tokio::spawn` outside a runtime — now guarded via `Handle::try_current`)
  and the 2 `dashboard_polish` JS-bundle-size budget tests (honest budget
  bump 444→540 KB / 624→720 KB raw, documented in
  `crates/aegis-control/assets/dashboard/bundle-budget.md`).

**DONE (all on `develop`, green):**
- **Phase 0** — `StateBackend` KV primitives (`incrby`/`expire`/`scan_prefix`/`cas_set`) `dcdd96f`.
- **Phase A** — full config plane: `ConfigStore` (versioned `config:waf:doc`,
  CAS activation, immutable snapshots, rollback, per-node ACK) `e9691d1`;
  `redis_source` watcher (apply via `reload::` helpers, ACK/NACK/fail-static)
  + boot wiring `e4bc458`; async `AuditedMutate::apply_async` + `PUT`/`POST
  /api/config`(+`/rollback`) `912b16e`; `GET /api/config` drift `312ab8d`;
  Scaling-page `ConfigVersionCard` `30d22f9`.
- **Phase B (partial)** — folded **AI** `3d2ca70`, **response_filter**
  `a5b818d` (1st `WafConfig` schema ext), **tier** `08a8e65`+`eacaa4b`
  (boot-path refactor threading `TierStore` run.rs→watcher+services + schema
  ext), **detectors** (base **+ per-tier** through the config plane; see
  below), **rules** (inline-rules schema + CRUD fold; see below), **upstreams**
  (per-node DNS pool rebuild on swap + 3-handler fold; see below). HA hardening
  already built (`node.id` HA-T3, `/api/cluster.peers` HA-T4).
- **Detectors fold (full)** — the plan's "apply-side already wired" was only
  true for the **base**: `apply_cfg_change_to_mask` re-derived base via
  `DetectorMask::from_config` and *preserved* live per-tier overrides, never
  reading `cfg.detectors.per_tier`. Folding the PUT naively would have
  **silently dropped** per-tier overrides on the next ~3s poll. Full fold
  shipped instead (user-confirmed):
  - *Pure (aegis-security)* — `DetectorMask::resolve_tier_override` (tri-state
    `TierDetectorMask` → full mask, `None`=inherit base) +
    `MaskState::from_detectors_config(cfg.detectors, ai_enabled)` (base + `Ai`
    bit from sibling `cfg.ai.enabled` + per-tier overlays). One constructor now
    shared by boot **and** every watcher.
  - *Apply (reload.rs)* — `apply_cfg_change_to_mask` now `store_state`s the FULL
    `MaskState` from cfg. **Contract change** (file/etcd/redis all in lockstep):
    `cfg.detectors.per_tier` is now the source of truth — a live override absent
    from cfg is cleared. Side effect / bugfix: file+etcd reloads now set the
    base `Ai` bit from `cfg.ai.enabled` (previously clobbered off).
  - *Boot (run.rs)* — seeds via `from_detectors_config` so per-tier overlays
    authored in YAML apply at boot, not just after the first reload.
  - *Write (admin_mutate.rs)* — `patch_detectors` patches base toggles
    (`ai`→sibling `cfg.ai.enabled`, `open_redirect`→`.enabled`, rest →
    `cfg.detectors.<class>.enabled`) + per-tier (`Some`→all-`Some`
    `TierDetectorMask`, `null`→remove); `handle_detectors_put` rewritten to the
    `apply_async`/`activate` template (requires a state backend; retires the
    local-snapshot model). Old `mask_state_to_json` removed.
- **Rules fold (full)** — discovered that dashboard rules were **ephemeral +
  node-local**: the engine `RuleSet` boots empty (`aegis-bin` `RuleSet::new()`),
  the `RuleStore` boots empty, and `cfg.rules.paths` is **never loaded** into
  the live engine (snapshot/backup tooling only). Folding it therefore *added*
  durability + propagation (net win, user-confirmed):
  - *Schema (aegis-core)* — `cfg.rules.inline: Vec<RuleDef{id,body,enabled}>`
    (the persistent rule list; `cfg.rules.paths` untouched for backup tooling).
  - *Store (aegis-control)* — `RuleStore::replace_all(&[RuleDef])` makes the
    store match `cfg.rules.inline` exactly (validates id+body, drops absent,
    returns rejected); reuses `rebuild_active_ruleset`.
  - *Apply (reload.rs)* — `apply_cfg_change_to_rules` re-derives the store +
    engine ruleset from `cfg.rules.inline` (source of truth) on every swap.
  - *Plumbing* — `RuleStore` lifted to `run.rs` (TierStore template) + threaded
    through `admin_accept_loop` → `spawn_with_mask_and_leader`; ApplyTargets
    gains `rules` + `active_ruleset` (`pipeline.rules_arc()`, in scope at the
    watcher spawn). Boot seeds the store from `cfg.rules.inline` so rules are
    live from the first request.
  - *Write (admin_mutate.rs)* — `patch_rule_upsert`/`patch_rule_remove` patch
    `cfg.rules.inline`; all 4 CRUD handlers (POST/PUT/DELETE/toggle) rewritten
    to the `apply_async`/`activate` template. **Existence checks run against the
    doc, not the local store** (eventual-consistency-safe: create-then-edit
    before the next poll works). Body+id validated up front (400 vs silent
    skip). Old `rebuild_ruleset_after_mutation` removed.
- **Upstreams fold (full)** — the plan's "sizable risky feature" was overstated:
  the live pool rebuild already exists (`PoolRegistry::apply` does the atomic
  pool + circuit-breaker + connection-pool swap; the audit-mutated PUT used it).
  The only gap was calling it from the *reload* path + handling **async DNS**
  (the watcher's `apply_and_swap` was sync). Shipped:
  - *Apply (reload.rs)* — `apply_cfg_change_to_upstreams` (async): resolves
    `cfg.upstreams` **per node** (`expand_hostname_members`, `SoftSkip`) then
    `PoolRegistry::apply`. `apply_and_swap` is now `async`; the watch loop
    `.await`s it. The shared doc keeps operator hostnames; each node uses its
    own resolver view (user-confirmed over freezing IPs at PUT time).
  - *Plumbing* — ApplyTargets gains `upstream_writer`
    (`Arc::new(upstream_ctx.pools.clone())`, in scope at the watcher spawn).
  - *Write (admin_mutate.rs)* — `patch_upstreams_replace` / `patch_upstream_pool_set`
    / `patch_upstream_pool_remove` patch `cfg.upstreams` on the doc (raw request
    JSON → YAML, since `PoolConfig` isn't `Serialize`). All 3 handlers
    (`PUT /api/upstreams/config`, pool upsert, pool delete) folded to
    `apply_async`/`activate`; `cfg` param dropped (existence + route-ref checks
    now run against the doc). Local `Strict` DNS resolve kept as a 400 typo gate
    (result discarded). `upstreams_audit_view` removed.
- **Phase C — metrics aggregation (DONE, 2026-05-27)** — `e47fa95` (foundation)
  + follow-up (wiring). Multi-node cluster-wide P5 route-activity + P4
  access-list-hit counters.
  - *Primitive*: `StateBackend::get_counter` (encoding-agnostic counter read —
    in-memory decodes LE bytes, Redis parses the decimal string; forwarded
    through Metered + Reconciling wrappers).
  - *Helper* (`metrics/window_flush.rs`): `WindowFlush` (per-`(id,abs_ts)` delta
    → `INCRBY <prefix>:<abs_ts>:<id>` + TTL), `read_buckets`/`sum_window`/
    `read_window`, `AggregateCache` (`ArcSwap` snapshot the flush task refreshes),
    `spawn_flush_task` (flush + cache-refresh + edge-triggered `metrics_flush_failed`
    audit). **Keyed by absolute bucket ts** → correct across ring rotation.
  - *Sources*: `BucketSource` for `RouteActivityWindow` + `AccessListStore`
    (abs-ts reconstruction from `last_bucket_ts`; only actively-written buckets
    have non-zero deltas, for which reconstruction is exact).
  - *Wiring*: `accept.rs` spawns 3 flush tasks (`waf:route` / `waf:hits:bl` /
    `waf:hits:wl`) + sets the caches on `DashboardServices` **only when
    `cfg.state.backend != in_memory`**. The 3 sync GET endpoints
    (`/api/analytics/route-activity`, `/api/blacklist|whitelist/hits`) read the
    cache when wired (cluster-wide) else the local rings (single-node). Sync
    dispatcher kept — the cache sidesteps the can't-`.await` problem (route
    `last_seen_age_s` stays node-local).
  - *Follow-up (ops, not code)*: re-run the `prod-balanced` 5k-RPS bench with the
    flush tasks active to confirm no p99 regression (design step 5).
- **Phase D — HAProxy LB (already DONE; the plan entry was stale)** — verified
  2026-05-27 that this was shipped as **HA-T1 (run-05)**, not outstanding:
  - `deploy/haproxy/haproxy.cfg` — single-VIP config (`:9180` plaintext / `:9443`
    TLS, `leastconn`, `/healthz/ready` http-check, `/stats` on `:8404`).
  - `aegis-lb` service in `deploy/docker-compose.dev.yml` (`profiles: ["ha"]`,
    `haproxy:2.9-alpine`, VIP + stats ports, healthcheck, `host.docker.internal`
    extra_host for Linux).
  - Single-VIP RPS benchmark: `tests/cluster/05-single-vip-baseline.sh` (brings
    up aegis-lb + 2 WAF nodes, k6 at the VIP, asserts both backends served
    ≥ 15 %, prints throughput) — part of the `tests/cluster/01..06` HA suite.
  - Helm: `deploy/helm/aegis-gate` data-plane `Service.type: LoadBalancer` +
    replicas/HPA = the k8s-native single-VIP equivalent.
  No new code needed. (Optional ops follow-up: run `tests/cluster/05` to capture
  a fresh throughput number — deferred per the docker-cleanup caution.)

**REMAINING:** none — the **Cluster config sync & scaling track is complete**
(Phase 0 + A + B fold-all + C + D). Deferred backlog below is independent.

**Reusable fold patterns (from AI / response_filter / tier / detectors / rules / upstreams):**
- *Write side*: handler patches the field on the shared doc's YAML blob via
  `serde_yaml::Value` (`WafConfig` isn't `Serialize`), seeds from
  `services.config_yaml_path` when no doc exists, validates via
  `aegis_core::load_config_str`, activates via `services.mutate.apply_async`
  → 200 `{version}` / 409 `{current}`. See `handle_ai_enabled_put` /
  `handle_response_filter_put` / `handle_tier_put` + the `patch_*` helpers in
  `admin_mutate.rs`.
- *Apply side*: add `reload::apply_cfg_change_to_<x>` (re-derives the
  in-process store from `new_cfg`), add a field to
  `redis_source::ApplyTargets`, call it in `apply_and_swap`, pass the handle
  at the `run.rs` watcher-spawn site.
- *Services-level stores* (created in `DashboardServices::spawn`) need the
  **TierStore plumbing template**: create in `run.rs`, thread the `Arc` into
  `spawn_with_mask_and_leader` (new param; `spawn`/`spawn_with_mask` pass a
  fresh default so test call sites stay untouched) AND `admin_accept_loop`.
- *If a new schema field carries a `Vec`* (like tier `pipeline`), drop `Copy`
  from the config struct's derive.

Deferred backlog (pick up after the above) from `plans/future/`:

- **Smart caching** —
  [`plans/archive/smart-caching.md`](plans/archive/smart-caching.md).
  Flips `X-WAF-Cache: BYPASS` (always today) to `HIT`/`MISS` for
  allow-listed GET routes. Phase 1 in-memory LRU is ~3 days,
  Phase 4 (Redis-backed + bypass intelligence) closes the spec.
- **JA4 device-FP populate** —
  [`plans/archive/risk-composite-key-data-plane.md`](plans/archive/risk-composite-key-data-plane.md).
  Storage + most call sites landed; `device_fp` axis still set
  to `None` in `build_risk_key`. ~50 LoC + a JA4 hash helper.
- **Audit cold-tier export** —
  [`plans/archive/audit-cold-tier-export.md`](plans/archive/audit-cold-tier-export.md).
  Beyond the 200-event ring cap; scheduled S3/SFTP delivery.
- **Rule non-block actions** —
  [`plans/archive/rule-non-block-actions.md`](plans/archive/rule-non-block-actions.md).
  Tarpit / mirror / challenge actions beyond block/log.

### Parked tracks (long-lived; pick up only on request)

- **CC-T3** — i18n + help.jsx slides (outsized scope; designer
  input needed).
- **B6-T5 (fd-pass)** — library complete; accept-loop drain
  refactor remains for end-to-end hot-restart via SIGUSR2.
- **B6-T4 (HSM)** — explicitly deferred; PKCS#11 against a real
  HSM, no design pass yet.
- **Rollback v6+** — rule CRUD, risk_reset, alert receivers,
  upstream pools (each requires audit-shape changes that
  pre-date the rollback dispatcher).

---

## Tracks in flight

Order is execution priority — earlier rows run first.

| # | Track | Plan | State |
|---|---|---|---|
| 1 | **Phase B — production-packaging (B6)** | [`plans/phase-b/README.md`](./plans/archive/phase-b-2026/README.md) | **active**; B1..B5 closed; B6-T1 in flight |
| 2 | **Console config pages (CC-T*)** — upstreams editor + alert-channel mgmt | [`plans/console-config-pages.md`](./plans/archive/console-config-pages.md) | **plan-only — awaiting confirmation**. CC-T1 (upstreams CRUD) → CC-T2 (alert receivers in Tracking page) → CC-T3 (i18n / OpenAPI / docs) |
| 3 | Scaling configuration (SC-T*) — three-layer worker/cluster/state surface | [`plans/scaling-config.md`](./plans/archive/scaling-config.md) | **parked plan — awaiting confirmation**. Surfaces existing L1/L2/L3 model in Console; adds `/api/state` health endpoint |
| — | Dashboard redesign (DD-T0..T8) | [`plans/dashboard-redesign.md`](./plans/archive/dashboard-redesign.md) | closed in run-10 |
| — | Console API integration (CI-T1..T8) | [`plans/console-api-integration.md`](./plans/archive/console-api-integration.md) | closed |
| — | HA cluster (HA-T1..T5) | [`plans/cluster-ingress-lb.md`](./plans/archive/cluster-ingress-lb.md) | closed in run-05 |
| — | Interop contract (IT-T1..T6) | [`plans/interop-contract.md`](./plans/archive/interop-contract.md) | closed |
| — | Interop dry-run (DR-T1..T7) | [`plans/interop-dry-run.md`](./plans/archive/interop-dry-run.md) | closed in run-08 |
| — | Post-run-08 (AF-T1, HP-T1, TLS-T1) | [`plans/post-run-08.md`](./plans/archive/post-run-08.md) | closed |
| — | Benchmark mode (B-T1..B-T6) | [`plans/benchmark-mode.md`](./plans/archive/benchmark-mode.md) | folded into Phase B as B5-T2 |
| — | Security toggles (P1..P8) + post-k6 (F-T1..F-T10) | [`plans/post-k6-followup.md`](./plans/archive/post-k6-followup.md) | closed |
| — | Enterprise dashboard (D-M1..D-M6) | [`plans/archive/dashboard-enterprise/`](./plans/archive/dashboard-enterprise/) | closed — superseded by DD-T0..T8 |
| — | Phase B intake | [`plans/archive/advanced-features.md`](plans/archive/advanced-features.md) | open — for items NOT covered by `plans/phase-b/` |

---

## Carry-overs / known limitations

Durable list of things that work but aren't fully shipped. Each row
is grouped under the Phase B milestone that closes it, so when a
milestone ships you can see exactly which lines to delete. See
[`plans/phase-b/README.md`](./plans/archive/phase-b-2026/README.md) for the task
breakdown.

**Access-list runtime enforcement** ✅ **CLOSED** 2026-05-03 PM
(`d801dfd`). `AccessListEntry::matches(peer, country_lookup)` lives
on the aegis-control type; `ProxyContext` owns shared `Arc<AccessListStore>`
for blacklist + whitelist + a `OnceLock`-installed
`AccessListCountryLookup` adapter wrapping the live `MaxMindReader`.
Data-plane handler consults blacklist immediately after XFF
resolution (cheapest-possible block) and short-circuits the detector
chain on a whitelist hit. Strikes still override whitelist so a
hammering whitelisted source can't burn CPU. 6 new unit tests cover
ip / cidr / country / expired / no-lookup-silent-miss / first-hit-
traceability paths.

**Multi-vhost upstream HTTPS / SNI pinning** — surfaced 2026-05-03 PM.
`MemberConfig.host_header` (commit `062d602`) handles the Host-
header rewrite case for vhost-routed backends. The TLS SNI +
cert-validation hostname for HTTPS upstreams still come from the
URL host (the member IP); operators with public TLS upstreams that
strictly validate SNI vs cert CN/SAN need a sidecar (Caddy/nginx)
today. A custom-resolver pass that pins both Host header AND SNI
to the override is queued; ~80 LOC + a hyper-rustls
`ServerName::DnsName(override)` shim.

**WS-T5 — real WS round-trip integration test** — bridge mechanics
shipped (T2/T3/T4 + T6 metrics), all three sub-mechanics covered
by unit tests (`is_websocket_upgrade`, `forward_websocket_upgrade`,
`bridge_upgrade`). The genuinely missing case is "successful WS
bridge through `forward_allow_to_upstream` with hyper actually
serving the connection." Manual verification at
`tests/manual/websocket-bridge.sh` covers it today; an in-process
test would need ~150 LOC to plumb the full ProxyContext + 14
parameters of detector chain — meaningful effort, low marginal
coverage.

**B1 — HA & multi-node** ✅ **CLOSED** 2026-04-29 — single-node
+ Redis-primary + local-fallback ships;
`docs/operations/ha-clustering.md` is Implemented. Two minor
follow-ups deliberately deferred from B1: counter merge-back
on partition heal (sliding-window can't be cleanly merged
without a wire-format change), and the GitOps / witness /
threat-intel lease gates (those subsystems aren't running as
background tasks today; their boot sites carry TODOs pointing
at `spawn_with_lease`). Per-member pool health is still
hardcoded to 0 in `pool_snapshot_provider` — depends on
membership-driven cluster runtime, not on the lease layer.

**B2 — Operational integrations** ✅ **CLOSED** 2026-04-29 —
the cloud-secrets quartet (vault/aws/gcp/azure) and the
service-discovery trio (consul/etcd/k8s) all ship. Both
`docs/control-plane/secrets-management.md` and
`docs/data-plane/service-discovery.md` are now Implemented.
HSM (B6-T4) and DNS SRV remain on the deferred list.
- **Service discovery:** `file` watcher + churn safety in
  `aegis-proxy/src/sd/`; Consul / etcd / k8s adapters not
  implemented despite being mentioned in the module doc.

**B3 — Data feeds + filtering** ✅ **CLOSED** 2026-04-29 — all
four sub-tasks ship: B3-T1 GitOps poll driver
(`aegis-control/gitops/poll_driver`); B3-T2 TAXII fetch loop
(`aegis-security/taxii` feature); B3-T3 GeoIP MaxMind reader
(`aegis-security/geoip` feature); B3-T4 ICAP TCP client
(`content::icap::tcp`). `threat-intelligence.md`,
`geoip-filtering.md`, and `content-scanning.md` all flipped
Partial → Implemented. `gitops-change-management.md` banner
stays Partial until the boot-site lease wrap (`aegis-bin` /
`aegis-proxy::run`) lands — same constraint as ACME.

**B4 — Operator tooling** ✅ **CLOSED** 2026-04-29 — all
four sub-tasks ship: B4-T1 `waf snapshot` (JSON envelope,
schema versioning, blake3 hash), B4-T2 `waf restore`
(atomic dry-run validation + rollback), B4-T3 full upstream
proxying (`upstream::forward` w/ hop-by-hop scrub on both
directions + Host rewrite + X-Forwarded-Host), and B4-T4
streaming SSE (`admin_sse::sse_response` w/ 15s heartbeat,
boxed body type, lag handling). `dr-backup.md` flipped
Implemented for the config/rules surface. Body forwarding
is currently buffered — true streaming forwarding (no
collect) is a deeper refactor that touches every listener
+ the SecurityPipeline body-frame hooks; deferred to a
future stream-through change.

**B5 — Protocols + benchmark** ✅ **CLOSED** 2026-04-29 —
both sub-tasks ship: B5-T1 HTTP/3 listener
(`aegis-proxy/http3` feature on quinn 0.11 + h3 0.0.8 +
h3-quinn 0.0.10), B5-T2 benchmark mode core slice
(`aegis-proxy::benchmark` ships `BenchmarkConfig` +
`StageTimings` + `X-Aegis-*` header serialiser, wired into
`proxy::handle_request`). `protocols.md` and
`benchmark-mode.md` both flipped Implemented. **Open
follow-ups** (not blocking B6): auto-stamp `Alt-Svc` on
every TLS response (helper exists; TLS-listener wire-up
deferred); IP allowlist + HMAC-token gating for benchmark
mode (deferred to the full `plans/benchmark-mode.md` plan);
per-detector timing + dashboard panel.

**Perf carry-overs surfaced 2026-04-29** (live re-runs
exposed five real gaps the milestones above didn't catch):

*Single-node perf re-run
([`tests/results/README-2026-04-29.md`](./tests/results/archive/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md))*
- ✅ **Data-plane Allow forwarding shipped** (carry-over A,
  closed 2026-04-29). `lib.rs::handle_data_request` now
  resolves the route + member through a `ProxyContext`
  built once in `run()` and forwards via
  `crate::upstream::forward::forward()`. The Allow branch
  no longer returns the synthetic `OK\n` body. Live perf:
  31.5 k RPS / 504 µs median / 3.66 ms full-hop p95 against
  `aegis-httpbin` (log:
  `tests/results/baseline-allow-forwarded-2026-04-29.log`).
- ✅ **Rate-limit 429 wire confirmed** (carry-over B,
  closed 2026-04-29). The 429 + Retry-After path was
  already live at `lib.rs:1814`; the perf failure was a
  test-script calibration bug. `tests/load/rate-limit.js`
  burst defaults bumped (200→2 000 RPS, 6→8 s) so the
  burst clears the configured budget; thresholds relaxed
  to match real budget arithmetic; 403 strike-block path
  also accepted. Re-run: `status_429_observed = 50` PASS
  (log:
  `tests/results/rate-limit-2026-04-29-fixed.log`).

*Cluster + HTTPS re-run
([`tests/results/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md`](./tests/results/archive/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md))*
- ✅ **Leader-state admin endpoint shipped** (carry-over 3,
  closed 2026-04-29). New `LeaderView` shared cell +
  background polling task that reads
  `lease_store.holder("leader:cluster")` every 2 s and
  updates `/api/cluster` with `is_leader`, `leader_node`,
  `our_node`. Singleton `leader:cluster` lease (5 s TTL) is
  acquired by exactly one node so failover takes ≤ 10 s.
  `tests/cluster/02-leader-failover.sh` now PASS.
- ✅ **Rate-limit per-node behaviour documented**
  (carry-over 4, closed 2026-04-29 as a doc clarification).
  `docs/security/rate-limiting.md` now distinguishes the
  two limiter surfaces: per-IP volumetric guard
  (`IpRateLimiter`, intentionally per-node), and named
  buckets (`sliding::check`, cluster-shared via
  `StateBackend`). The "v1 → v2 counters are clusterable"
  banner that misled the original carry-over investigator
  is replaced with the correct dual-surface contract.
- ✅ **Data-plane TLS loader shipped** (carry-over 5,
  closed 2026-04-29). `config.tls.certificates` is now
  consumed at boot: a single `tokio_rustls::TlsAcceptor` is
  built once from the cert/key/host list and reused by
  every `listeners.data[*]` whose `tls: true` is set.
  ALPN forced to `http/1.1` for now (HTTP/2 over TLS is a
  separate task). New
  [`config/prod.yaml`](./config/prod.yaml) +
  [`tests/fixtures/tls/`](./tests/fixtures/tls/) self-signed
  cert pair drive `tests/load/tls-baseline.js` end-to-end
  (run-04 measured 31.8 k RPS / handshake p95 2.12 ms /
  request p95 1.03 ms).
- ✅ **Carry-over 6 closed 2026-04-30** — HA perf test now
  routes through a single VIP. Plan
  [`plans/cluster-ingress-lb.md`](./plans/archive/cluster-ingress-lb.md)
  fully landed: HA-T1 (HAProxy reference deploy in
  `deploy/haproxy/haproxy.cfg` + `aegis-lb` compose service),
  HA-T2 (`tests/cluster/05-single-vip-baseline.sh` +
  `06-mid-burst-failover.sh` + `tests/load/failover-burst.js`),
  HA-T3 (`WafConfig.node.id` in
  `crates/aegis-core/src/config.rs` + `derive_node_id(&cfg)` in
  `lease_select.rs`), HA-T4 (`LeaderView::set_members` +
  `/api/cluster.peers[]` + membership heartbeat + roster
  poller in `crates/aegis-proxy/src/lib.rs`), HA-T5 (`POST
  /admin/drain` + `?strict=1` on `/healthz/ready` +
  SIGTERM-triggered drain with 5 s grace). Validated by
  run-05: 99.93 % allow_success on hard kill, 100 % on
  graceful drain.

**B6 — Production packaging**
- **Production packaging:** no Dockerfile, no Helm chart, no
  GitHub Actions CI — `deploy/` ships dev/test compose only.
- **Zero-downtime ops:** `supervisor.rs` + `hotbin.rs` + drain
  exist; no live binary-handover via fd-passing — restart is via
  supervised re-exec only.

When a milestone closes, delete the rows above it and append a
"**Bx milestone**" row to the Completed Tasks Log.

---

## Future phases

Order is execution priority — earlier phases run first.

1. **Phase B — production-readiness (active).**
   [`plans/phase-b/README.md`](./plans/archive/phase-b-2026/README.md).
   Six milestones (B1..B6) that close every Partial /
   Designed-only banner currently in `docs/`. Each milestone close
   removes the matching block of carry-overs above and flips the
   matching `> **Status:**` banners.
2. **Dashboard redesign (closed).**
   [`plans/dashboard-redesign.md`](./plans/archive/dashboard-redesign.md).
   Aegis WAF Console shipped in run-10 (DD-T0..T8). Per-page
   screenshot regression (DD-T4) is the only follow-up.
   Implementation notes live under
   [`docs/control-plane/enterprise/`](./docs/control-plane/enterprise/).
   The earlier milestone-paced plan was superseded and archived
   under [`plans/archive/dashboard-enterprise/`](./plans/archive/dashboard-enterprise/).
3. **Open intake.**
   [`plans/archive/advanced-features.md`](plans/archive/advanced-features.md)
   for proposals NOT covered by Phase B (e.g. multi-tenancy,
   anything new). Scored against the Impact / Reach /
   Cost / Confidence rubric.

---


---

## Verification & completion log (off-page)

- [`docs/progress/verification.md`](./docs/progress/verification.md)
  — last full-suite snapshot (tests + clippy + perf).
- [`docs/progress/completed-tasks-log.md`](./docs/progress/completed-tasks-log.md)
  — append-only log of every closed task.
