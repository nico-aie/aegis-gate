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

- **As of:** 2026-05-19 (post v2.5 contract compliance sprint).
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
- **Active track:** **Cluster config sync & scaling** (multi-node
  next-round). Plan:
  [`plans/future/cluster-config-sync-and-scaling.md`](./plans/future/cluster-config-sync-and-scaling.md);
  design doc
  [`docs/operations/cluster-config-distribution.md`](./docs/operations/cluster-config-distribution.md).
  **Done on `develop`:** Phase 0 — `StateBackend` generic KV primitives
  (`incrby`/`expire`/`scan_prefix`/`cas_set`, `dcdd96f`); Phase A core —
  `ConfigStore` (versioned `config:waf:doc` + CAS activation + immutable
  snapshots + rollback + per-node ACK) and the `redis_source` watcher
  (`e9691d1`). **Next:** see Next Task.
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
  [`plans/future/risk-composite-key-data-plane.md`](./plans/future/risk-composite-key-data-plane.md).
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
  [`plans/future/smart-caching.md`](./plans/future/smart-caching.md).
- **Operator UX:** every config defaults to **Redis state**; the
  Makefile auto-starts the dev Redis on `run-*` targets.
  `make build && make stage && ./waf run` is the v2.5 §8 binary-
  contract boot path.

---

## Last Completed

**Task:** 2026-05-19 v2.5 contract compliance + final-round
committee bind hardening + dashboard mockup sweep + plans
folder cleanup. Branch
`fix/v2.5-contract-compliance-and-cleanup` →
develop @ `fd587db`.

**Headline:** the v2.5 interop contract surface is fully
conformant. `/__waf_control/*` is invisible from outside the
host (loopback peer-IP gate on both admin + data-plane mounts).
`/challenge/verify` is a public data-plane endpoint with the
contract-shape JSON. `prod-balanced.yaml` ships judging-ready
without operator edits.

### What shipped

1. **Committee loopback bind contract** (merge `150f3cb`).
   `should_dispatch_data_plane_control(path, peer)` gates
   `/__waf_control/*` on the public data plane; admin-mount
   `is_open_endpoint(method, path, peer)` only admits the
   namespace when `peer.is_loopback()`. Non-loopback callers
   fall through to standard pipelines (404 / login redirect).
   Benchmarker reaches the namespace via SSH tunnel from
   loopback. Boot-time NOTICE on stderr when `interop.enabled`
   AND admin bind is non-loopback (defence-in-depth reminder,
   not a hard fail — keeps dev Prometheus scrape working).

2. **Challenge wire shape (v2.5 §4 Format A)** (merge
   `fd587db`). Issue body emits `challenge_token` (packed
   `nonce.difficulty.expires_at_ms.mac`), `submit_url:
   /challenge/verify`, `submit_method: POST`. Verify body
   accepts `{challenge_token, nonce}`; returns `200 {ok:true,
   action:"challenge_verified"}` (was 204). `PowChallenge`
   gets `challenge_token()` / `unpack_token()` helpers with
   round-trip + malformed-input regression tests.

3. **Public `/challenge/verify` mount on data plane**
   (`accept.rs`). POST short-circuits the verify handler before
   the loopback control gate so the external benchmarker can
   POST solutions without an SSH tunnel. Old
   `/__waf_control/challenge_verify` branch removed; dispatcher
   signature trimmed (no more `pow_issuer`/`state` plumb-through).

4. **`prod-balanced.yaml` v2.5 fixes.** `audit_path:
   ./waf_audit.log` (was `/var/log/aegis/contract-audit.jsonl` —
   not where the benchmarker looks). `control_secret:
   waf-hackathon-2026-ctrl` (was `"REPLACE FROM SECRET MANAGER"`
   — failed every request with 403).

5. **Dashboard mockup sweep.** Removed `SSE (demo)` +
   `Audit chain demo` pills (status bar), Live Feed CSV button,
   Overview Export + Open Grafana buttons. Wired "View all →"
   on Overview to `#/top-attackers`. Bundle now 479 485 bytes.

6. **Docs.** New `deploy/STAGING-BENCHMARK.md` v2.5 delta block
   + SSH tunnel walkthrough + `/challenge/verify` smoke test;
   contract-default audit path applied throughout. README
   gained a hackathon-submission deploy call-out documenting
   `make build && make stage` as mandatory. Architecture.md +
   Requirement.md picked up the composite-key axis change and
   v2.5 contract coverage table.

7. **Plans folder cleanup (2026-05-19).** Moved 13 closed
   issue-fix sprints into `plans/archive/issue-fix/`; archived
   shipped `dns-upstream-resolution.md` (hickory-resolver +
   multi-A expansion in deps); flipped smart-caching matrix
   row from Implemented → Deferred (TierCache removed
   2026-05-11); drafted `plans/future/smart-caching.md`
   restoration spec.

### Verification

- `cargo test -p aegis-proxy --lib` → 679 passed, 0 failed,
  1 ignored.
- `cargo test -p aegis-security --lib` → 1467 passed.
- `cargo test -p aegis-core --lib` → 262 passed.
- `cargo check -p aegis-proxy -p aegis-core -p aegis-security`
  clean.
- 5 new control-gate unit tests in `accept::control_gate_tests`,
  1 added in `admin_auth_middleware::tests`, 3 new in
  `challenge::pow::tests` (challenge_token roundtrip + 2
  malformed-input variants).
- Manual: `make build && make stage && ./waf run` boots
  against `prod-balanced.yaml`; `curl -k -H "X-Benchmark-Secret:
  waf-hackathon-2026-ctrl" https://127.0.0.1:9443/__waf_control/capabilities`
  returns features payload. External
  `curl https://<public>:9443/__waf_control/capabilities`
  returns login redirect (loopback gate verified).

### Next-session hand-off

The full 2026-05-11 sprint is closed (now including PR-DNS-1 +
PR-DNS-2 — hostname-addressed upstreams shipped end-to-end with
background DNS refresh on TTL).

Two stale "open thread" notes were retired here on 2026-05-11:
- **AI-T2..T9** — flagged as "waiting on the operator's .onnx
  file" but actually shipped on 2026-05-03 PM in `80362e8`
  (operator handed over the model that day; AI-T1..T5 landed
  end-to-end). T6 metrics, T7 `make ai-link`, T8 integration
  test, and T9 dashboard `AiDetectorRow` all in tree. The
  hot-enable PUT (`f2ae002`, 2026-05-09) closed the only
  follow-up. Genuinely-open AI work is the §8 "out of scope"
  list (model hot-reload, drift detection, per-route threshold,
  SHAP/LIME, ensembles, GPU) — none required for v1.
- **FDP accept-loop drain refactor** — flagged as "the one
  durable open thread" but actually shipped on 2026-05-03 PM
  in `362c366` + `6fc56c1`. SIGUSR2 → `perform_handover` is
  wired end-to-end via the polling task in `run.rs:1366`;
  `InFlightCounter::admit` is wired on both planes
  (`accept.rs:848` admin, `accept.rs:987` data).

Nothing else is mid-flight. Future tracks beyond the two
retired notes: DNS Phase 3 (dashboard "Resolved IPs"
expandable, ~1 day) and AI model hot-reload (~½–1 day) are the
two smallest visible follow-ups.

---

## Recent History

| Date | Task | Outcome |
|---|---|---|
| 2026-05-19 | v2.5 contract compliance + bind hardening + dashboard mockup sweep + plans cleanup | See Last Completed. Two merges: `150f3cb` (loopback gate) + `fd587db` (challenge wire shape, prod-balanced, dashboard sweep, SUBMISSION/STAGING docs). 13 issue-fix sprints + `dns-upstream-resolution.md` archived. |
| 2026-05-18..19 | Composite-key RiskKey data-plane wire-up (Phase E) + Top Attackers Composite view | Storage layer + 8 data-plane `*_with_key` swaps + `RiskSnapshot` extension + dashboard "Composite RiskKey" tab + per-bucket surgical reset (`POST /api/risk/reset_key`). `tenant_id` axis retired. |
| 2026-05-18 | Detector-recall fix plan (ML rules-binary eval + juice-shop) | 4 sprints triaged in `plans/archive/issue-fix/2026-05-18-detector-recall-from-ml-eval/`. Recall 63.9 → target ≥ 95% scoped; juice-shop manual eval at 45/45 audit correlation. |
| 2026-05-17 | aegis-control + aegis-core security audits (16 commits) | F-CRITICAL bundles closed across rules CRUD, AuditAction enum, JA4-light fingerprint, ASN-class wire-up, bots ladder. "All issue-fix phases now closed." |
| 2026-05-14 | LT-RUN-6/7 fix plan execution | 25 audit findings triaged; 4 regraded as false positives (auditor read dead trait surfaces). 9 unit tests added; EVAL-01 CIDR + EVAL-02 RateLimit bugs fixed in unused-but-tested rule-engine code. |
| 2026-05-11 | Policy QA + crate audit triage (9 PRs) | 72 raw findings → 9 PRs landed across `2f50176` → PR #9. TierCache removed (PROXY-08/09). PR #7 response-filter wire-up (`Pipeline::on_body_frame`). PR #8 SEC-18/SEC-21/CTL-20 correctness. |

For full chronological detail see `git log` and the
`plans/archive/issue-fix/` sprint READMEs.

---

## Next Task

**Active track: Cluster config sync & scaling** — full plan +
per-fold technical notes in
[`plans/future/cluster-config-sync-and-scaling.md`](./plans/future/cluster-config-sync-and-scaling.md).

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
  below). HA hardening already built (`node.id` HA-T3, `/api/cluster.peers`
  HA-T4).
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

**REMAINING (resume order):**
1. **`rules`** — needs a NEW feature first: `cfg.rules` is `{paths, max_rule_count,
   strict_compile}` (rule *files*), NOT the rule list. Add `cfg.rules.inline:
   Vec<RuleDef>`, seed the `RuleStore` from it (reuse the TierStore
   run.rs→services plumbing), add `apply_cfg_change_to_rules`, then fold the
   CRUD handlers (post/put/delete/toggle each patch the inline list + activate).
2. **`upstreams`** — needs a NEW feature first: pools are NOT hot-reloadable
   today (`run.rs` warns "pools are NOT rebuilt"). Implement live pool rebuild
   (DNS re-resolve + health re-arm) on `cfg.upstreams` change, add
   `apply_cfg_change_to_upstreams`, then fold `PUT /api/upstreams/config`.
3. **Phase C — metrics aggregation** — `crates/aegis-control/src/metrics/window_flush.rs`
   (local ring → `incrby` flush, `expire` TTL=2×window) for `RouteActivityWindow`
   (P5) + `AccessListHits` (P4); flush tasks at boot; endpoint reads switch to
   `scan_prefix`+sum when `backend != in_memory`, else local rings;
   `flush_failed` audit. Design: [`plans/future/multi-node-metrics-aggregation.md`](./plans/future/multi-node-metrics-aggregation.md).
4. **Phase D — HAProxy LB** — `aegis-lb` container in `deploy/docker-compose.dev.yml`
   + Helm toggle + single-VIP RPS benchmark.

**Reusable fold patterns (from AI / response_filter / tier / detectors):**
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
  [`plans/future/smart-caching.md`](./plans/future/smart-caching.md).
  Flips `X-WAF-Cache: BYPASS` (always today) to `HIT`/`MISS` for
  allow-listed GET routes. Phase 1 in-memory LRU is ~3 days,
  Phase 4 (Redis-backed + bypass intelligence) closes the spec.
- **JA4 device-FP populate** —
  [`plans/future/risk-composite-key-data-plane.md`](./plans/future/risk-composite-key-data-plane.md).
  Storage + most call sites landed; `device_fp` axis still set
  to `None` in `build_risk_key`. ~50 LoC + a JA4 hash helper.
- **Audit cold-tier export** —
  [`plans/future/audit-cold-tier-export.md`](./plans/future/audit-cold-tier-export.md).
  Beyond the 200-event ring cap; scheduled S3/SFTP delivery.
- **Rule non-block actions** —
  [`plans/future/rule-non-block-actions.md`](./plans/future/rule-non-block-actions.md).
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
| — | Phase B intake | [`docs/future/advanced-features.md`](./docs/future/advanced-features.md) | open — for items NOT covered by `plans/phase-b/` |

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
   [`docs/future/advanced-features.md`](./docs/future/advanced-features.md)
   for proposals NOT covered by Phase B (e.g. multi-tenancy,
   RBAC/SSO, anything new). Scored against the Impact / Reach /
   Cost / Confidence rubric.

---


---

## Verification & completion log (off-page)

- [`docs/progress/verification.md`](./docs/progress/verification.md)
  — last full-suite snapshot (tests + clippy + perf).
- [`docs/progress/completed-tasks-log.md`](./docs/progress/completed-tasks-log.md)
  — append-only log of every closed task.
