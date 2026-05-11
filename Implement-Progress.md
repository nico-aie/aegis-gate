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

- **As of:** 2026-05-11
- **Workspace tests:** **~3 300 across 18 binaries** (all green;
  baseline 2 850 + ~450 from the 2026-05-04..11 sprint:
  Detectors & Tiers UX, Strike-Block enable/disable, AI hot-enable,
  policy-QA Phase 1 (8 findings), aegis-core gap fixes, PROXY-02
  regex/glob guard, P2C + Rendezvous Hashing correctness, TierCache
  removal, PR #7 response-filter wire-up + dashboard surface, PR #8
  SEC-18 / SEC-21 / CTL-20 correctness pack).
- **Dashboard bundle:** ~300 KB (size varies; the
  `crates/aegis-control/assets/dashboard/app.js` baseline is the
  authoritative number per build).
- **Headline perf** (`tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/`):
  prod-balanced profile sustained **4 891 RPS k6 / 6 392 RPS WAF-internal**
  for 2 min with **legit p99 1.03 ms, legit median 0.13 ms, legit OK 100 %,
  detection 80 %**. All three k6 thresholds passed. (Pre-PR #7;
  the new response-filter rungs pay one `Cow::Borrowed` check per
  rung on clean responses — the hot path overhead is structurally
  zero on unmodified bodies.)
- **Active track:** none open. The `plans/issue-fix/2026-05-11-policy-qa-and-audits/`
  triage is the most recently closed track (9 sub-PRs, see Recent
  History). AI-T2..T9 wait on the operator's `.onnx` file.
- **DDoS posture:** **enforce by default** (`cfg.ddos.observe_only:
  false` is the shipped default — 7c9e5dc landed 2026-05-09; CORE-01
  documented this 2026-05-11). Operators wanting log-only mode opt
  in explicitly via the dashboard's Traffic Gates page or
  `observe_only: true` in YAML.
- **Response filtering:** **shipped** (`Pipeline::on_body_frame`
  runs three independently toggleable rungs — stack-trace scrub,
  RFC 1918 IP mask, DLP redact — over every upstream response).
  Audit-mutated PUT `/api/response-filter` + dashboard tile under
  Settings → Response Filtering. See `docs/security/response-filtering.md`
  for the operator surface and `Architecture.md` §5 item 12 for the
  internal shape.
- **TierCache:** **removed 2026-05-11** (PROXY-08/09 — the module
  had zero call sites in the request pipeline). `moka` workspace
  dep dropped. `POST /__waf_control/flush_cache` still returns
  `{ok: true, supported: false}` per contract §9.
- **Closed 2026-05-03 (AM):** TCP forwarder Phase 4 (TCP-T1..T6),
  Binary handover library (FDP-T1..T6), SWEEP-T sweep tooling,
  MTLS-T10 Phase 2, B5 benchmark gating, geoip XFF wiring + 3-state
  pill.
- **Closed 2026-05-03 (PM, this session):**
  - Access-list runtime enforcement (`d801dfd`) — was a CRUD-only
    gap; data plane now consults the live Arc on every request.
  - AI-T1 stub (`d8660a9`) — `ai` Cargo feature + tract-onnx
    workspace dep + `WafConfig.ai: AiConfig` schema.
  - FDP accept-loop drain refactor (`faee699`) — SIGUSR2 polling
    task wired to `perform_handover`.
  - WebSocket bridge (`d612d4b` WS-T2/T3/T4 + `6f2730f` WS-T6 +
    `b3f61cb` WS-T5 e2e) — end-to-end raw-TCP forwarder +
    `OnUpgrade` bridge + audit pair + Prometheus metrics +
    Live-Feed proto pill + real round-trip integration test.
  - Manual validation scripts (`9585c7e`) — `tests/manual/`.
  - README + QUICKSTART rewrite (`ef1fdaa` + `b559922`) —
    Build → Run → Configure-upstream → Test → Deploy spine.
  - Login page fix (`01695f0`) — GET `/admin/login` now serves
    the standalone form.
  - Console SOC-UX pass (`c854617`) — Live Feed path/method/status
    fixed; Investigation defaults to recent-requests list +
    absorbs Attack Analytics; RequestDetail drawer shows
    status/latency/route/extra fields.
  - Multi-vhost upstream — `host_header` (`062d602`) + HTTPS
    SNI pinning (`c6098ae`) — vhost-routed backends including
    public TLS services (httpbin.org, GitHub Pages,
    Cloudflare-fronted) work without a sidecar.
  - Top Attackers page (`674c86f`) — first-class SOC view of
    `/api/attacks/top` with one-click pivot + block.
  - aegis-waf-tester Claude Skill (`cb95934` + `4d4f408` first
    run) — importable Claude Skill with 4 graded checklists +
    structured findings template; smoke run surfaced 7 findings.
  - All 4 skill findings closed (`405b2b8`) — GeoIP country
    fall-back to registered_country, detector_name() refactored
    to drop `detector:` prefix + preserve `path_traversal`,
    `unknown` filtered out of by-detector chart, bot mix shows
    honest empty state. PageErrorBoundary added so a single
    component crash never blanks the dashboard
    (closes operator-reported white-page bug).
  - Protocol-aware upstream UI + cookbook (`b559922`) —
    Members table gains Host-header column, Scheme dropdown
    surfaces Protocol matrix card, new
    docs/operator/upstream-cookbook.md with 8 per-protocol
    recipes, body-abuse detector doc updated for XXE +
    mass-assignment.
- **Operator UX simplified 2026-05-02:** every config (dev / prod /
  3 profiles) defaults to **Redis state**; the Makefile auto-starts
  the dev Redis on every `run-*` target. New `make obs-up` / `make urls`
  / `make logs` targets surface Prometheus + Grafana + Jaeger + audit
  paths in one command. First-light is `make setup && make run-dev`.

---

## Last Completed

**Task:** 2026-05-11 policy-qa + crate-audit triage + Phase-1..4
fixes. 72 raw findings across 3 reports → 9-PR sub-plan in
`plans/issue-fix/2026-05-11-policy-qa-and-audits/`; all 9 PRs
landed across commits `2f50176` (Phase 1 dashboard) → `e445f31`
(Phase 2 aegis-core) → `144c779` (regex/glob route guard) →
`8c9b35c` (LB correctness) → `2ad3a61` (TierCache removal) →
`cde14b7` + `30f7bf8` + `e705eff` (PR #7 response filtering full
stack) → `3b01ade` (PR #8 SEC-18/SEC-21/CTL-20) → `<this PR>`
(PR #9 docs + stub deprecation).

### What shipped

1. **Phase 1 — Policy QA dashboard fixes** (`2f50176`). 8 findings
   from `tests/n-tester/reports/policy-qa-findings.md` closed:
   Rules Simulator now renders API response (F-01), inline
   validation + aria-invalid on Rules/Access Lists empty-submit
   (F-02), Audit Log deep-link reads `?rule_id=…&ip=…&request_id=…`
   (F-03), styled `RemoveAccessListEntryModal` replaces native
   confirm (F-07), AI Disable confirms before flipping (F-06),
   dropped `+` icon on Cancel state (F-08).

2. **Phase 2 — aegis-core gap fixes** (`e445f31`). CORE-01: the
   `WafConfig.ddos` field doc now matches the enforce-by-default
   posture (`observe_only: false`). CORE-09 / CTL-08:
   `WafConfig::validate()` rejects `state.backend = raft |
   redis_cluster` and `state.reconcile.mode = latest | fail_safe`
   at config-load time instead of crashing at boot. CORE-06:
   `StateBackend::health()` default flipped to `connected: true`
   so the dashboard pill doesn't red-flag new backends.

3. **PR #4 — route resolver guard** (`144c779`). PROXY-02:
   `route.match_type = regex | glob` now rejected by
   `WafConfig::validate()` since `resolve_inner` only calls
   `trie.find_all_prefixes`. Same pattern as PR #8's SEC-21 lint.

4. **PR #5 — load-balancer correctness** (`8c9b35c`). PROXY-10:
   P2C swapped from deterministic counter to `subsec_nanos`
   entropy + n=2 short-circuit. PROXY-11: ConsistentHash replaced
   modulo with Rendezvous Hashing (`hash(key, member_addr)`,
   pick max). 3 new property tests verify (a) P2C spreads picks,
   (b) member change remaps ~1/n keys, (c) session affinity is
   deterministic across the same key.

5. **PR #6 — TierCache removal** (`2ad3a61`). Module had zero
   call sites in the request pipeline (PROXY-08/09 spot-check).
   `crates/aegis-proxy/src/cache/` deleted, `moka` workspace dep
   dropped, contract's `flush_cache` endpoint kept returning
   `supported: false` per §9 wording.

6. **PR #7 — Response filtering wire-up** (`cde14b7` + `30f7bf8`
   + `e705eff`). `Pipeline::on_body_frame` runs three independently
   toggleable rungs over every upstream response: stack-trace
   scrub (Node/JVM/Python/Rust/PHP/.NET/Ruby/Go), RFC 1918 IP
   mask, DLP redact (Luhn-validated credit cards + SSN + IBAN +
   email + AWS/GitHub/Stripe/Slack tokens). `ResponseFilterConfig`
   held in `ArcSwap` for hot-reload. Audit-mutated PUT
   `/api/response-filter` + Security Engine tile. Bonus: caught
   + fixed a boot-path bug where `run.rs` was passing a fresh
   `NoopPipeline` to `ProxyContext`, silently dropping the
   wire-up. Operator doc at `docs/security/response-filtering.md`.

7. **PR #8 — Phase 3d/e/f correctness pack** (`3b01ade`). SEC-21:
   `RuleAction::RateLimit` rejected at lint time (`eval.rs:107`
   returned `Action::RateLimited` on every match without
   consulting a counter). SEC-18: CIDR threat-intel indicators
   now stored in a separate `Vec<(IpNet, Indicator)>` with
   `check_ip` linear-scanning via `IpNet::contains` (previously
   keyed by string, so `10.0.0.0/8` never matched `10.5.5.5`).
   CTL-20: `handle_password_change` gains a mandatory
   `invalidate_sessions: I` closure called after `apply_new`
   succeeds. CTL-19 downgraded — `set_all(mode)` clearing
   overrides is contract-conformant per v2.3 line 186.

8. **PR #9 — Documentation + dead-stub deprecation** (this PR).
   New `plans/future/unwired-stubs-catalog.md` catalogs every
   "trait exists but zero callers in proxy/bin" stub: CAPTCHA
   providers (3 vendors), JWT validator, OPA client, ICAP scanner,
   Basic-Auth, Forward-Auth. Each stub gets a `//! deferred`
   module-level doc + `#![allow(dead_code)]` so static audits
   don't re-raise them. The catalogue spells out which sub-feature
   is needed for each one to ship and which ones the contract
   requires (none of them, today). `Implement-Progress.md`
   updated to reflect the post-sprint state.

### Verification

- `cargo test --workspace` → all green (~3 300 tests; +13 from
  PR #4-#9: 3 LB property tests, 1 SEC-21 lint test, 3 SEC-18
  CIDR tests, 1 CTL-20 password test, 5 response-filter writer
  tests).
- `cargo build --workspace` clean, no clippy warnings on the
  modified surfaces.
- Manual: dashboard Settings → Response Filtering renders the
  three live toggles + flips a rung via `PUT /api/response-filter`
  → audit-chain entry appears in Live Feed.

### Next-session hand-off

The full 2026-05-11 sprint is closed (now including PR-DNS-1 +
PR-DNS-2 — hostname-addressed upstreams shipped end-to-end with
background DNS refresh on TTL).

AI-T2..T9 still wait on the operator's `.onnx` file — that's the
only meaningful pre-existing open thread. The FDP accept-loop
drain refactor that was previously flagged here was already
shipped on 2026-05-03 PM (commit `6fc56c1` + `362c366`); SIGUSR2
→ `perform_handover` is wired end-to-end and production
hot-restart works via the polling task in `run.rs:1366`. Stale
note retired here on 2026-05-11.

---

## Previous "Last Completed" (preserved for context)

**Task:** 2026-05-03 multi-track sprint — TCP-T Phase 4 + FDP-T1..T6
binary handover primitives + SWEEP-T multi-tester sweep tooling +
MTLS-T10 Phase 2 + B5 benchmark gating + geoip XFF wiring + dashboard
3-state pill + AI-T design pass.

### What shipped

1. **TCP forwarder Phase 4 — CONNECT-method tunneling** (8 commits
   `e15d3fb` → `d903d7f`, ~2400 LOC, 41 new tests). `scheme: tcp`
   routes now open real TCP tunnels via `hyper::upgrade::on` +
   `tokio::io::copy_bidirectional`. Per-IP concurrent-tunnel cap +
   SSRF gate (loopback / link-local hardcoded-deny) + paired
   `tcp_tunnel_open` / `tcp_tunnel_close` audit events with byte
   counters. Operator docs at `docs/data-plane/reverse-proxy.md`
   § "TCP tunneling via CONNECT".

2. **Binary handover via fd-passing — library** (FDP-T1..T6, 6
   commits `6d98c5d` → `ad5540f`, ~1100 LOC, 26 new tests).
   `adopt_inherited_listeners` (RFC1918 default + systemd
   `LISTEN_FDS` compat + colon-separated names support) +
   `spawn_successor` with FD pre-placement + CLOEXEC clear +
   `bridge_tunnel` async splice + `InFlightCounter` RAII +
   `perform_handover` orchestration + `ReadinessPipe` single-byte
   signal + SIGUSR2 listener wired into boot path. **Library
   complete; one gap remains:** the accept-loop drain refactor
   that lets SIGUSR2 actually invoke `perform_handover`.

3. **Multi-tester AI-assistant sweep tooling** (commit `1356409`).
   `tests/sweeps/{README, CLAIMS.template.md, template/, consolidate.sh}`
   + `make sweep-validate` / `sweep-consolidate`. 8-slice claim
   catalogue + `findings.jsonl` schema + auto-dedup + ranking by
   severity × distinct-tester count. Plan at
   [`plans/ai-assistant-testing-kickoff.md`](./plans/ai-assistant-testing-kickoff.md).

4. **MTLS-T10 Phase 2 — live CA bundle hot-swap** (commit `95deaef`).
   `PUT /api/mtls/ca-bundle?apply=true` swaps `RootCertStore` via
   `ClientTrustStore::swap_pem`; new `WebPkiClientVerifier`
   instances see the new roots immediately, in-flight handshakes
   complete on the old store. `TrustAnchorWriter` trait at the
   aegis-control boundary so the audit-mutated handler doesn't
   pull aegis-proxy types.

5. **B5 benchmark mode two-factor gating** (commit `8ae951a`).
   Optional source-IP allowlist + HMAC-SHA256 token gating for
   the `x-aegis-*` headers; both fail-closed; AND-composed.
   Production-safe for `enabled: true` deployments without leaking
   timing or rule-id signal to the public.

6. **geoip XFF wiring + dashboard 3-state pill** (commits `a166e3f`,
   `c908fe8`, `f6c0a04`, `86bcc01`). Local `data/geoip/` with
   `make geoip-link` (mirrors `make ai-link` from the AI-T design),
   `geoip` joins default `FEATURES`, the data-plane handler
   resolves XFF before recording `client_ip`, dashboard pill
   distinguishes "DB not loaded" / "DB loaded but no resolvable
   IPs" / "N geo-tagged".

7. **AI-T design pass shipped** (commits `4beb4a3`, `70b8985`).
   `plans/ai-detector.md` covers the full integration of the
   trained ONNX model with all 4 user-locked decisions (operator-
   supplied .onnx, default-off Cargo feature, 0.85 threshold,
   hybrid `mode: observe | enforce`). 9-slice AI-T1..T9 breakdown.
   Awaiting the operator's .onnx file before AI-T1 starts.

### Verification

- `cargo test --workspace` → all green (~2 823 tests across 17
  binaries; +320 from the 2026-05-03 work over the 2 500 baseline).
- `cargo build` (default features) byte-stable across the sprint;
  no unconditional dep growth.
- TCP track: `tests/api/connect-tunnel.sh` deny-path smoke,
  `bridge_tunnel_round_trips_bytes_through_an_echo_upstream`
  full-flow integration, 9-test dispatch matrix.
- FDP track: `adopt_real_listener_round_trips_an_accept` proves
  `from_raw_fd` round-trips a working socket; the load-bearing
  `spawn_successor_places_fd_at_slot_3` proves `dup2 + CLOEXEC`
  clear actually plumbs an FD into a forked-and-exec'd child.
- geoip: end-to-end verified in 3-attack postman scenario;
  `geoip_loaded: true` in `/api/attacks/top` response;
  `8.8.8.8 → US`, `202.12.27.33 → JP` country resolutions confirmed.

### Next-session hand-off

The user is building the .onnx model for AI-T. AI-T1 (Cargo feature
+ tract dep + AiConfig in aegis-core; ~2h) is the next sliceable
unit when the model artifact arrives. The AI-T design has zero
open questions.

The accept-loop drain refactor for FDP is also a viable pickup —
it's the one gap between "FDP library shipped" and "production
hot-restart works end-to-end via SIGUSR2".

---

## Recent History

| Date | Task | Outcome |
|---|---|---|
| 2026-05-11 | Policy QA + crate audit triage (9 PRs) | 72 raw findings → 9 PRs landed: Phase 1 dashboard fixes, Phase 2 aegis-core gaps, PROXY-02 regex/glob guard, PR #5 LB correctness (P2C entropy + Rendezvous Hashing), PR #6 TierCache removal, PR #7 response-filter wire-up + dashboard surface, PR #8 SEC-18/SEC-21/CTL-20 correctness pack, PR #9 docs + stub deprecation. ~3 300 workspace tests, +13 new. |
| 2026-05-09..10 | DDoS enforce-by-default + Strike-Block opt-in + AI hot-enable + Detectors & Tiers UX overhaul + per-tier cumulative threshold retirement | 7c9e5dc landed DDoS enforce. Strike-Block ships defaulted OFF (operator opt-in). AI enable/disable lives in the Detectors page without a restart. Detectors & Tiers got a per-tier override card + lifted Risk score reference. R3 retired the per-tier cumulative threshold inputs (cumulative gate is global / per-IP, not per-tier). |
| 2026-05-03 PM (late) | Skill run + finding closeout + UI/docs | All 4 skill findings closed (geoip country fall-back, detector_name refactor, by-detector unknown filter, bot-mix honest empty), PageErrorBoundary closes white-page bug, Members table gains Host-header column, Protocol matrix card, upstream-cookbook.md with 8 per-protocol recipes, README features-first rewrite, body-abuse doc covers XXE + mass-assignment. ~700 LOC + 4 new tests; bundle 300 KB. 4 commits. |
| 2026-05-03 PM | Open-tracks closeout + UX pass | Access-list runtime, AI-T1 stub, FDP drain refactor, WS bridge (T2/T3/T4/T5/T6), login page fix, multi-vhost upstream (`host_header` + SNI pinning), Investigation default-list + Attack-Analytics merge, Top Attackers page, aegis-waf-tester Skill. ~2 700 LOC + ~40 new tests; bundle 296 KB. 13 commits. |
| 2026-05-03 AM | TCP-T + FDP-T + SWEEP-T + AI-T design + geoip XFF | ~3500 LOC + 320 new tests. CONNECT tunneling live; binary-handover library; multi-tester sweep tooling. |
| 2026-05-02 (PM) | Operator UX simplification + Redis-default + obs stack + AI-testing scaffold | `make setup && make run-dev` boots a Redis-backed dev profile in 2 commands. AI-Assistant testing rules + guide live under `tests/`. |
| 2026-05-02 (mid) | prod-balanced @ 5 k+ RPS sustained (3 iterative runs) | v3 = 4 891 RPS k6 / 6 392 RPS WAF-internal, legit p99 1.03 ms, legit OK 100 %, 80 % detection. Surfaced 7 improvements; identified Python upstream as the prior 600-RPS ceiling. |
| 2026-05-02 (early) | Profile picker + Makefile profile-aware run targets | 3 profiles (balanced/strict/high-throughput) + `docs/operator/profiles.md` decision tree + `run-strict`/`run-throughput`/`validate-all` make targets. |
| 2026-05-02 | Detector-coverage sprint + rollback v2..v5 + SC-T4 | Detection 33 % → 80 % via BodyPeek fix + mass-assignment + XXE + brute-force + SSRF body. Rollback covers 11 of 18 audit-mutated actions. SC-T4 tokio runtime gauges live (gated on `--cfg tokio_unstable`). |
| 2026-05-01 | HACK-T1..T5 stress-test prep + MTLS-T1..T7 | 15-min mixed-traffic harness scaffolded; mTLS rustls inbound + identity extraction + route gate + hot-reload + console observability + SAN allowlist all shipped. |

For full chronological detail see `git log` and `docs/progress/completed-tasks-log.md`.

---

## Next Task

### TCP forwarder Phase 4 — ✅ shipped 2026-05-03

CONNECT-method TCP tunneling is live and tested. Track closed
across 7 commits totalling ~1900 LOC + 41 new tests. Design at
[`plans/tcp-forwarder-phase-4.md`](./plans/tcp-forwarder-phase-4.md);
operator docs at [`docs/data-plane/reverse-proxy.md`](./docs/data-plane/reverse-proxy.md)
§ "TCP tunneling via CONNECT".

**Slice landing log:**

| Slice | Commit | Scope |
|---|---|---|
| TCP-T1 | `f1b52b1` | Destination policy + RouteConfig allowlist + SSRF gate |
| TCP-T2 | `e39ea51` | Per-IP concurrent-tunnel counter with RAII guard |
| TCP-T3a | `e02cb27` | `connect_admit` pure admission gate |
| TCP-T3b | `7c62f3e` | `bridge_tunnel` async splice + close-reason |
| TCP-T3c | `159cebd` | Data-plane wiring + audit pair + 6 deny rule_ids |
| TCP-T5+T6 | `15b378c` | 9 dispatch-matrix tests + retire 502 stub |

TCP-T4 (richer audit field shape) was rolled into T3c — the
`tcp_tunnel_open` / `tcp_tunnel_close` events ship the full
design-doc payload (route_id, destination, duration_ms,
bytes counters, close_reason).

**What's left as polish (not blocking):**

- `tests/api/connect-tunnel.sh` end-to-end smoke — optional;
  in-process integration tests already cover the dispatch
  matrix and the bridge byte-flow.
- HTTP/2 extended CONNECT (RFC 8441) — rare in the wild;
  current build returns 405 `connect_no_upgrade_support` for
  h2 clients. Pick up if/when an operator asks.

### AI-Assistant testing track — kicked off

Sweep tooling shipped at `1356409`:
- `plans/ai-assistant-testing-kickoff.md` — design (8 slices,
  schema, anti-patterns, SWEEP-T1..T5).
- `tests/sweeps/{README.md, CLAIMS.template.md, template/, consolidate.sh}`
  — runnable scaffolding.
- `make sweep-validate TESTER=...` and
  `make sweep-consolidate SWEEP=...` — ops one-liners.

Existing intake (still current):
- `tests/AI-ASSISTANT-GUIDE.md` — workflow + review checklist.
- `tests/AI-ASSISTANT-RULES.md` — terse do/don't sheet.

**Open for user when picking up:** schedule sweep #1 (4-6
testers across 4-6 slices, ~2h), name the theme, branch from
develop.

### AI-T — ML detector integration (shipped 2026-05-03)

Full implementation now live — `plans/ai-detector.md` + per-detector
doc `docs/security/detectors/ai-detector.md`.

**Slices delivered** (all 9 closed in one session):

- **T1** — `ai` Cargo feature, `WafConfig.ai: AiConfig` schema, default OFF.
- **T2** — `features.rs`: 26-feature extractor (method ID, URL/path
  shape, suspicious-keyword counts raw + URL-decoded, Shannon
  entropy, %XX counts) — byte-for-byte match with the trainer's
  feature pipeline. 16 unit tests.
- **T3** — `model.rs`: `Mutex<ort::Session>` wrapper, 1×26 `f32`
  tensor → `i64` class label out. `ort = "=2.0.0-rc.12"` with
  `download-binaries` + `ndarray`.
- **T4** — `AiDetector` impl of the `Detector` trait; binary
  attack-vs-normal verdict (`class != normal_class_idx`), single
  `Signal { tag: "ai", score: 60 }`. Body capped at 4 KiB before
  feature extraction.
- **T5** — boot wiring in `aegis-proxy/src/run.rs`: load model
  + register metrics + push into the detector chain when
  `cfg.ai.enabled = true` and the `ai` feature is on.
- **T6** — `aegis_ai_predictions_total{verdict}`,
  `aegis_ai_inference_duration_seconds{verdict}`,
  `aegis_ai_fallback_total{reason}` Prometheus series via
  `AiMetricsSink` trait (avoids cyclic dep: trait in
  aegis-security, impl in aegis-control).
- **T7** — Makefile targets `ai-link`, `ai-status`, `ai-unlink`
  with self-link guard; `data/ai_model/.gitignore` keeps the
  model artefact out of git.
- **T8** — `crates/aegis-security/tests/ai_e2e.rs` integration
  test, gated on `AEGIS_AI_MODEL`. Asserts ≥ 8/10 attacks caught
  + ≤ 25 % FP rate on a fixed corpus.
- **T9** — Dashboard "AI Detector" card on the Detector tier-config
  page, reads `/metrics` directly, renders inferences / hit rate
  / mean latency live. Bundle now 305 058 bytes.

**Perf measured** (`tests/results/run-ai-compare-2026-05-03/REPORT.md`):
side-by-side comparison harness, 4 cases × 8 000 requests at
400 RPS (60 % attack mix), with **p99** captured against a
**5 ms target**:

| Case | Detect % | FP % | Attack p95 / **p99** | Mean inference | RSS |
|---|---|---|---|---|---|
| ALL on (regex+AI) | **93.8** | 40.0 | 2.48 / **4.53** | **694 µs** | 562 MB |
| AI ONLY | 85.7 | 40.1 | 2.39 / **5.58** ❌ | 783 µs | 507 MB |
| REGEX ONLY | 93.5 | 10.4 | 1.36 / **2.26** ✅ | — | 65 MB |
| NONE (baseline) | 0.0 | 0.0 | 1.42 / **2.44** ✅ | — | 51 MB |

**p99 vs 5 ms target**: regex-only ✅, no-detector ✅, regex+AI
⚠ (clean p99 5.71 ms — over by 0.71 ms on laptop), AI-only ❌
(5.58 ms attack p99). Production-class hardware is expected to
close the gap (the existing 5 k RPS run measured p99 1.03 ms
with the regex chain).

AI lifts detection +0.3 pp over regex-only on this corpus, costs
~+1.1 ms p95 / +2.3 ms p99 / +500 MB RSS chained. Bundled model
favours recall: at threshold 0.5 it fires on ~68 % of all
traffic — `ai.mode: observe` is the right starting position;
threshold-tightening recipe documented in the per-detector page.

**Re-run perf**: `bash tests/perf/ai-compare.sh` (env knobs
`RPS=`, `DURATION=`, `ONLY="A B"`). Output lands at
`tests/results/run-ai-compare-<UTC-date>/REPORT.md`.

### Other queued / parked

- **CC-T3** — i18n + help.jsx slides remain (the test-side slice
  shipped at `180f6dd`). Both items have outsized scope (i18n
  needs JSX runtime loader work; help slides need designer
  input) so they're polish for a future Console-redesign cycle.
- **B6-T5 (fd-pass)** — ✅ FDP-T1..T6 shipped. Library
  primitives all proven correct (26 new tests). Boot path now
  adopts inherited listener FDs from an exec'ing parent
  (FDP-T2), spawns a successor with FD pre-placement +
  CLOEXEC clear (FDP-T3), supports the drain protocol with
  in-flight counter + grace timer (FDP-T4), uses a pipe-based
  readiness signal (FDP-T5), and accepts systemd
  `LISTEN_FDS` / `LISTEN_FDNAMES` env aliases plus a SIGUSR2
  listener wired into the live boot path (FDP-T6).

  **One gap remains:** the accept-loop drain refactor.
  Today's wiring records the SIGUSR2 in `HotReloader` but
  doesn't invoke `perform_handover` because the accept loops
  don't yet take a shutdown channel + the shared
  `InFlightCounter`. Operators get clean adopt-or-bind on
  first boot today; full hot-restart lands when the
  accept-loop refactor track closes.
- **B6-T4** (HSM) — still explicitly deferred; PKCS#11 against a
  real HSM, no design pass yet.
- **SC-T4** runtime metrics polish — already wired at boot in
  `run.rs:341-344`; gauges register, sampler ticks; behaviour
  cfg-gated by `--cfg tokio_unstable`. No further work pending
  unless an operator asks for documentation.
- **Rollback v6+** — rule CRUD, risk_reset, alert receivers,
  upstream pools (each requires audit-shape changes that
  pre-date the rollback dispatcher).

---

## Tracks in flight

Order is execution priority — earlier rows run first.

| # | Track | Plan | State |
|---|---|---|---|
| 1 | **Phase B — production-packaging (B6)** | [`plans/phase-b/README.md`](./plans/phase-b/README.md) | **active**; B1..B5 closed; B6-T1 in flight |
| 2 | **Console config pages (CC-T*)** — upstreams editor + alert-channel mgmt | [`plans/console-config-pages.md`](./plans/console-config-pages.md) | **plan-only — awaiting confirmation**. CC-T1 (upstreams CRUD) → CC-T2 (alert receivers in Tracking page) → CC-T3 (i18n / OpenAPI / docs) |
| 3 | Scaling configuration (SC-T*) — three-layer worker/cluster/state surface | [`plans/scaling-config.md`](./plans/scaling-config.md) | **parked plan — awaiting confirmation**. Surfaces existing L1/L2/L3 model in Console; adds `/api/state` health endpoint |
| — | Dashboard redesign (DD-T0..T8) | [`plans/dashboard-redesign.md`](./plans/dashboard-redesign.md) | closed in run-10 |
| — | Console API integration (CI-T1..T8) | [`plans/console-api-integration.md`](./plans/console-api-integration.md) | closed |
| — | HA cluster (HA-T1..T5) | [`plans/cluster-ingress-lb.md`](./plans/cluster-ingress-lb.md) | closed in run-05 |
| — | Interop contract (IT-T1..T6) | [`plans/interop-contract.md`](./plans/interop-contract.md) | closed |
| — | Interop dry-run (DR-T1..T7) | [`plans/interop-dry-run.md`](./plans/interop-dry-run.md) | closed in run-08 |
| — | Post-run-08 (AF-T1, HP-T1, TLS-T1) | [`plans/post-run-08.md`](./plans/post-run-08.md) | closed |
| — | Benchmark mode (B-T1..B-T6) | [`plans/benchmark-mode.md`](./plans/benchmark-mode.md) | folded into Phase B as B5-T2 |
| — | Security toggles (P1..P8) + post-k6 (F-T1..F-T10) | [`plans/post-k6-followup.md`](./plans/post-k6-followup.md) | closed |
| — | Enterprise dashboard (D-M1..D-M6) | [`plans/archive/dashboard-enterprise/`](./plans/archive/dashboard-enterprise/) | closed — superseded by DD-T0..T8 |
| — | Phase B intake | [`docs/future/advanced-features.md`](./docs/future/advanced-features.md) | open — for items NOT covered by `plans/phase-b/` |

---

## Carry-overs / known limitations

Durable list of things that work but aren't fully shipped. Each row
is grouped under the Phase B milestone that closes it, so when a
milestone ships you can see exactly which lines to delete. See
[`plans/phase-b/README.md`](./plans/phase-b/README.md) for the task
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
([`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md))*
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
([`tests/results/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md`](./tests/results/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md))*
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
  [`plans/cluster-ingress-lb.md`](./plans/cluster-ingress-lb.md)
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
   [`plans/phase-b/README.md`](./plans/phase-b/README.md).
   Six milestones (B1..B6) that close every Partial /
   Designed-only banner currently in `docs/`. Each milestone close
   removes the matching block of carry-overs above and flips the
   matching `> **Status:**` banners.
2. **Dashboard redesign (closed).**
   [`plans/dashboard-redesign.md`](./plans/dashboard-redesign.md).
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
