# FEAT — Attack-coverage wiring: close the red-team gaps that already have (tested) code

> **Type:** FEAT (security-coverage track) · **Status:** ⬜ Not started · **Branch:** `feat/attack-coverage-*` (per stage)
> **Track ID prefix:** `AC-P1<–3>`
> **Derived from:** [`ASSESSMENT-attack-scenario-coverage-2026-07-02.md`](./ASSESSMENT-attack-scenario-coverage-2026-07-02.md) (8-vector red-team matrix, re-verified 2026-07-03). That file is the *why*; this file is the *what ships*.
> **Honors:** [[project_attack_vector_coverage_assessment]] · [[project_apply_and_swap_helper_guard]] (any new config-plane toggle must be wired into every `apply_cfg_change_to_*` site + guard test) · [[project_ddos_fleet_rps]] (the fleet-bucket pattern P2-b copies) · [[project_ltester_decodes_dataplane_raw]] (validate detector fixes with Rust unit tests on RAW forms, not the Python report) · [[feedback_test_suite_green_baseline]] (detector FP-reduction commits routinely make older tests stale — confirm intent before "fixing")

**Goal (one line):** ship the cheapest, highest-certainty coverage wins from the assessment — items whose logic already exists and is tested and just needs wiring or a small table extension — without regressing the 20-point Performance criterion.

---

## Performance budget (applies to every stage — non-negotiable)

The WAF is judged on p99 ≤ 5 ms and ≥ 5,000 req/s. Every item below runs on the request (or response) hot path, so each stage carries an explicit cost ceiling and a before/after benchmark gate (`deploy/STAGING-BENCHMARK.md`).

- **Default-OFF detectors cost zero when disabled** — the detector mask is derived once on config load (`detectors/mod.rs`), so a disabled detector is never constructed into the chain. New toggles inherit this for free; confirm with a "mask excludes X when off" test.
- **No new unbounded state.** Any per-key map is `DashMap` with a `MAX_TRACKED_KEYS` cardinality cap (mirror `risk/tracker.rs:71`, `ip_limiter.rs:59`) and a TTL/eviction path — never a map that grows with attacker-chosen keys.
- **No new per-request regex passes** without batching. If a stage adds patterns, they go through a `RegexSet` single pass (see the l-tester perf plan `PLAN-ltester-perf-and-hardening-2026-07-03.md` O-2), not another `Vec<Regex>` loop.
- **Fleet work is async + fail-safe.** Redis increments are fire-and-forget; a backend error falls back to the per-node count and never blocks the request (mirror `ddos.rs::tick_rps_fleet_at`).
- **Response-path work is O(fixed).** Header stripping touches a known small header set, not a body scan.

Each PR description must paste the before/after p99 + throughput delta. A stage that regresses p99 by >5% at target RPS does not merge without sign-off.

---

## AC-P1 — cheap wins: wire/extend already-tested logic (START HERE)

Four independent, small PRs. Each closes a concrete external-red-team finding. Lowest risk on the board.

### AC-P1-a · Wire response header stripping for proxied traffic · **S** · *(vector 08 — version-banner leak)*
`should_strip_header` + `inject_security_headers` are written and tested but have **only test callers** (`response_filter.rs:38, 68`); proxied upstream responses leak `Server` / `X-Powered-By` / `X-AspNet-Version` / `X-Debug*` / `X-Internal*`. The body scrub *is* already wired at the same pipeline stage (`pipeline.rs:214-259` ← `data_plane.rs:3044`), so this is: call `inject_security_headers` (or a strip-only variant) from the proxied-response path alongside the body scrub.
- **Perf:** O(number of response headers), no allocation on the common path (only removes matched keys). Negligible.
- **Config:** default-ON strip of the leak set; CSP/HSTS injection stays opt-in (don't force security headers onto arbitrary upstreams — could break apps). Wire the toggle through every `apply_cfg_change_to_*` site + guard test.
- **Tests:** proxied response with `Server: nginx/1.2` → header absent downstream; body scrub still fires (no regression); toggle-off leaves headers intact.

### AC-P1-b · Extend the transaction shape table + add a `LimitChange` tag · **S** · *(vector 06 — missing fraud shapes)*
`VelocitySequenceDetector` rule table (`velocity_sequence.rs:112-137`) covers login/otp → deposit/withdrawal but **not** `deposit→withdrawal` or `limit-change→withdrawal`; there is no `LimitChange` `EndpointTag` at all (`velocity_sequence.rs:62-102`), so limit-change paths classify `None` and aren't even stored.
- Add `EndpointTag::LimitChange` + `classify` patterns (settings/limits/profile-limit routes).
- Add rules: `deposit→withdrawal <Ns` and `limit_change→withdrawal <Ns` with scores tuned like the existing table (withdrawal target → block-class 70).
- **Perf:** pure data extension; the ring buffer (`MAX_HISTORY=8`) and per-IP `DashMap` are unchanged. Zero added cost per request beyond one more `classify` match arm.
- **Known limitation (document, don't fix here):** still IP-keyed → rotation evades / NAT false-positives (test `different_ips_do_not_chain` pins this). Account-keying is AC-P3-c territory.
- **Tests:** `deposit→withdrawal` within window blocks; outside window doesn't; limit-change classified (not `None`); existing login/otp rules unchanged.

### AC-P1-c · Canonicalize usernames in the brute-force per-user axis · **S** · *(vector 02 — spray evasion)*
`extract_username` returns the raw wire string and the per-user axis keys on it verbatim (`brute_force.rs:268-271`), so `Alice` / `alice` / `alice ` count as distinct and defeat the cross-IP per-user aggregation. Lowercase + trim before keying.
- **Perf:** one `to_ascii_lowercase()` + `trim()` per auth request (already parsing the username). Negligible; consider `Cow` to avoid allocation when already canonical.
- **Watch:** canonicalize the **key** only; keep the original for the audit/display field so ops still see what was sent.
- **Tests:** `Alice`/`alice`/` alice ` from 6 IPs trip the >5-distinct-IP threshold as one user; audit event still shows the raw submitted username.

### AC-P1-d · XSS body decoding parity with SQLi · **M** · *(vector 07 — JSON-body XSS evasion)*
The XSS body path decodes only `url_decode` + `html_entity_decode`, single pass, and deliberately drops `\uXXXX` (`xss.rs:120-121`), so `{"x":"<script>"}` and double-URL-encoded payloads slip. Bring it to parity with SQLi's repeated-decode normalization.
- Reuse `normalize_for_detection` / the SQLi decode approach; add unicode-escape handling and/or JSON-value extraction for the body path.
- **Perf — the real risk in this batch.** Repeated decoding on every body is CPU. Bound it: cap decode iterations (SQLi already does), keep the opaque-beacon skip, and only apply the heavier normalization to bodies that look like JSON/text (not opaque blobs). Benchmark large-body throughput before/after — this is the one AC-P1 item that can move p99.
- **FP guard:** per [[feedback_test_suite_green_baseline]], measure against the benchmark FP corpus — unicode normalization can newly-flag legitimate accented content. Validate on RAW data-plane forms per [[project_ltester_decodes_dataplane_raw]], not the l-tester Python report.
- **Tests:** `<script>` in JSON body blocks; double-URL-encoded `%253Cscript` blocks; accented legit display-name still allowed (the existing `json_accented_display_name` test must be re-evaluated, not blindly deleted).

---

## AC-P2 — meaningful coverage, moderate work

### AC-P2-a · Wire `BehavioralAnalyzer` behind a default-OFF toggle · **M** · *(vectors 2, 5)*
The real behavioral engine (`behavior.rs`: CV-jitter timing, error-ratio, rate, no-cookie) is fully implemented + tested but **never called**; non-wiring is self-documented at `run.rs:2596-2602, 2697-2706`. Call `.observe()` from the data plane and feed jitter/rate signals into risk.
- **Default-OFF** (like `behavior_signals`) — zero cost until an operator opts in. The timing signal (`behavior_burst`) was previously *removed* for tripping on benchmarks, so re-tune thresholds and gate behind the toggle.
- **Perf:** the observe path is per-{key} timestamp bookkeeping — must be bounded `DashMap` + cardinality cap, O(1) amortized. Error-ratio needs the response-signal channel (AC-P3-b) to be fully useful; ship the timing/rate half first.
- **Tests:** machine-perfect cadence (near-zero CV) scores when enabled; disabled → not in mask, zero overhead; benchmark traffic doesn't trip it at default thresholds.

### AC-P2-b · Fleet-aggregate the brute-force axes — **cluster mode only** · **M** · *(vector 2, theme 2)*
Per-user / per-device distinct-IP counts are per-node `Mutex<HashMap>` (`brute_force.rs:52-58`) → a campaign load-balanced across nodes dilutes below threshold. Mirror the DDoS fleet-bucket pattern (`ddos.rs:448-495`).
- **Gating (owner constraint — "only in cluster mode"):** add `brute_force.count_scope: per_node | fleet` (default `per_node`) mirroring `SpikeScope` (`config.rs:5095`), **and** require a shared Redis `StateBackend` (`cluster_enabled()`, `control.rs:493`). Do **not** repeat the DDoS `spike_scope` gap where `fleet` on an in-memory backend silently means "fleet == this node" — if scope is `fleet` but no shared backend, log once and run per-node.
- **Plumbing:** thread a `StateBackend` handle into `BruteForceDetector` (it holds no backend today — this is the bulk of the work, not the flag).
- **Perf:** fire-and-forget `incrby` on a windowed key + read prior bucket; **fail-safe to per-node on any backend error** (mirror `tick_rps_fleet_at:476-479`). Never a blocking Redis call on the request path.
- **Tests:** two nodes sharing Redis, 3 IPs each → fleet count trips at 6 while neither node's local count would; backend error → falls back to local count, no request stalls; `per_node` default → byte-identical to today (no backend touch).

### AC-P2-c · Fix rules-engine `Asn`/`Country` eval + wire ASN blacklist · **M** · *(vector 3, theme 3; needs GeoIP)*
Even with GeoIP provisioned (on in production builds), geo rules are dead: `Condition::Asn/Country` always false because every call site uses the empty-context `evaluate()` shim (`eval.rs:118-120`) — both data-plane sites (`data_plane.rs:1090, 2071`) **and** the simulator (`simulator.rs:339`) — and `kind: asn` blacklist is hard-coded `false` (`blacklist.rs:505`).
- Populate `EvalContext.geoip` from the already-threaded `OnceLock` MMDB reader at all three sites; flip `kind: asn` to a real lookup.
- **Perf:** reuse the country access-list's lazy-cached lookup — at most one MMDB lookup per request, and only when a geo condition/entry is actually present (not unconditional). No new per-request cost for requests that hit no geo rule.
- **Prereq:** GeoIP feature compiled + MMDB configured (document the gate; it's on in `production` builds).
- **Tests:** a `Condition::Asn`/`Country` rule fires with a stub geoip reader in the data plane **and** in the simulator (`/api/rules/validate` must agree with the data plane); `kind: asn` blacklist entry blocks; no-geoip build/config → conditions still safely false, no panic.

### AC-P2-d · Endpoint-enumeration / 404-rate detector · **M** · *(vector 8)*
Recon is pure per-path signature (`recon.rs`); a scanner hitting many non-signatured paths, or a slow/distributed scan under the accumulation floor, isn't flagged. Add a per-IP (and, in cluster mode, fleet) rolling counter of distinct-path responses / non-signatured probes, scoring above the accumulation floor.
- **Perf — highest-risk item for footprint.** "Distinct paths per IP" is a cardinality trap. Use a bounded structure (capped `DashMap` per IP with a small ring of recent path hashes, or an approximate distinct counter) — never an unbounded per-IP `HashSet<String>`. Cap tracked IPs. This detector must survive a unique-path flood without OOM.
- **Response-status dependency:** true 404-rate needs response status (AC-P3-b). Until then, key off *distinct non-signatured request paths* per IP as a proxy signal.
- **Default-OFF** until tuned against benchmark FP.
- **Tests:** enumeration across 50 distinct paths from one IP scores; bounded memory under a 10k-unique-path flood (assert cap holds); legit multi-page browsing stays under threshold.

### AC-P2-e · Referer origin validation (opt-in, CRITICAL routes) · **S/M** · *(vector 5)*
`behavior_missing_referer` is presence-only (`behavior_signals.rs:159-171`) — any non-empty value passes. Upgrade to same-origin/allowlist checking for CRITICAL-tier routes, opt-in.
- **Perf:** string compare of Referer host vs configured origin/allowlist — trivial. No new state.
- **FP guard:** legitimate cross-origin flows must be allowlistable; default-OFF; only CRITICAL routes.
- **Tests:** cross-origin Referer to a CRITICAL route scores when enabled; same-origin passes; allowlisted origin passes.

---

## AC-P3 — larger / architectural (scope carefully; some may spin out to their own issues)

- **AC-P3-a · Real JA4 from the ClientHello.** Read cipher/extension lists in the TLS layer (`listener/tls.rs:34-67`) and call the existing `ja4.rs::compute` so fingerprints are version-precise (today it's a "JA4-light" stub; `ja3/ja4/h2` modules are library-only). Prereq for a real TLS-fp↔UA consistency check and the known-bad-JA4 blocklist (`bots.rs:124`). **Perf:** fingerprint computed once per connection, not per request — acceptable, but measure handshake overhead. *Candidate to spin out — non-trivial TLS-layer surgery.*
- **AC-P3-b · Response-outcome signal channel.** Give detectors access to upstream status so login **failures** (401/403) drive scoring, not just attempts (theme 4 — the owner's noted "OK for now, maybe later"). Unlocks credible ATO/stuffing detection and is a prereq for AC-P2-a's error-ratio half, AC-P2-d's true 404-rate, and AC-P3-e. **Structural** — `RequestView` has no response field today. *Spin out to its own issue; several items depend on it.*
- **AC-P3-c · One-device-many-accounts detector.** device_fp→distinct-account counter (peer of `DeviceIpTracker`). Needs an account/username signal on the relevant routes. Bounded/capped like DeviceIpTracker.
- **AC-P3-d · Decide L4 posture explicitly (doc, not code).** State that TCP/UDP volumetric floods are handled upstream (kernel/LB/anycast); confirm the app-layer `conn_limit` + accept-loop backpressure story suffices for "DDoS aimed at the WAF." Runbook + stated boundary. *Pairs with the l-tester perf plan's DDoS default-limit item.* ✅ **DONE 2026-07-04** — `docs/security/ddos-protection.md` gained an "L3/L4 volumetric floods — out of scope (handled upstream)" section (network/LB tier absorbs packet volume; WAF absorbs request/connection volume via `conn_limit` reject-before-admit + Gradient2 shedder) + an "is this L4 or L7?" runbook.
- **AC-P3-e · Per-account lockout primitive.** ~~Hard lockout (not just additive score) after repeated failures on one account — **requires AC-P3-b** (failure signal) first.~~ **DECLINED 2026-07-04 (evaluated, backed out before merge).** Hard/virtual account lockout is an **anti-pattern for an L7 WAF**: (1) it's **DoS-weaponizable** — a stuffer sprays a victim's username with wrong passwords and *the WAF locks the real user out* (the failure mode is inherent, not fixable by a default-OFF flag); (2) the WAF is **not the source of truth** for accounts — lockout belongs to the app / IAM / IdP; (3) it adds hot-path cost (per-auth-request username parse + lock check) for **redundant** value. The major WAFs (Cloudflare, F5 AWAF, Imperva, Akamai Account Protector) don't hard-lock accounts — they *detect + score + challenge/step-up/rate-limit* and let the app decide. **That posture is already shipped here:** AC-P3-b (merged) feeds upstream 401/403 into the BehavioralAnalyzer → `behavior_high_errors` raises the risk score; the 3-axis brute-force detector catches per-user-across-IP stuffing; risk crossing `challenge_at` → PoW challenge, `block_at` → cumulative block. A bounded `AccountLockout` primitive + data-plane gate were built and unit-tested, then **discarded** (branch dropped, never pushed). Same evaluate-then-reject discipline as LT-P2 (RegexSet) / LT-P1b (panic=abort). *If future ATO work wants more, it should feed a risk **signal** to the app, not maintain hard account state in the WAF.*

---

## Out of scope (state the boundary, don't build)

- Deep transaction-fraud enforcement (balances, HMAC, authZ) stays in the router/gateway (`scores.rs:452-455`); the WAF owns **shape** detection only (AC-P1-b). Consistent with [[project_waf_vs_gateway_boundary]].
- L4 TCP/UDP flood absorption is a network/LB concern (AC-P3-d documents, doesn't implement).
- Full session navigation-depth modeling needs session state the WAF doesn't hold — gateway/app responsibility.

## Suggested sequencing

1. **AC-P1-a, -b, -c** first (three tiny, high-certainty PRs — banner leak, fraud shapes, spray evasion). Land the l-tester perf plan's `[profile.release]` + `RegexSet` around the same time so the coverage additions land on an already-faster baseline.
2. **AC-P1-d** (JSON-body XSS) with a dedicated benchmark pass — the one P1 item that can move p99.
3. **AC-P2** as capacity allows; **AC-P2-c** only once someone confirms the judged config has GeoIP + MMDB.
4. **AC-P3-b** is the unlock for the outcome-blind theme — schedule it before the error-ratio half of AC-P2-a. The owner has flagged outcome-blindness as "OK for now," so AC-P3-b was explicitly deferrable. (AC-P3-e, which would have consumed it, is now **declined** — see above.)

## Definition of done / archival

- Each shipped stage: PR link + before/after benchmark delta recorded here.
- Items deliberately **not** taken (e.g. AC-P3-d/-e if deferred) get an explicit "deferred — see follow-up issue #NNN" line, so nothing is silently dropped.
- When the committed set has merged, move this file to `plans/issues/archived/` and add the "shipped" banner to the parent ASSESSMENT per its *Archival note*.
