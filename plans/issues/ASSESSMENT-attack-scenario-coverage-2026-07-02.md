# Attack-scenario coverage assessment — 8-vector red-team matrix

**Status:** 🔵 Assessment / gap analysis (no code changed). Source-verified against `develop`-era tree, 2026-07-02. **Re-verified 2026-07-03** (4 parallel passes); corrections folded in — see *Corrections* below.
**Author:** security review (4 parallel code-exploration passes, one per vector pair).
**Input:** external red-team "Kịch bản tấn công (mở rộng)" — 8 attack vectors (DDoS L4/7, bot login & credential stuffing, relay/proxy, device-fingerprint evasion, behavioral bypass, transaction fraud, OWASP injection, canary/recon).
**Method:** every claim below is traced to a `file:line`. Repo docs are known to overstate implementation in both directions, so nothing here is taken from `docs/` — only from code and its call sites.
**Derived work:** the improvement backlog has been split into two shippable plans — [`FEAT-attack-coverage-wiring-2026-07-03.md`](./archived/FEAT-attack-coverage-wiring-2026-07-03.md) (security coverage) and [`PLAN-ltester-perf-and-hardening-2026-07-03.md`](./PLAN-ltester-perf-and-hardening-2026-07-03.md) (performance + hardening, from the l-tester audit). This file stays as the umbrella analysis. See *Archival note* at the bottom.

> ✅ **FEAT-attack-coverage-wiring SHIPPED & ARCHIVED 2026-07-04** → [`archived/FEAT-attack-coverage-wiring-2026-07-03.md`](./archived/FEAT-attack-coverage-wiring-2026-07-03.md). Merge PRs: #127 #128 #129 #130 (AC-P1-a/b/c/d) · #136 (AC-P2-e) · #138 (AC-P2-c) · #139 (AC-P2-a) · #140 (AC-P3-b) · #141 + #147 (AC-P2-d base + true 404-rate) · #142 (AC-P3-d doc) · #148 (AC-P2-b fleet brute-force). Not taken, explicitly: AC-P3-a real JA4 (blocked on rustls ClientHello API — needs a raw-parse spike), AC-P3-c one-device-many-accounts (owner declined per-request account parsing), AC-P3-e account lockout (declined — L7-WAF anti-pattern; see the archived FEAT's ledger). This ASSESSMENT stays live until the l-tester perf plan also archives.

---

## Corrections & re-verification (2026-07-03)

Re-ran all `file:line` claims against the current tree. **Every claim held except one factual error**, plus two framings that needed a nuance. Everything else in this document is confirmed accurate.

1. **[FIXED BELOW] DDoS auto-block returns HTTP 403, not 503.** The enforce path calls `blocked_response(...)` (`data_plane.rs:689`), which hard-codes `.status(403)` (`data_plane.rs:4424-4425`) — identical to every other WAF block. 503 is used **only** by the load-shedder and the fail-close backend-error path (`data_plane.rs:726`). The original doc had this inverted (it claimed the block was 503 and the `403` comment was stale); reality is the reverse — the block is **403**, and the stale comment is the `// Enforce — 503` at `data_plane.rs:678`. Vector 01's table row and gap bullet are corrected accordingly. *(No behavior change needed; the only fix is the stale source comment — folded into the l-tester hardening plan as a doc-hygiene nit.)*

2. **[NUANCE] GeoIP is a compile-time feature that IS on in production builds — "off by default" is misleading for real deployments.** `geoip` is off in a plain `cargo build`, but the `production` meta-feature the Dockerfile ships pulls it in (`aegis-bin/Cargo.toml:92-95`). When compiled **and** an MMDB path is configured, the **country access-list is checked on every request** (`data_plane.rs:458`; MMDB queried lazily, only when a `kind: country` entry exists — not an unconditional DB hit). So "we always check GeoIP when the feature is enabled" is **true for the country access-list path** (and display-only ASN/bot enrichment). Theme 3's deeper point still stands and is the actual gap: *even with GeoIP on*, `kind: asn` is hard-coded `false` (`blacklist.rs:505`), rules-engine `Asn`/`Country` always eval false (empty-context `evaluate()` shim at every call site incl. the `/api/rules/validate` simulator, `simulator.rs:339`), and the Tor/VPN classifier is dead. Theme 3 reworded below.

3. **[NUANCE] Fleet aggregation must gate on cluster mode.** The owner's constraint: cross-node counter sync should only apply in cluster mode. Confirmed the right surface — mirror the DDoS `spike_scope` pattern **but** also require a shared Redis `StateBackend` to be present (`cluster_enabled()`, `control.rs:493`), because the existing DDoS `spike_scope: fleet` toggle does **not** check for cluster mode and silently degrades to "fleet == this node" on an in-memory backend. P2-b reworded below. Note brute-force/velocity detectors hold no backend handle today (`Mutex`/`DashMap` only), so this is real plumbing, not a flag flip.

---

## Verdict at a glance

| # | Vector | Coverage | One-line verdict |
|---|--------|----------|------------------|
| 01 | DDoS L4 & 7 | 🟢 **Strong (L7)** | HTTP-flood auto-block (**403**), Slowloris/RUDY timeouts, tier-aware load-shed that never sheds Critical (503 `load_shed`). **L4 TCP/UDP flood is out of scope (L7 proxy).** Block counting is per-node. |
| 02 | Bot login & credential stuffing | 🟡 **Good structure, blind to outcome** | 3-axis brute-force (per-IP, per-user-across-IPs, per-device-across-IPs) is live and enforced. But the WAF **counts attempts, not failures** (never sees 401/403), counters are **per-node**, and usernames aren't canonicalized. |
| 03 | Relay & proxy | 🟡 **XFF solid, ASN/Tor/VPN dead** | Trusted-proxy XFF resolution + country blacklist are enforced with a safe empty default. **ASN/Tor/VPN classification is display-only or dead code; rules-engine `Asn`/`Country` always evaluate false (empty GeoIP context).** |
| 04 | Device-fingerprint evasion | 🟡 **Device→IP rotation works, fp is coarse** | Device→many-IPs detector is wired and enforced (JA4-keyed, UA-immune). But live TLS fp is a coarse "JA4-light" stub; **rotating UA mints a fresh rate-limit/risk bucket**; no one-device-many-accounts detector. |
| 05 | Behavioral bypass | 🔴 **Largely inert** | The real behavioral engine (`behavior.rs`: timing jitter, error ratio, rate) is **dead code, never wired**. Wired signals are default-OFF and sub-threshold; Referer is **presence-checked only** (any value passes); no navigation/session-depth tracking; no behavioral AI. |
| 06 | Transaction fraud | 🟡 **Shape engine exists, gaps in the shapes** | `velocity_sequence` detects `login→deposit/withdrawal <5s` (enforced) — this is the flagship answer. But **`deposit→withdrawal` and `limit-change→withdrawal` are undetected**, it's IP-keyed (rotation evades, NAT false-positives), and the per-account rate-cap engine (`velocity.rs`) is dead code. |
| 07 | OWASP injection | 🟢 **Broad & enforced, with named evasions** | SQLi (incl. blind/time-based), XSS (incl. in JSON body), SSRF (internal + 3 cloud metadata), path traversal, NoSQL, cmdi/Log4Shell all block at score 70+. Named gaps: **XSS `\uXXXX`/double-encoded in JSON body**, **SSRF DNS-rebinding**, content-type-gated body skip for SQLi/cmdi, lone-hit doesn't block on `low` tier. |
| 08 | Canary / recon | 🟡 **Signatures + response scrub good, no volumetrics** | Canary honeypots block at every tier; recon path/UA signatures score; stack-trace + internal-IP response scrubbing is wired. Gaps: **no endpoint-enumeration / 404-rate detector**, **no OPTIONS/method-abuse scoring**, and **response header strip/inject (`Server`, `X-Powered-By`) is unwired for proxied traffic** → version banners leak. |

Legend: 🟢 credible defense in place · 🟡 partial / evadable / needs wiring · 🔴 mostly absent or inert.

---

## Cross-cutting themes (the patterns behind the per-vector gaps)

Four systemic issues recur across vectors and are worth fixing structurally rather than one detector at a time:

1. **Dead-but-shipped code.** Three fully-implemented, tested subsystems are never called in the request path:
   - `aegis-security/src/behavior.rs` `BehavioralAnalyzer` — timing-jitter, error-ratio, rate, no-cookie. Only `.observe()` in the data plane is the *DeviceIpTracker* (`data_plane.rs:1195`), not this. Non-wiring is self-documented at `run.rs:2596-2602, 2697-2706`. (Vectors 2, 5)
   - `aegis-security/src/velocity.rs` per-account rate-cap engine (`check`/`VelocityRule`) — **zero call sites** in `aegis-proxy/src`. (Vector 6)
   - `response_filter::inject_security_headers` / `should_strip_header` — callers are **only that module's own tests**; proxied upstream responses keep `Server`/`X-Powered-By`/`X-Debug*`. (Vector 8)
   These represent the cheapest coverage wins: the logic already exists and is tested; it just needs wiring + a config toggle.

2. **Per-node counting vs. fleet.** Brute-force axes (`brute_force.rs:52-58`), the velocity-sequence ring buffer, and DDoS *block* counting are per-node in-process. Only the DDoS **spike signal** aggregates fleet-wide (`ddos.rs:448-495`, Redis, `spike_scope: fleet`). A campaign load-balanced across nodes dilutes every per-node distinct-IP / sequence count below threshold. Distributed credential stuffing (vector 2) and IP-rotating fraud (vector 6) are the direct beneficiaries.

3. **GeoIP: the country access-list works when provisioned; ASN + geo-rules are dead even then.** *(reworded 2026-07-03)* `geoip` is a compile-time feature — off in a plain `cargo build`, but **on in production builds** (pulled by the `production` meta-feature, `aegis-bin/Cargo.toml:92-95`) and enforced once an MMDB path is set (`accept.rs:831-834`). What actually consults it per request is **only the country access-list** (`data_plane.rs:458`, lazy MMDB lookup) — that path is live and correct. The real gap is that the rest of the geo surface is dead *even with GeoIP on*: `kind: asn` is hard-coded `false` (`blacklist.rs:505`); rules-engine `Asn`/`Country` conditions get an **empty `EvalContext` (no geoip)** at every call site — both data-plane sites (`data_plane.rs:1090, 2071` vs `eval.rs:326-336`, via the `evaluate()` shim `eval.rs:118-120`) *and* the `/api/rules/validate` simulator (`simulator.rs:339`) — so they always return false; and the Tor/VPN classifier (`ip_rep/asn.rs`) is never wired. Vector 3's Tor/VPN/datacenter-to-`/login` story is essentially unshipped.

4. **The WAF is request-phase and outcome-blind.** No detector sees the upstream **response status**. Brute-force counts attempts not failures (vector 2); there is no login success/failure feedback loop; the one component that models error ratio (`behavior.rs`) is the dead code from theme 1. This caps how good bot/ATO detection can get without a response-signal channel.

---

## Per-vector detail

### 01 — DDoS Layer 4 & 7 · 🟢 Strong (L7 only)

**Enforced today:**
- Per-`(tier,ip)` HTTP-flood sliding window → auto-block **403** (via `blocked_response`, `data_plane.rs:689`/`:4424-4425`), default `1000 req/10s`, 300s TTL (`ddos.rs:564-622`, wired `data_plane.rs:586-700`).
- Independent per-IP RPS limiter layered underneath (`rate_limit/ip_limiter.rs`, `data_plane.rs:775-797`).
- EWMA spike detection with hysteresis tightens every IP's window to ~20 rps while active (`ddos.rs:199-212, 787-829`).
- Fleet-wide RPS aggregation for the **spike signal** (`ddos.rs:448-495`).
- **Slowloris:** 10s header-read timeout (`accept.rs:45`, applied at `:1551/1562/2407/2428`); pre-TLS trickle deadline (`proxy_protocol.rs:240`).
- **RUDY / slow-POST:** body collect wrapped in `read_timeout` (default 30s) → **408** (`data_plane.rs:962-986`); oversize `Content-Length` rejected up front.
- Connection-concurrency semaphore acquired **before** TLS work (`accept.rs:1657-1670`); separate streaming-body semaphore.
- **Graceful degradation:** adaptive-concurrency load-shedder (Gradient2) that **never sheds Critical tier**, sheds Medium/Low first → 503 `load_shed` (`shed.rs:197-220`, `data_plane.rs:908-927`), fed by run-queue dispatch delay so it opens under CPU starvation.
- Per-tier fail-open/close on backend error (`data_plane.rs:708-715`).

**Gaps:**
- **L4 TCP/UDP flood is out of scope** — aegis is an L7 TLS/HTTP proxy; no UDP sockets exist. SYN/UDP-amp floods must be absorbed by kernel/LB/network upstream. `conn_limit` only mitigates app-layer TCP connection exhaustion.
- DDoS **block** counting is per-node; only the spike *signal* aggregates fleet-wide (and only with Redis + `spike_scope: fleet`).
- Pre-TLS connection-cap rejections drop silently at TCP (debug-logged only) — correct for cost, invisible to ops.
- **Stale doc-comment (corrected 2026-07-03):** the block is **403** (via `blocked_response`); the misleading comment is `// Enforce — 503` at `data_plane.rs:678`. `ddos.rs:37` ("does NOT short-circuit with HTTP 403") is accurate. Doc-only fix — tracked in the l-tester hardening plan.

### 02 — Bot login & credential stuffing · 🟡 Good structure, outcome-blind

**Enforced today** — `BruteForceDetector` is in the default chain (`detectors/mod.rs:681`) with three real axes (`brute_force.rs:90-163`):
1. Per-IP attempts/window (classic brute force).
2. **Per-username across distinct IPs** (`record_user_and_check`, default >5 distinct IPs/window) — genuine cross-IP correlation = **password spraying / distributed stuffing on one account**.
3. **Per-device (JA4) across distinct IPs** (default >10) — **IP-rotating stuffing reusing one TLS client**.
- Auth-path aware (15 login aliases), counts POST/PUT/PATCH + any method carrying `Authorization: Basic` (`brute_force.rs:171-192, 516-532`); username parsed from Basic/JSON/form (`:272-339`).
- Per-IP RPS limiter + bot-classifier challenge ladder (`bots.rs:252-256`).

**Gaps:**
- **Outcome-blind:** counts attempts, not failures — no upstream 401/403 feedback (theme 4). Can't tell 10 good logins from 10 failed; a lucky guess on attempt #2 isn't flagged.
- Counters are **per-node in-process** (theme 2) — cross-node stuffing dilutes distinct-IP counts.
- Device axis needs forwarded JA4 (`brute_force.rs:213-223` skips when `tls == None`) — a JA4-stripping CDN in front loses it.
- Score-based, no hard **per-account lockout** primitive.
- Usernames not canonicalized (`brute_force.rs:270-271`) — `Alice`/`alice`/`alice ` count as distinct → per-user aggregation evaded with case/whitespace variants.

### 03 — Relay & proxy · 🟡 XFF solid, ASN/Tor/VPN dead

**Enforced today:**
- `resolve_client_ip` walks XFF right-to-left skipping trusted CIDRs; if the TCP peer isn't trusted, XFF is ignored entirely (`xff.rs:13-50`). **Trusted-proxy list defaults empty** (`data_plane.rs:399-403`) → an edge attacker can't spoof XFF to move their keyed IP. Resolved IP keys blacklist/DDoS/rate-limit/risk.
- **Country** blacklist enforced on the resolved IP *if* GeoIP is provisioned (`blacklist.rs:506-515`, `accept.rs:865-879`).
- XFF/XFH injection-payload detection (CRLF, host-poisoning) (`header_injection.rs:22, 91-111, 237-303`).

**Gaps (most of the vector):**
- **No Tor/VPN detection in the enforced path.** The wired enum `bots::AsnClassification` has only Residential/Mobile/Hosting/Datacenter/Unknown — no Tor/VPN. The Tor/VPN-aware `ip_rep/asn.rs` (`AsnCategory::Tor/Vpn/Bogon`, risk deltas) is **dead code** (referenced only by its own tests; empty Tor list).
- **ASN blocking not wired:** `kind: asn` blacklist is hardcoded `false` (`blacklist.rs:505`); ASN→bot-score is **dashboard-only** (`accept.rs:2239-2295`), never feeds the block decision.
- **Rules-engine `Asn`/`Country` always false** — both data-plane call sites pass `EvalContext::empty()` (no geoip) (`data_plane.rs:1090, 2071` vs `eval.rs:326-336`).
- Datacenter-IP-to-`/login` gets no special handling (only +40 to a display-only bot score).
- No XFF hop-count / duplicate-header / Via-chain anomaly rejection.
- Everything ASN/country is off until an operator provisions an MMDB (theme 3).

### 04 — Device-fingerprint evasion · 🟡 Rotation works, fp coarse

**Enforced today:**
- **Device→many-IPs** detector: `observe(device_fp, ip)` counts distinct IPs/device in a window (>5/60s → score 60), wired into risk/block (`device_ip_tracker.rs:123-167`, `data_plane.rs:1192-1199`). Keyed on **JA4 only** → rotating UA does **not** defeat it.
- Real post-handshake TLS fp captured from the rustls `ServerConnection` (`accept.rs:1826-1838`).
- Composite risk/rate key = `ip + blake3(ja4‖ua) + session` (`data_plane.rs:4123-4139`) so NAT'd users don't share buckets.

**Gaps:**
- **Rotating User-Agent mints a fresh bucket.** `device_fp = hash(ja4‖UA)` (`fingerprint/mod.rs:60-71`) → new UA = new RiskKey = **fresh rate-limit budget + reset cumulative risk** (`data_plane.rs:776, 789/1234`). (DeviceIpTracker is the one exception.)
- **Live fp is a coarse "JA4-light" stub** — negotiated cipher + ALPN + version + SNI type only; ClientHello cipher/extension lists are never read (`listener/tls.rs:34-67`). The careful `ja3.rs`/`ja4.rs`/`h2.rs` modules are **library-only, never called**. Consequence: class-level only (Chrome vs curl), many legit collisions + easy blend-in.
- **No one-device-many-accounts detector** — there's a device→IP reverse map but no device→account/session count; the `session` axis *separates* buckets rather than counting accounts per device.
- H2 fingerprint always `None` (`accept.rs:2225`); known-bad-JA4 list empty (`bots.rs:124`).
- Plain HTTP has no device axis (`tls: None` → `device_fp None`).
- No TLS-fp ↔ UA consistency check (Chrome UA + curl-class cipher isn't flagged — the JA4-light can't express it).

### 05 — Behavioral bypass · 🔴 Largely inert

**What's wired** is thin and default-OFF: `BehaviorSignalsDetector` (`config.rs:5017` default-OFF) emits sub-threshold corroborating signals — `behavior_zero_depth` 15, `behavior_missing_referer` 20, `behavior_no_ua` 15 — stacking to at most 50, deliberately below block_at 70 (`detectors/behavior_signals.rs:136-190`).

**Gaps:**
- **The real behavioral engine is dead code** (theme 1): `behavior.rs` implements machine-perfect-timing detection via coefficient-of-variation jitter (`:122-182`), error ratio, rate, no-cookie — all tested, all **unwired**. The wired path's timing signal (`behavior_burst`) was *removed* for tripping on benchmarks. So bot cadence is neither scored nor observed in production.
- **Zero-depth is not navigation tracking** — it's a per-IP first-touch flag keyed on `peer.ip()` (`behavior_signals.rs:120-134`); any Cookie or Referer defeats it, and it's off by default. No session-sequence / legitimate-flow verification (arguably needs session state the WAF doesn't hold → a gateway concern).
- **Referer is presence-checked only** (`behavior_signals.rs:159-171`) — any non-empty value passes; zero origin/host/same-origin validation anywhere.
- **No behavioral AI.** The wired AI detector (`run.rs:588/683`) is a **content classifier** — 29 features are lengths/entropy/injection-pattern counts (`detectors/ai/features.rs:99-128`), no timing/sequence/navigation features.

### 06 — Transaction fraud · 🟡 Shape engine, missing shapes

**Enforced today** — `VelocitySequenceDetector` is default-ON and in-path (`config.rs:5018`, `detectors/mod.rs:764-770`):
- Classifies endpoints into Login/Otp/Deposit/Withdrawal (transfer/cashout/payout → Withdrawal) (`velocity_sequence.rs:71-92`).
- Detects fast cross-endpoint shapes per-IP: `login→deposit <5s` score 60 (challenge), `login→withdrawal <5s` score **70 → blocks**, `otp→deposit` 50, `otp→withdrawal` 60 (`velocity_sequence.rs:112-137`). This is the WAF's deliberate answer to "login→deposit <5s" (F-CRITICAL-003).

**Gaps:**
- **`deposit→withdrawal` not detected** — no such rule in the table.
- **`limit-change→withdrawal` completely undetected** — there is no limit-change EndpointTag at all; such paths classify as `None` and aren't even stored.
- **IP-keyed, not account/session** (`velocity_sequence.rs:192, 241`) — IP rotation between the two steps **evades** (test `different_ips_do_not_chain` documents this); NAT causes false chains.
- Ruleset is **hardcoded**, not operator-tunable (config is a TODO).
- No transaction value/amount awareness.
- The stateful per-account rate-cap engine (`velocity.rs`) is **dead code** (theme 1).
- **Scope note:** deep transaction-fraud enforcement (balances, HMAC, authZ) is intentionally punted to the gateway (consistent with JWT being detection-only, `scores.rs:452-455`). But shape detection is deliberately in-WAF — extending the rule table + adding account-keying is in-scope and just unimplemented.

### 07 — OWASP injection · 🟢 Broad & enforced

**Enforced today** (all block at score 70, Log4Shell/XXE 80, on critical/high/medium tiers):
- **SQLi** incl. blind/time-based (`WAITFOR DELAY`, `BENCHMARK(`, `SLEEP(`), 30+ regexes over a repeatedly-decoded target (`sqli.rs:31-76`, `mod.rs:315-330`).
- **XSS incl. in JSON body** — body scanned **unconditionally** (only opaque beacons skipped) so `<script>` in a JSON body blocks (`xss.rs:114-127`).
- **SSRF** — loopback/RFC1918, AWS `169.254.169.254`, GCP `metadata.google.internal`, Alibaba `100.100.100.200`, decimal/hex/octal encodings, IPv4-mapped-IPv6, userinfo confusion; scans query/path/body + `x-original-url`/`x-rewrite-url` (`ssrf.rs:12-128`).
- **Path traversal**, **NoSQL**, **command injection / Log4Shell** all present and enforced.

**Named evasions (real gaps):**
- **XSS-in-JSON-body Unicode-escape / double-encode:** the XSS body path decodes only `url_decode` + `html_entity_decode` and doesn't parse JSON, so `{"x":"<script>…"}` and double-URL-encoded payloads slip (`xss.rs:120-121`; `\u00XX` deliberately dropped).
- **SSRF DNS-rebinding:** pure static IP/hostname regex, no resolution — a public name resolving to `169.254.169.254` passes.
- **Content-type-gated body skip for SQLi/cmdi:** a missing/forged/`octet-stream` Content-Type skips SQLi + cmdi **body** scanning (`mod.rs:405-420`). (XSS/SSRF/NoSQL don't gate — asymmetric.)
- **`low`-tier single-hit gap:** a lone score-70 exploit does **not** block on a `low`-tier route (only accumulates); only canary(100)/Log4Shell/XXE(80) single-block there.
- FP-reduction gates narrow coverage: XSS exec-sink/HTML-context gating, opaque-beacon body gate, cookie removed from SQLi/XSS scan, CookieInjection default-OFF, AI backstop deferred + only scores 50.

### 08 — Canary / recon · 🟡 Signatures + scrub, no volumetrics

**Enforced today:**
- **Canary/honeypot** paths (operator-configured, hot-swappable via `PUT /api/risk/canary-paths`) score **100** → single-hit block at **every** tier incl. low (`canary.rs:97-190`, `scores.rs:446-451`). Inert until enabled + paths configured.
- **Recon signatures:** ~60 probe-path regexes + scanner-UA list (`recon.rs:203-288`). recon_path scores 25 (accumulates only); recon_tool 50 (single-blocks on critical only).
- **Error-harvest response scrubbing:** stack-trace scrub (7 languages) + internal-IP masking, **wired & enforced** on proxied response bodies (`response_filter.rs:94-180`, `pipeline.rs:214-259` ← `data_plane.rs:3042-3078`).

**Gaps:**
- **No endpoint-enumeration / high-404-rate detector** — recon is pure per-path signature; a scanner hitting many non-signatured paths, or a slow/distributed scan under the accumulation threshold, isn't flagged.
- **No OPTIONS / method-abuse scoring** — OPTIONS is handled only as CORS preflight (which itself advertises allowed methods); the verb is never scored.
- **Response security-header strip/inject is UNWIRED for proxied traffic** (theme 1) — `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug*`, `X-Internal*` leak from the origin; CSP/HSTS injection exists only for the dashboard, not upstream responses.
- `mask_json_fields` (field-aware DLP) is unwired (self-noted "follow-up").
- recon_path never single-blocks; recon_tool blocks only on critical.

---

## Recommended improvement backlog

Ordered by (impact × cheapness). Each item is independently shippable; file:line anchors are the starting point. **Now staged into [`FEAT-attack-coverage-wiring-2026-07-03.md`](./FEAT-attack-coverage-wiring-2026-07-03.md)** — the descriptions below remain the rationale; the FEAT file carries the PR breakdown, acceptance tests, and performance budget.

> **Performance is a scored criterion (20 pts) and a hard requirement — every item here runs on the request hot path.** Guardrails carried into the FEAT plan: (a) new default-OFF detectors add **zero** cost when disabled (mask-derivation already gates them); (b) any wired signal must be O(1)/bounded per request — no unbounded maps, no new regex passes without `RegexSet` batching (see the l-tester perf plan); (c) fleet aggregation is async/fire-and-forget over the shared backend, never a blocking round-trip on the request path, and gated on cluster mode; (d) response-path work (header strip) is a fixed small set of header ops, not a scan. Measure each against `deploy/STAGING-BENCHMARK.md` before/after.

### P1 — high impact, logic already exists (wiring / small extension)

- **P1-a · Wire response header stripping for proxied traffic.** `should_strip_header` + `inject_security_headers` are written and tested (`response_filter.rs:11-91`) but only the dashboard path uses fixed headers. Call them from the proxied-response pipeline (alongside the already-wired body scrub at `data_plane.rs:3042-3078`). Closes the vector-8 version-banner leak. *Lowest-risk, highest-certainty win.*
- **P1-b · Extend the transaction shape table + add a limit-change tag.** Add `deposit→withdrawal` and `limit-change→withdrawal` rules and a `LimitChange` EndpointTag to `velocity_sequence.rs:71-137`. Covers the two missing vector-6 shapes. Pure data/table extension.
- **P1-c · Canonicalize usernames in the brute-force per-user axis.** Lowercase + trim before keying (`brute_force.rs:270-271`) so case/whitespace spray variants aggregate. One-line-ish, closes a real per-user evasion.
- **P1-d · XSS body decoding parity with SQLi.** Add unicode-escape + repeated-decode (and/or JSON-value extraction) to the XSS body path (`xss.rs:120-121`) so `\uXXXX`/double-encoded payloads in JSON bodies are caught. Reuse `normalize_for_detection`.

### P2 — meaningful coverage, moderate work

- **P2-a · Wire `BehavioralAnalyzer` into the request path (behind a default-OFF toggle).** Call `.observe()` from the data plane and feed its jitter/rate signals into risk (`behavior.rs` is ready; non-wiring noted at `run.rs:2596-2602`). Revives vector-5 timing detection and vector-2 error-ratio (needs the response-signal channel in P3-b to be fully useful). Re-tune thresholds so it doesn't trip benchmarks (the reason `behavior_burst` was removed).
- **P2-b · Fleet-aggregate the brute-force axes (cluster mode only).** Mirror the DDoS Redis fleet-bucket pattern (`ddos.rs:448-495`) for per-user / per-device distinct-IP counts so cross-node distributed stuffing doesn't dilute below threshold (theme 2). **Gating (per owner): only in cluster mode.** Add a per-detector `count_scope: per_node | fleet` (default `per_node`) mirroring `SpikeScope`, *and* require a shared Redis `StateBackend` present (`cluster_enabled()`, `control.rs:493`) — do **not** repeat the DDoS `spike_scope` gap where `fleet` on an in-memory backend silently means "fleet == this node". Prereq plumbing: thread a `StateBackend` handle into `BruteForceDetector` (which today holds only `Mutex`/`DashMap`, no backend). Perf: fire-and-forget increment + read-prior-bucket, fail-safe to per-node on backend error (as `tick_rps_fleet_at` does) — never block the request on Redis.
- **P2-c · Fix rules-engine `Asn`/`Country` evaluation + wire ASN blacklist.** Populate `EvalContext` with geoip at the two data-plane call sites (`data_plane.rs:1090, 2071`) **and** the simulator (`simulator.rs:339`) so `Condition::Asn/Country` can be true; flip `kind: asn` blacklist from hardcoded-false (`blacklist.rs:505`). Prerequisite: GeoIP provisioned (already on in production builds). Unlocks vector-3 datacenter-to-`/login` rules. Perf: the MMDB reader is a `OnceLock` already threaded to the data plane; reuse the same lazy-cached lookup the country access-list uses (one lookup per request max, only when a geo condition is present).
- **P2-d · Endpoint-enumeration / 404-rate detector.** Add a per-IP (and fleet) rolling counter of distinct-path 404s / non-signatured probes to `recon.rs`, scoring above the accumulation floor. Catches enumeration that today's per-path signatures miss.
- **P2-e · Referer origin validation (optional, opt-in).** Upgrade `behavior_missing_referer` from presence to same-origin/allowlist checking (`behavior_signals.rs:159-171`) for CRITICAL routes. Guard against false positives on legitimate cross-origin flows.

### P3 — larger / architectural

- **P3-a · Real JA4 from the ClientHello.** Read the cipher/extension lists in the TLS layer (`listener/tls.rs:34-67`) and call the existing `ja4.rs::compute` so fingerprints are version-precise. Prerequisite for a real TLS-fp↔UA consistency check and known-bad-JA4 blocklist (`bots.rs:124`). Reduces vector-4 rotation FPs and blend-in.
- **P3-b · Response-outcome signal channel.** Give detectors (brute-force, behavioral) access to upstream status so login **failures** (401/403) drive scoring, not just attempts (theme 4). Structural but unlocks credible ATO/stuffing detection.
- **P3-c · One-device-many-accounts detector.** Add a device_fp→distinct-account counter (peer of DeviceIpTracker) to catch multi-account creation from one device (vector-4 core scenario). Needs an account/username signal on the relevant routes.
- **P3-d · Decide L4 posture explicitly.** Document that TCP/UDP volumetric floods are handled upstream (kernel/LB/anycast), and confirm the app-layer `conn_limit` + accept-loop backpressure story is sufficient for "DDoS aimed at the WAF." Not code — a stated boundary + runbook.
- **P3-e · Per-account lockout primitive.** A hard lockout (not just additive score) for repeated failures on one account, once P3-b provides failure signal.

### Out of scope (state the boundary, don't build)

- Deep **transaction-fraud** enforcement (balance checks, HMAC/signature, authZ) stays in the router/gateway per the existing architectural stance (`scores.rs:452-455`); the WAF owns only **shape** detection (P1-b).
- **L4 TCP/UDP flood** absorption is a network/LB concern (P3-d documents, doesn't implement).
- Full **session navigation-depth** modeling needs session state the WAF doesn't hold — a gateway/app responsibility; the WAF contribution is the presence/timing heuristics above.

---

## Notes for whoever picks this up

- Nothing here changes code. The P1 items are the intended first PR(s): they wire or minimally extend logic that already exists and is tested, so they carry the least risk and clear the most obvious external-red-team findings (leaked banners, missing fraud shapes, spray evasion, JSON-body XSS).
- Verify each "unwired/dead" claim still holds before building — three were re-confirmed on 2026-07-02 **and again 2026-07-03** (`BehavioralAnalyzer`, `velocity.rs`, `inject_security_headers` all have no non-test callers), but the tree moves.
- Per the repo norm, treat FP-reduction gates (content-type body gating, exec-sink XSS, beacon skip) as deliberate — tightening them for coverage must be measured against benchmark false-positive rates, not just added blindly.

---

## Archival note (what to close out after the derived plans ship)

This file is the umbrella analysis; it does not get archived on its own. Close it out as follows:

- ✅ **DONE 2026-07-04** — [`FEAT-attack-coverage-wiring-2026-07-03.md`](./archived/FEAT-attack-coverage-wiring-2026-07-03.md) shipped everything it committed to and is archived; the shipped banner at the top of this file lists the merge PRs. Not-taken items carry explicit won't-do / blocked notes in the FEAT ledger (AC-P3-a blocked on rustls, AC-P3-c owner-declined, AC-P3-e declined as an L7 anti-pattern) — nothing silently dropped.
- When **[`PLAN-ltester-perf-and-hardening-2026-07-03.md`](./PLAN-ltester-perf-and-hardening-2026-07-03.md)** ships, archive it the same way; it also closes the two doc-hygiene nits from *Corrections* above (the `data_plane.rs:678` "503" comment and `canary.rs:6` "score 90"). ✅ **Both nits FIXED 2026-07-03** (LT-P8 doc-nits PR): `data_plane.rs:678` now reads `// Enforce — 403`; `canary.rs:6` now reads `(score 100)`.
- **Archive this ASSESSMENT** only once both derived plans are archived and every vector's residual gap is either shipped or captured as a standalone issue — at which point this becomes a historical record, not a live tracker. Until then it stays in `plans/issues/` as the source of truth for *why* each derived item exists.
