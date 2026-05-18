# 2026-05-18 QC follow-up — verification + remaining fix plan

> **Status:** Drafted 2026-05-18. Cross-checks the three QC report
> sets at `tests/s-tester/reports/2026-05-18-*` against current HEAD.
> The reports were generated mid-day on 2026-05-18, BEFORE my Phase
> E/F/C.2 commits landed — so a large fraction of their "still
> broken" claims are stale.

## Sources

- `tests/s-tester/reports/2026-05-18-ddos-bug-report/F-CRITICAL-005-ddos-still-not-wired.md`
- `tests/s-tester/reports/2026-05-18-detector-spec-verification/` (6 files)
- `tests/s-tester/reports/2026-05-18-fix-verification/` (8 files — SUMMARY, STILL-BROKEN-CRITICAL, STILL-BROKEN-PARTIAL, NEXT-STEPS, 5× per-crate)

## Methodology

Spot-checked every `file:line` cited in the QC reports against
current HEAD. Each finding is classified as:

- **STALE** — fix landed in my Phase E/F/C.2 batch; QC was looking at pre-fix state
- **OUTSTANDING** — claim still holds at the cited file:line; real work to do
- **MOOT** — issue is real but explicitly out of v2.3 contract scope (e.g. compliance modes)

## Verification matrix

### STALE (9 findings — already fixed)

| QC finding | My fix commit | What the QC missed |
|---|---|---|
| security F-CRITICAL-001 — RiskTracker IpAddr-only | `2521d17` | `tracker.rs:74` now `DashMap<RiskKey, Slot>` |
| security F-CRITICAL-002 — IpRateLimiter IpAddr-only | `aedcece` | `ip_limiter.rs:90` now `DashMap<RiskKey, …>` |
| security F-CRITICAL-003 — velocity sequence engine missing | `44ebdcc` | new `detectors/velocity_sequence.rs` wired at boot; 4 sequences (login→deposit/withdrawal, otp→deposit/withdrawal) within 5 s |
| security F-CRITICAL-004 — 3 of 4 §5.2 behavior signals missing | `ffe11c0` | new `detectors/behavior_signals.rs` ships all 4 (burst, no-UA, missing-Referer, zero-depth); wired |
| security F-CRITICAL-007 — canary doesn't auto_block | `966f831` | new `detectors/canary.rs` consumes `risk.canary_paths`, emits score 90 (above default `block_at: 70`) — single-hit-block by accumulation |
| security F-CRITICAL-012 — `header_injection` hardcoded keywords | `3a1adde` | structural needles only; `evil`/`attacker`/`malicious`/`phish` removed |
| security F-CRITICAL-013 — response_filter §5.7 (partial) | `755e9b2` | header strip expanded (exact + prefix scanner); IPv6 internal-IP masking; JSON field-mask helper |
| control F-CRITICAL-001 — rule CRUD doesn't drive live RuleSet | `c760d8f` | three-surface shared `Arc<RuleSet>`; data-plane evaluator wired; UI templates landed |
| core F-CRITICAL-003 — AuditEvent missing method/path/mode | `c3f45a0` | three Option<String> fields added; 73-site sweep; `with_request_info` builder |

**Action:** none — these are done. The QC report should be updated
to reflect the post-fix state. Mention in next QC pass.

### OUTSTANDING (7 findings)

| # | Finding | File:line | LoC | Round-1? |
|---|---|---|---:|:-:|
| 1 | proxy F-CRITICAL-001 — H3 bypasses entire security pipeline | `aegis-proxy/src/listener/http3.rs:290` | 80 | **YES** |
| 2 | security F-CRITICAL-005 — DDoS gate ignores per-tier + no fail-close | `aegis-security/src/ddos.rs` (runtime) + `data_plane.rs:349` + `api/gates.rs:117` | 175 | **YES** |
| 3 | security F-CRITICAL-011 — JA4 `sort_unstable` + no GREASE strip | `aegis-security/src/fingerprint/ja4.rs:57-60` | 15 | no |
| 4 | security F-CRITICAL-010 — no device→IP reverse map | `aegis-security/src/fingerprint/mod.rs` (missing) | 120 | no |
| 5 | security F-CRITICAL-014 — `brute_force` per-IP + POST-only | `aegis-security/src/detectors/brute_force.rs:39,91` | 175 | no |
| 6 | security F-CRITICAL-015 — `bots.rs` ignores `ja4_fingerprint`; no ASN; no ladder | `aegis-security/src/bots.rs:17,72-115` | 175 | no |
| 7 | security F-CRITICAL-008 — `Pipeline::inbound` runs rules only, no detectors/risk/canary | `aegis-security/src/pipeline.rs:170-178` | 100 (or document as deliberate bypass) | no |

**Plus the detector-spec-verification surfaced one item not in the
fix-verification list:**

| 8 | engine FAIL — Smart Cache §5.2 #07 (no per-tier vary, no bypass, no /api/cache) | needs new module | unknown — design call needed | no |

### MOOT (2 findings — out of v2.3 scope)

| Finding | Why moot |
|---|---|
| control F-CRITICAL-002 — compliance modes theater | User decision: compliance enforcement removed in `a647b60`; `Hackathon_Doc/EN_waf_interop_contract_v2.3.md` doesn't mandate compliance modes. The "Tính hiệu lực" risk is mitigated because the dashboard UI no longer claims a compliance toggle. |
| control F-CRITICAL-008 — rollback dispatcher missing 11 actions | Tracked in `plans/future/`; not Round-1 gate. |

## Recommended sprint plan

### Sprint 1 — Round-1 Pass/Fail gates (~255 LoC, prio order)

Two items, both architecture-impacting:

#### S1.1 · H3 bypass — `aegis-proxy/src/listener/http3.rs` (~80 LoC)

The QUIC listener currently calls `crate::proxy::handle_request`
(the bare router). Every HTTP/3 request skips the full security
pipeline: no detectors, no rate-limit, no risk score, no §5 headers
stamped, no §6 audit. The §5/§6/§10 contract fails on the entire
QUIC surface.

**Fix sketch:**

```rust
// listener/http3.rs around line 290
let peer = SocketAddr::new(connection.remote_address().ip(),
                           connection.remote_address().port());
// extract body with proxy.max_body_bytes cap

let (resp, decision_tag) = crate::data_plane::handle_data_request(
    hyper_req,
    peer,
    detectors.as_ref(),
    &mask,
    &risk,
    &ip_rate_limiter,
    &load_gauge,
    &verbosity,
    &request_stage_hist,
    &route_latency_hist,
    &route_activity,
    &detector_latency_hist,
    &bus,
    &ctx,
    &detector_hit_metrics,
    &identity,
).await;
let resp = stamp_interop_response(resp, decision_tag, …);
```

The HTTP/1.1 and HTTP/2 listeners already do this — copy the
shape. Tests: a unit test that drives a QUIC request through the
listener and asserts `X-WAF-Action` header is present.

#### S1.2 · DDoS per-tier + fail-close — `aegis-security/src/ddos.rs` + `data_plane.rs:349` + `aegis-control/src/api/gates.rs:117` (~175 LoC)

Schema landed in Phase G (`678baa2`); runtime ignores it. Three
sub-fixes per `tests/s-tester/reports/2026-05-18-ddos-bug-report/F-CRITICAL-005-ddos-still-not-wired.md`
(items DD-01 through DD-07):

1. **DD-01** — `DdosConfig` runtime struct gains `tier_overrides:
   HashMap<Tier, DdosTierLimit>` + `failure_mode: HashMap<Tier,
   FailureMode>`; new `limit_for(tier)` + `fail_mode_for(tier)`
   helpers. (~30 LoC.)
2. **DD-02** — `DdosDetector::check(ip, tier)` takes tier; reads
   per-tier limit; falls back to global when no override. (~25
   LoC.)
3. **DD-03** — `DdosRuntime::check(peer_ip, tier)` plumbs through.
   (~20 LoC.)
4. **DD-04** — `data_plane.rs:349` passes `route_ctx.tier` to the
   call. (~10 LoC.)
5. **DD-05** — fail-close branch: when the state-backend lookup
   returns `Err(_)` AND `tier == Critical`, return 503 immediately.
   Other tiers fail-open with a warn log. (~30 LoC.)
6. **DD-06** — `DdosPutBody` in `api/gates.rs:117` gains
   `tier_overrides` + `failure_mode` fields; PUT handler
   propagates into the runtime struct. (~40 LoC.)
7. **DD-07** — dashboard UI knob to surface the per-tier sliders.
   (~50 LoC of jsx + rebuild.)

### Sprint 2 — Quick wins (~205 LoC, high impact / low LoC)

#### S2.1 · JA4 sort + GREASE strip (~15 LoC) — cheapest fix

`aegis-security/src/fingerprint/ja4.rs:57-60`. Two changes:

```rust
fn is_grease(v: u16) -> bool { (v & 0x0F0F) == 0x0A0A }

// In ja4_a / ja4_b construction:
let ciphers: Vec<u16> = cipher_suites
    .iter()
    .copied()
    .filter(|c| !is_grease(*c))
    .collect();
// REMOVE: ciphers.sort_unstable();
let exts: Vec<u16> = extensions
    .iter()
    .copied()
    .filter(|e| !is_grease(*e))
    .collect();
// REMOVE: exts.sort_unstable();
```

Two unit tests pin: (a) Chrome's GREASE-rotated handshake produces
the SAME `JA4` across multiple connections after this fix;
(b) deliberate cipher reorder DOES change the JA4 (sort would have
masked this).

Impact: stabilises the device fingerprint that F-CRITICAL-010
(device→IP reverse map) and F-CRITICAL-015 (bots.rs ja4_fingerprint
read) depend on.

#### S2.2 · `bots.rs` reads ja4_fingerprint + adds ASN (~175 LoC)

After S2.1 the JA4 fingerprint is stable; now make `bots.rs`
actually use it. Per QC `03-identity.md`:

```rust
pub struct BotSignal {
    pub ja4_fingerprint: Option<String>,   // already exists at line 17
    pub asn: Option<u32>,                  // NEW
    pub asn_classification: AsnClass,      // NEW (Hosting / Datacenter / Residential / Unknown)
}

fn classify(signal: &BotSignal) -> BotClass {
    // currently: UA-only heuristic
    // add: JA4 match against known-bot table + ASN-class weighting
    //      challenge ladder (suspicious → challenge → block on repeat)
}
```

Impact: §5.2 #05 (ASN classification mandate), §5.2 #08 (JA
fingerprint).

#### S2.3 · brute_force three-axis tracker (~175 LoC)

`detectors/brute_force.rs`:

- Add per-user axis (parse `username` from body for POST/PUT/PATCH).
- Add per-device axis (read JA4 from RequestView).
- Keep existing per-IP axis.
- Method allowlist: POST, PUT, PATCH, and Basic-auth `Authorization`
  header on any method.
- Score arithmetic: separate counters per axis; fire when ANY axis
  crosses threshold.

Impact: §5.3 OWASP brute force; Attack Battle scenario 02
(distributed credential stuffing).

### Sprint 3 — Intelligence rubric depth (~220 LoC)

#### S3.1 · device→IP reverse map — `DeviceIpTracker` (~120 LoC)

New module `aegis-security/src/fingerprint/device_ip_tracker.rs`:

```rust
pub struct DeviceIpTracker {
    map: Mutex<HashMap<DeviceId, Vec<(IpAddr, Instant)>>>,
    threshold_distinct_ips: usize,
    window: Duration,
}

impl DeviceIpTracker {
    /// Returns Some(Signal { score: 60 }) when the same device_id
    /// has been seen from `threshold_distinct_ips` distinct IPs
    /// within `window`.
    pub fn observe(&self, device_id: DeviceId, ip: IpAddr) -> Option<Signal> { … }
}
```

Wire as a peer detector after `behavior_signals` in the chain.
Impact: §5.2 #08 device-rotation-across-IPs; Attack Battle 04.

#### S3.2 · `Pipeline::inbound` consolidation (~100 LoC, OR documentation)

Two options:
- Wire `Pipeline::inbound` to call canary → blacklist → detectors
  → risk → rules in the right order. Currently it runs rules only;
  the data plane bypasses it intentionally.
- Document the bypass as deliberate and remove the trait if it
  has zero callers other than tests.

Recommend the second option — the data plane shape is correct,
the trait surface is a legacy artifact.

### Out of scope for this plan

- Smart Cache §5.2 #07 — needs a design call (do we want HTTP cache
  in the WAF, or is that the upstream CDN's job?). Skip until user
  weighs in.
- F-CRITICAL-002 compliance modes — already removed per v2.3
  contract.
- Stale findings — already fixed.

## Suggested execution order

1. **Sprint 1 first** — Round-1 Pass/Fail is non-negotiable.
2. **Sprint 2 in any order** — items independent; ship as
   separate small commits.
3. **Sprint 3 last** — Intelligence depth, scoring axis only.

Total: ~680 LoC, ~5-7 hours dev + test if executed back-to-back.
Each item has tests-first scope; no architectural rewrites needed.

## QC report follow-up

After we close Sprint 1 + 2 + 3, the QC reports at
`tests/s-tester/reports/2026-05-18-*/` should be re-run against
HEAD. They will need updating for:

1. The 9 STALE findings (so the next pass doesn't re-raise them).
2. The 2 MOOT findings (so the next pass doesn't bring back
   compliance theater as a problem).

Optionally, the next QC pass should rebase its file:line citations
against HEAD before publishing, to avoid the stale-report problem
that happened here.
