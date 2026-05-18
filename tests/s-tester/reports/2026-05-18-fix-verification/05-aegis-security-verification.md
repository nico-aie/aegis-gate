---
folder: 2026-05-17-security-audit/
agent: Agent E (verification)
date: 2026-05-18T00:00Z
status: 3 FIXED / 1 PARTIAL / 11 NOT_FIXED (15 total) — ⚠️ VẤN ĐỀ NGHIÊM TRỌNG
---

# aegis-security fix verification — chi tiết

**⚠️ Đây là crate sửa ÍT NHẤT** — chỉ 20% CRITICAL được fix. Crate
này chứa logic detection chính nên impact lớn lên Security
Effectiveness rubric (40/120) và Intelligence rubric (20/120).

## Status table

| ID | Title | Status | Evidence |
|---|---|---|---|
| F-CRITICAL-001 | RiskTracker keyed by IpAddr only | **NOT_FIXED** | `risk/tracker.rs:74` vẫn `DashMap<IpAddr, Slot>`; mutators take `ip: IpAddr` (lines 146, 152, 172, 198) — không có device_fp / session axes. |
| F-CRITICAL-002 | Rate limit per-IP only | **NOT_FIXED** | `rate_limit/ip_limiter.rs:90` vẫn `DashMap<IpAddr, VecDeque<Instant>>`; `consume(ip: IpAddr)` line 123. Không có session/user limiter. |
| F-CRITICAL-003 | Velocity cross-endpoint sequence | **NOT_FIXED** | `velocity.rs` whole file vẫn là generic per-discriminator sliding-window counter. Zero references to Login/OTP/Deposit/Withdraw/sequence. |
| F-CRITICAL-004 | Behavior missing 3/4 signals | **NOT_FIXED** | `behavior.rs:49-55` `observe()` signature: `key, path, is_error, has_cookie` — không có `referer`, không có `tier`. Vẫn thiếu: zero-depth, missing-Referer, absolute <50ms inter-request check. |
| F-CRITICAL-005 | DDoS no per-tier no fail-close | **PARTIAL** | `aegis-core::config::DdosConfig` có `tier_overrides: HashMap` (test `ddos.rs:542`), nhưng `DdosDetector::check(state, ip)` (line 209) và `DdosRuntime::check(peer_ip)` (line 136) vẫn ignore tier — chỉ đọc `cfg.per_ip_limit`. Không có fail-close branching. |
| F-CRITICAL-006 | Risk thresholds 30/70 | **FIXED** | `risk/mod.rs:78-84` dùng 30/70 boundaries. `aegis-core/config.rs:2217-2218` `RiskThresholds::default` → `challenge_at: 30, block_at: 70`. |
| F-CRITICAL-007 | Canary doesn't block IP | **NOT_FIXED** | `risk/mod.rs:24-27,44` vẫn hardcoded `canary_tags: vec!["recon_path"]`. Scoring path lines 60-65 gọi `state.add_risk(...)` set max score nhưng KHÔNG gọi `state.auto_block(ip, ttl)`. `aegis-core::config::canary_paths` (config.rs:2063) exists nhưng không consumed trong aegis-security hoặc aegis-proxy. |
| F-CRITICAL-008 | Pipeline::inbound bypasses security | **NOT_FIXED** | `pipeline.rs:170-178` `inbound()` chỉ gọi `self.rules.snapshot()` + `rules::evaluate(...)`. Không detector chain, không risk tracker, không canary check. Comment 150-169 acknowledge bypass intentional. |
| F-CRITICAL-009 | Rule scope enum missing 4/6 | **FIXED** | `aegis-core/config.rs:1985-2000` `RlScope` có tất cả 6 variants: Global, Route, Tier, RoutePattern, Ip, UserSession, DeviceFingerprint. |
| F-CRITICAL-010 | No same-device-different-IP | **NOT_FIXED** | `fingerprint/mod.rs` là single `device_id()` hash function — không DashMap, không reverse map device→Vec<IpAddr>, không tracker state. |
| F-CRITICAL-011 | JA4 sorts + no GREASE strip | **NOT_FIXED** | `fingerprint/ja4.rs:57-60` vẫn `sorted_ciphers.sort_unstable()` và `sorted_exts.sort_unstable()`. Không GREASE filter (grep `GREASE`/`0x0a0a`/`0x2a2a` → 0 matches). |
| F-CRITICAL-012 | header_injection hardcoded keywords | **FIXED** | `detectors/header_injection.rs:132-161` — `evil/attacker/malicious/phish` đã removed. Comment cite F-CRITICAL-012 fix; replace bằng structural needles. Tests `xfh_with_evil_keyword_flagged` removed. **§9 disqualification risk resolved**. |
| F-CRITICAL-013 | response_filter misses §5.7 | **NOT_FIXED** | `response_filter.rs:5` vẫn `const STRIP_HEADERS: &[&str] = &["server", "x-powered-by"];`. Không x-debug/x-internal prefix scanner. Không 5xx body size cap. Không JSON field-aware redaction. |
| F-CRITICAL-014 | brute_force per-IP POST-only | **NOT_FIXED** | `detectors/brute_force.rs:39` vẫn `Mutex<HashMap<IpAddr, Vec<Instant>>>`. `inspect()` line 88 gate on `method != POST` và `peer.ip()` only — không có per-user / per-device axes. |
| F-CRITICAL-015 | bots.rs ignores JA4 no ASN | **NOT_FIXED** | `bots.rs:17` `BotSignals.ja4_fingerprint` field exists nhưng `classify()` (lines 72-115) không đọc. Không có `asn` field on `BotSignals`. Không có ladder logic. |

## §9 DISQUALIFICATION RISK CHECK

✅ **F-CRITICAL-012 đã FIXED**. `evil/attacker/malicious/phish` hardcoded keyword list đã được replace bằng structural URI-scheme + HTML-metachar needles. §9 immediate-disqualification risk **đã đóng**.

## Cần fix tiếp — 11 finding NOT_FIXED + 1 PARTIAL

### Priority 1: Round-1 Pass/Fail risk

#### F-CRITICAL-001 — RiskTracker key shape (§5.5)

```diff
 pub struct RiskTracker {
-    map: DashMap<IpAddr, Slot>,
+    map: DashMap<RiskKey, Slot>,
     ...
 }
```

Sửa hết mọi mutator: `record_malicious`, `record_clean`, `level`, `top`, `snapshot_wire`, strike gate.

#### F-CRITICAL-002 — Rate limit per-session (§5.2 #02)

Hai option:
- Option A: Composite limiter (per-IP + per-session + per-user) parallel
- Option B: Generic `RateKey` enum

```rust
pub enum RateKey {
    Ip(IpAddr),
    Session(String),
    User(String),
    Device(String),
}
```

#### F-CRITICAL-004 — Behavioral signals (§5.2 #09)

Thêm 3 signal:

```diff
 pub fn observe(
     &self,
     ip: IpAddr,
     path: &str,
+    referer: Option<&str>,
+    tier: Tier,
     ...
 ) -> Vec<Anomaly> {
     ...
+    // Zero-depth session: first request to CRITICAL tier
+    if session.paths.is_empty() && tier == Tier::Critical {
+        out.push(Anomaly::ZeroDepthSession { path: path.into() });
+    }
+    // Missing Referer on CRITICAL/HIGH
+    if matches!(tier, Tier::Critical | Tier::High) && referer.is_none() {
+        out.push(Anomaly::MissingReferer);
+    }
+    // <50ms inter-request (absolute)
+    if let Some(last) = session.last_event {
+        if now.duration_since(last) < Duration::from_millis(50) {
+            out.push(Anomaly::TooFastInterRequest);
+        }
+    }
+    session.last_event = Some(now);
     ...
 }
```

#### F-CRITICAL-007 — Canary auto_block (§5.5)

```rust
// risk/mod.rs hoặc thêm hook vào pipeline
if cfg.canary_paths.iter().any(|p| path_matches(p, req.uri().path())) {
    risk_tracker.set_score_at(&ctx.key(), u32::MAX);
    state.auto_block(ip, cfg.canary_block_ttl).await?;
    return Ok(build_403_response("canary hit"));
}
```

Đọc `cfg.canary_paths` từ aegis-core (đã có) thay vì tag match `"recon_path"`.

### Priority 2: Attack Battle scenarios

#### F-CRITICAL-003 — Velocity sequence engine (§5.2 #10, Attack Battle 06)

Net-new module ~300-400 LoC. Tracker per-user events, detect:
- Login→OTP→Deposit trong N giây
- Withdrawal sau Deposit trong M giây
- Rapid limit-change pattern

#### F-CRITICAL-010 — Same-device-different-IP detection (§5.2 #08, Attack Battle 04)

```rust
pub struct DeviceIpTracker {
    map: DashMap<String /* device_id */, VecDeque<(IpAddr, Instant)>>,
}

pub fn observe(&self, device_id: &str, ip: IpAddr, now: Instant) -> Option<RotationSignal> {
    // Count distinct IPs per device in window
    // → emit signal if >= threshold
}
```

#### F-CRITICAL-011 — JA4 sort + GREASE (§5.2 #08)

```diff
+fn is_grease(v: u16) -> bool {
+    (v & 0x0F0F) == 0x0A0A
+}
+
-let mut sorted_ciphers: Vec<u16> = cipher_suites.to_vec();
-sorted_ciphers.sort_unstable();
+let ciphers: Vec<u16> = cipher_suites.iter()
+    .copied()
+    .filter(|c| !is_grease(*c))
+    .collect();
```

Bỏ `sort_unstable()` — JA4 spec yêu cầu preserve observed order.

### Priority 3: Detection coverage

#### F-CRITICAL-013 — response_filter §5.7

```rust
const STRIP_HEADERS_EXACT: &[&str] = &[
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-runtime", "x-version", "x-generator", "x-php-version",
];
const STRIP_HEADERS_PREFIX: &[&str] = &["x-debug", "x-internal", "x-trace"];

// + 5xx body size cap
// + JSON field-aware masking (card_number, bank_account)
```

#### F-CRITICAL-014 — brute_force per-user/device (§5.3)

Tracker 3-axis: per-user (classic) + per-IP-distinct-users (spraying) + per-device (distributed credential stuffing).

#### F-CRITICAL-015 — bots.rs JA4 + ASN + ladder (§5.2 #05+#08+#04)

Đọc `ja4_fingerprint` field; thêm `asn` field + `asn_classification`; multi-signal classifier với weighted score; challenge ladder (JS → CAPTCHA → Block).

### Architecture

#### F-CRITICAL-008 — Pipeline::inbound consolidation

`pipeline.rs:170-178` chỉ chạy rule engine. Hoặc:
- Wire full pipeline (canary → blacklist → rate-limit → detectors → risk → rules)
- Hoặc xóa trait nếu không dùng → tránh consumer hiểu nhầm

#### F-CRITICAL-005 — DDoS tier-aware (§5.2 #03 + §5.8)

Config đã có `tier_overrides` (aegis-core fixed F-CRITICAL-008). Cần sửa detector:

```diff
-pub fn check(&self, ip: IpAddr) -> Decision {
+pub fn check(&self, ip: IpAddr, tier: Tier) -> Decision {
     let limit = self.cfg.tier_overrides
         .get(&tier)
         .unwrap_or(&self.cfg.default);
     // + fail-close branching theo tier
 }
```

## Đánh giá

aegis-security fix **kém nhất** — chỉ 3/15 FIXED. Crate này chứa core attack-detection logic; impact lớn lên 2 rubric quan trọng nhất:
- Security Effectiveness 40/120 — bị ảnh hưởng bởi response_filter, brute_force, header_injection (fixed), behavior, velocity
- Intelligence & Adaptiveness 20/120 — bị ảnh hưởng bởi RiskTracker key shape, canary, device-IP map, JA4 stability, bots ladder

Recommend: ưu tiên fix aegis-security trước proxy H3 / control compliance — leverage cao nhất cho Hackathon scoring.
