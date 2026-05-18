---
id: 2026-05-18-identity-verification
date: 2026-05-18T00:00Z
area: Identity / behavior / risk
spec_ref: §5.2 #04 #05 #08 #09 #10 + §5.5
---

# Identity detectors — Fingerprint + Behavior + Velocity + Bots + Risk + Challenge

## 1. Device Fingerprint — §5.2 #08 — **PARTIAL**

### Spec mandate

> Compute device ID stable per-device, **deterministic** across requests, **không bao gồm GREASE bytes** (JA4 spec yêu cầu strip), **không sort cipher** (JA4 raw giữ nguyên order từ ClientHello). Output: 1 device ID nhất quán dù IP thay đổi.

### Code under test

[crates/aegis-security/src/fingerprint/ja4.rs:57-60](../../../../crates/aegis-security/src/fingerprint/ja4.rs#L57)

```rust
// Sort cipher suites and extensions for stability.
let mut sorted_ciphers: Vec<u16> = cipher_suites.to_vec();
sorted_ciphers.sort_unstable();         // <-- spec JA4 KHÔNG sort
let mut sorted_exts: Vec<u16> = extensions.to_vec();
sorted_exts.sort_unstable();
```

### A) Spec compliance — **PARTIAL**

- ✅ Deterministic + per-device aggregation: `fingerprint/mod.rs:10-31` composite JA3 + JA4 + H/2 + UA + header order qua keyed blake3.
- ✅ Salted variant: `compute_salted()` ở ja4.rs:82-94 dùng keyed blake3 per-device.
- ❌ **Sort ciphers BREAK JA4 spec**: spec JA4 yêu cầu cipher hex string theo thứ tự xuất hiện trong ClientHello (giữ TLS ordering — vì client TLS library order là 1 signal). Sort xóa signal này.
- ❌ **Không có GREASE filter**: JA4 spec yêu cầu strip values match `0x0A0A, 0x1A1A, ...` (mask `0x0F0F == 0x0A0A`). Code hiện tại để GREASE bytes vào hash → khi Chrome rotate GREASE (mỗi connection 1 giá trị mới), JA4 thay đổi → mất tính ổn định per-device.

### B) Dashboard config — N/A

- Stateless fingerprint, không có config knob.

### C) Hot-reload — N/A

### D) §9 — **PASS**

### Verdict

PARTIAL. Implementation đếm được fingerprint, NHƯNG kết quả không khớp JA4 reference. Hệ quả: Chrome stable rotate GREASE → 1 device cho ra N device IDs → §5.2 #08 fail (không nhận diện được device).

### Fix outline (~15 LoC, ~1h)

Xem Sprint 2.1 trong [NEXT-STEPS.md](../2026-05-18-fix-verification/NEXT-STEPS.md#21--security-f-critical-011-ja4-sort--grease-15-loc-1h):

```rust
fn is_grease(v: u16) -> bool { (v & 0x0F0F) == 0x0A0A }
let ciphers: Vec<_> = cipher_suites.iter()
    .copied()
    .filter(|c| !is_grease(*c))
    .collect();
// KHÔNG sort — giữ raw order
```

---

## 2. Behavioral Anomaly — §5.2 #09 — **PARTIAL**

### Spec mandate

> Phải observe ≥4 trong 6 signal: (1) request frequency, (2) path entropy, (3) timing jitter, (4) zero-depth session, (5) missing Referer on CRITICAL, (6) inter-request <50ms.

### Code under test

[crates/aegis-security/src/behavior.rs:29-144](../../../../crates/aegis-security/src/behavior.rs#L29)

### A) Spec compliance — **PARTIAL** (4/6 signal)

- ✅ Request frequency (>50): line 89-95 `behavior_high_rate`.
- ✅ Path entropy (>30 unique, diversity >0.8): line 98-108 `behavior_high_diversity`.
- ✅ Timing jitter (CoV <0.05): line 122-132 `behavior_low_jitter`.
- ✅ Error ratio (>50% failed): line 110-120 `behavior_high_errors`.
- ❌ Zero-depth session (first request to CRITICAL tier): **chưa có**.
- ❌ Missing Referer on CRITICAL/HIGH: **chưa có**.
- ❌ Inter-request <50ms absolute gap: **chưa có** (chỉ có CoV jitter).

Note: spec liệt kê 6 signal, code có 4 (đếm cookie thay vì zero-depth — không khớp).

### B) Dashboard config — **FAIL**

- Threshold hardcoded inline tại line 89, 99, 111, 123, 135. Không có `BehaviorConfig` struct, không có endpoint.

### C) Hot-reload — **FAIL**

Recompile required.

### D) §9 — **PASS**

### Verdict

PARTIAL. Đếm được 4 signal nhưng thiếu các signal mà spec yêu cầu cho tier CRITICAL (Referer + zero-depth).

### Fix outline (~50 LoC, ~3h) — Sprint 2.3

```rust
pub fn observe(&self, sid: &str, peer_ip: IpAddr, path: &str,
               referer: Option<&str>, tier: Tier, was_error: bool) -> Vec<Signal> {
    // ... existing signals ...

    // SIGNAL 5: Zero-depth on CRITICAL
    if tier == Tier::Critical && session_request_count == 1 {
        sigs.push(Signal { score: 30, tag: "behavior_zero_depth_critical", ... });
    }

    // SIGNAL 6: Missing Referer on CRITICAL/HIGH
    if matches!(tier, Tier::Critical | Tier::High) && referer.is_none() {
        sigs.push(Signal { score: 20, tag: "behavior_no_referer", ... });
    }

    // SIGNAL 7: inter-request <50ms
    if let Some(last) = self.last_seen(sid) {
        if now.duration_since(last) < Duration::from_millis(50) {
            sigs.push(Signal { score: 35, tag: "behavior_burst", ... });
        }
    }
}
```

---

## 3. Transaction Velocity — §5.2 #10 — **PARTIAL**

### Spec mandate

> Detect: login→OTP→deposit trong <Ns. Withdraw-after-deposit pattern. Rapid-limit-change. Operator config được sequence + window per scenario.

### Code under test

[crates/aegis-security/src/velocity.rs:5-51](../../../../crates/aegis-security/src/velocity.rs#L5)

### A) Spec compliance — **PARTIAL**

- ✅ `VelocityRule { action_name, limit, window_s, risk_delta }` struct (line 7-16).
- ✅ Async `check()` increment counter qua `StateBackend::incr_window` (line 30-51).
- ✅ Multi-user isolation test (line 160-187).
- ⚠️ **Sequence engine vắng mặt**: code hiện chỉ counter per single action (e.g. "deposit"). Không có logic chuỗi `login → OTP → deposit` theo trình tự trong window. Spec yêu cầu detect sequence pattern, không phải đơn lẻ.

### B) Dashboard config — **PARTIAL**

- `VelocityRule` instances được khai báo trong policy file, không expose qua `DetectorsConfig`. Không endpoint PUT `/api/velocity/rules`.

### C) Hot-reload — **UNKNOWN**

- VelocityRule không wrap ArcSwap. Restart proxy required để load new rules.

### D) §9 — **PASS**

### Verdict

PARTIAL. Counter engine hoạt động, sequence engine chưa có. Cần làm Sprint 4.1 (~400 LoC, ~12h).

---

## 4. Bot/Relay/Headless — §5.2 #05 — **PARTIAL**

### Spec mandate

> Combine UA + **JA4 fingerprint** + **ASN** + ladder challenge để classify bot. Multi-signal scorer (không chỉ UA contains-match).

### Code under test

[crates/aegis-security/src/bots.rs:55-116](../../../../crates/aegis-security/src/bots.rs#L55)

### A) Spec compliance — **PARTIAL**

- ✅ Multi-signal struct: `BotSignals { ja4_fingerprint, h2_fingerprint, user_agent, has_cookies, has_js_challenge_pass, failed_challenges, reverse_dns }` (line 16-24).
- ✅ KnownBad UA patterns: sqlmap/nikto/nmap → line 73-80.
- ✅ GoodBot reverse DNS check: Googlebot/Bingbot/Yandex → line 83-91.
- ❌ **`ja4_fingerprint` field declared nhưng `classify()` không bao giờ đọc**: grep `ja4_fingerprint` trong `bots.rs::classify()` — chỉ thấy ở struct definition, không thấy ở logic. Multi-signal scorer chưa wire JA4.
- ❌ **ASN field hoàn toàn vắng mặt**: `BotSignals` không có `asn: Option<u32>`. Spec yêu cầu ASN-based scoring (e.g. cloud ASN AS14618 AWS → bump bot score).
- ⚠️ Ladder challenge: integrate qua `challenge/ladder.rs` — OK, nhưng `bots.rs::classify()` return `BotClass` enum, không tích hợp trực tiếp với ladder.

### B) Dashboard config — **PARTIAL**

- UA blocklist hardcoded tại bots.rs:42-53. Không edit được qua dashboard.

### C) Hot-reload — **FAIL** (UA list compile-time).

### D) §9 — **PASS** (sqlmap/nikto là legitimate detection, không phải benchmark-rigging keyword).

### Verdict

PARTIAL. UA + reverse DNS hoạt động, JA4 + ASN không wire. Round-1 score §5.2 #05 sẽ mất điểm.

### Fix outline (~200 LoC, ~6h) — Sprint 3.4

---

## 5. Risk Engine — §5.5 — **PARTIAL** (FAIL spec key shape, PASS threshold)

### Spec mandate

> Key by **{IP + device_fp + session}** composite. Thresholds 30/70 (Allow/Challenge/Block). Strike-block sau N lần block accumulate (lifetime counter). Canary auto-block. Trust recovery (score decay).

### Code under test

[crates/aegis-security/src/risk/tracker.rs:67-87](../../../../crates/aegis-security/src/risk/tracker.rs#L67)

```rust
pub struct RiskTracker {
    inner: Arc<TrackerInner>,
}

struct TrackerInner {
    map: DashMap<IpAddr, Slot>,            // <-- chỉ IP, KHÔNG composite
    thresholds: arc_swap::ArcSwap<RiskThresholds>,
    trust: TrustRecoveryConfig,
    strikes: arc_swap::ArcSwap<StrikeConfig>,
}
```

### A) Spec compliance — **PARTIAL** (FAIL key shape, PASS các phần khác)

- ❌ **Key shape: chỉ `IpAddr`, không phải `{IP + device_fp + session}`**. Spec mandate composite. Hệ quả: 2 attacker chia sẻ NAT public IP đụng nhau; cùng 1 attacker xoay device qua VPN exit không bị track tiếp.
- ✅ Thresholds 30/70: `challenge_at: 30`, `block_at: 70` defaults tại config.rs:2194-2207.
- ✅ Strike counter lifetime: `Slot::strikes` (line 92), increment trong `record_malicious()` (line 164), strike-block gate tại `is_strike_blocked()` (line 244-252).
- ✅ Trust recovery: `record_clean()` (line 172-187) apply decay theo time elapsed.
- ✅ Per-tier thresholds via `level_with(ip, challenge_at, block_at)` (line 222-236).
- ⚠️ Canary auto-block: schema `cfg.canary_paths` tồn tại trong aegis-core, nhưng `risk/mod.rs` không gọi `state.auto_block(ip, ttl)` khi path match canary.

### B) Dashboard config — **PASS**

- `GET /api/risk` top-N + `GET /api/risk/{ip}` snapshot + `PUT /api/risk/{ip}/reset` audit-mutated.
- `PUT /api/risk/thresholds` swap ArcSwap via `set_thresholds()` (line 133-135).

### C) Hot-reload — **PASS**

- ArcSwap pattern, sub-ms.

### D) §9 — **PASS**

### Verdict

PARTIAL. Engine hoạt động tốt với threshold + strike + decay, NHƯNG key shape là gap §5.5 chính. Đây là F-CRITICAL-001 từ audit 2026-05-17 — vẫn NOT_FIXED.

### Fix outline (~150 LoC, ~6h) — Sprint 3.1

```rust
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct RiskKey {
    pub ip: IpAddr,
    pub device_fp: Option<DeviceId>,
    pub session: Option<String>,
}

struct TrackerInner {
    map: DashMap<RiskKey, Slot>,  // <-- composite
    // ...
}
```

Plus update mọi mutator + call site truyền `RiskKey` từ `RequestCtx`.

---

## 6. Challenge Engine — §5.2 #04 — **PASS**

### Spec mandate

> Ladder CAPTCHA → PoW → JS theo risk score. Risk-aware escalation. PoW stateless issuance + verify replay-protected.

### Code under test

- Ladder: [challenge/ladder.rs:24-88](../../../../crates/aegis-security/src/challenge/ladder.rs#L24)
- PoW: [challenge/pow.rs:100-150](../../../../crates/aegis-security/src/challenge/pow.rs#L100)

### A) Spec compliance — **PASS**

- ✅ `next_level(risk, human_conf, bot, tier)` escalation logic line 24-52.
- ✅ Tier-aware escalation:
  - Critical: Js@0-29, PoW@30-49, Captcha@50-69, Block@70+
  - High: Js@0-39, PoW@40-59, Captcha@60-79, Block@80+
  - Medium: Js@0-49, PoW@50-69, Captcha@70-89, Block@90+
  - Low: Js@0-59, PoW@60-79, Captcha@80-94, Block@95+
- ✅ Human-confidence override (line 41-43).
- ✅ Verified bot leniency (line 31-33).
- ✅ PoW stateless: `pow.rs:106-116` issuance, line 123-150 verify với replay-cache.

### B) Dashboard config — N/A

- Ladder thresholds hardcoded; spec không yêu cầu tune qua dashboard cho hackathon (acceptable theo finding M-30).

### C) Hot-reload — N/A

### D) §9 — **PASS**

### Verdict

PASS. Challenge engine là phần làm tốt nhất trong cụm identity.

---

## Summary Identity

| Detector | Spec | Dashboard | Hot-reload | Verdict |
|---|---|---|---|---|
| Device Fingerprint | PARTIAL (sort + no GREASE) | N/A | N/A | **PARTIAL** |
| Behavioral | PARTIAL (4/6 signal) | FAIL hardcoded | FAIL | **PARTIAL** |
| Velocity | PARTIAL (no sequence engine) | PARTIAL | UNKNOWN | **PARTIAL** |
| Bots | PARTIAL (no JA4, no ASN) | PARTIAL hardcoded UA | FAIL | **PARTIAL** |
| Risk Engine | PARTIAL (per-IP, spec yêu cầu composite) | PASS | PASS | **PARTIAL** |
| Challenge | PASS | N/A | N/A | **PASS** |
