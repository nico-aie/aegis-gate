---
id: 2026-05-18-next-steps
date: 2026-05-18T00:00Z
purpose: Roadmap fix tiếp theo, sắp xếp theo (a) Round-1 gate, (b) effort × impact, (c) Attack Battle scenario
---

# Roadmap fix tiếp theo

Hiện trạng: 60% CRITICAL fixed (36/60). 25% chưa fix (15). 15% partial (9).

## 📅 Sprint 1 — Round-1 Pass/Fail risk (BẮT BUỘC trước thi)

Ba bug này gây Round-1 fail trực tiếp nếu BTC test:

### 1.1 — proxy F-CRITICAL-001 H3 bypass (~80 LoC, ~4h)

`listener/http3.rs:290` → đổi gọi `data_plane::handle_data_request` thay `crate::proxy::handle_request`. Capture `connection.remote_address()` cho §10.

Xem chi tiết: [03-proxy-full-audit-verification.md](03-proxy-full-audit-verification.md)

### 1.2 — aegis-core F-CRITICAL-003 AuditEvent thiếu fields (~50 LoC + migration, ~3h)

`audit.rs` struct thêm `method`, `path`, `mode` fields. Migration touches ~10-15 populator call sites trong aegis-proxy/admin_mutate.rs, accept.rs, admin_dispatch.rs.

Xem chi tiết: [01-aegis-core-verification.md](01-aegis-core-verification.md)

### 1.3 — aegis-control F-CRITICAL-002 Compliance modes wire (~100 LoC, ~3h)

`api/detectors.rs::COMPLIANCE_PINNED` populate per mode + wire `cfg.compliance.min_tls_version` + `disallow_algorithms` vào TLS stack builder.

Xem chi tiết: [04-aegis-control-verification.md](04-aegis-control-verification.md)

**Sprint 1 effort tổng**: ~230 LoC, ~10h dev + test.

---

## 📅 Sprint 2 — Quick wins (high impact, low LoC)

Các fix nhỏ nhưng impact lớn lên scoring:

### 2.1 — security F-CRITICAL-011 JA4 sort + GREASE (~15 LoC, ~1h)

`fingerprint/ja4.rs:57-60` — bỏ `sort_unstable()` + thêm GREASE filter:

```rust
fn is_grease(v: u16) -> bool { (v & 0x0F0F) == 0x0A0A }
let ciphers: Vec<_> = cipher_suites.iter()
    .copied()
    .filter(|c| !is_grease(*c))
    .collect();
// KHÔNG sort
```

**Impact**: §5.2 #08 Chrome stable device ID; unlock F-CRITICAL-010 same-device-IP fix.

### 2.2 — security F-CRITICAL-007 Canary auto_block (~30 LoC, ~2h)

`risk/mod.rs` đọc `cfg.canary_paths` (đã có ở aegis-core) + gọi `state.auto_block(ip, ttl)` khi match.

**Impact**: §5.5 + Attack Battle scenario 08 Canary/Recon.

### 2.3 — security F-CRITICAL-004 Behavioral signals 3/4 thiếu (~50 LoC, ~3h)

`behavior.rs::observe()` thêm `referer` + `tier` params; thêm 3 signal:
- Zero-depth session (first request to CRITICAL tier)
- Missing Referer on CRITICAL/HIGH
- Inter-request <50ms (absolute gap)

**Impact**: §5.2 #09 + Attack Battle scenario 05 Behavioral Bypass.

### 2.4 — aegis-core F-CRITICAL-006 Action enum rename RateLimited → RateLimit (~30 LoC, ~1h)

`decision.rs:14` rename variant. Update mọi `match` arm trong consumers.

**Impact**: §5.1 wire-format compliance.

### 2.5 — security F-CRITICAL-013 response_filter §5.7 (~100 LoC, ~3h)

`response_filter.rs` mở rộng `STRIP_HEADERS` + thêm prefix scanner cho `x-debug-*`, `x-internal-*`; thêm 5xx body size cap; thêm JSON field-aware redaction.

**Impact**: §5.7 mandatory; Security rubric.

**Sprint 2 effort**: ~225 LoC, ~10h dev + test. Tổng impact rubric: +5-7 điểm Security/Intelligence.

---

## 📅 Sprint 3 — Major Security rubric items

Fix bigger items, high impact on Security Effectiveness 40/120:

### 3.1 — security F-CRITICAL-001 RiskTracker key shape (~150 LoC, ~6h)

`risk/tracker.rs:74` đổi `DashMap<IpAddr, Slot>` → `DashMap<RiskKey, Slot>`. Update tất cả mutators (record_malicious, record_clean, level, top, snapshot_wire, strike gate). Plumb RiskKey từ RequestCtx.

**Impact**: Intelligence rubric headline + unlock F-CRITICAL-010.

### 3.2 — security F-CRITICAL-002 Rate limit per-session (~150 LoC, ~6h)

`rate_limit/ip_limiter.rs` → composite limiter (IP + session + user). Plumb session_id từ context.

**Impact**: §5.2 #02 + Attack Battle scenario 02.

### 3.3 — security F-CRITICAL-014 brute_force 3-axis (~200 LoC, ~6h)

`brute_force.rs` → 3-axis tracker (per-user / per-IP-distinct-users / per-device). Body-parse for `username`. Method allowlist.

**Impact**: §5.3 + Attack Battle scenario 02.

### 3.4 — security F-CRITICAL-015 bots.rs JA4+ASN+ladder (~200 LoC, ~6h)

`bots.rs::classify()` đọc `ja4_fingerprint`; thêm `asn` field + classifier; multi-signal scorer; challenge ladder.

**Impact**: §5.2 #05+#08+#04.

### 3.5 — security F-CRITICAL-005 DDoS tier-aware (~50 LoC, ~2h)

`ddos.rs::check()` đọc `cfg.tier_overrides` (đã có ở config). Plumb tier param. Add fail-close branching.

**Impact**: §5.2 #03 + §5.8.

**Sprint 3 effort**: ~750 LoC, ~26h. Tổng impact rubric: +10-12 điểm Security/Intelligence.

---

## 📅 Sprint 4 — Attack Battle scenarios

### 4.1 — security F-CRITICAL-003 Velocity sequence engine (~400 LoC, ~12h)

Net-new module. Login→OTP→Deposit / withdraw-after-deposit / rapid-limit-change.

**Impact**: Attack Battle scenario 06 Transaction Fraud.

### 4.2 — security F-CRITICAL-010 Same-device-different-IP map (~120 LoC, ~4h)

Net-new `DeviceIpTracker` (sau khi F-CRITICAL-001 fixed).

**Impact**: Attack Battle scenario 04.

**Sprint 4 effort**: ~520 LoC, ~16h.

---

## 📅 Sprint 5 — Architecture + Schema cleanup

### 5.1 — security F-CRITICAL-008 Pipeline::inbound consolidation (~100 LoC, ~3h)

`pipeline.rs::inbound()` wire full pipeline OR xóa trait.

### 5.2 — proxy F-CRITICAL-006 Xóa dead modules quota/dr/traffic (~50 LoC, ~1h)

Xóa hoặc wire. Recommend xóa.

### 5.3 — aegis-core F-CRITICAL-004 audit `action: String` → enum (~30 + migration, ~3h)

### 5.4 — aegis-core F-CRITICAL-013 `deny_unknown_fields` mở rộng (~20 LoC, ~1h)

### 5.5 — proxy F-CRITICAL-010 WS Sec-WebSocket-Accept verify (~30 LoC, ~2h)

### 5.6 — control F-CRITICAL-014 Rollback dispatcher còn thiếu actions (~300 LoC, ~10h)

### 5.7 — PARTIAL items aegis-core type refactor (~50 LoC + migration, ~4h)

**Sprint 5 effort**: ~580 LoC, ~24h.

---

## 📊 Tổng hợp

| Sprint | Title | LoC | Hours | Priority |
|---|---|---:|---:|---|
| 1 | Round-1 Pass/Fail risk | 230 | 10 | **MUST** |
| 2 | Quick wins | 225 | 10 | **MUST** (cao impact / cheap) |
| 3 | Security rubric major | 750 | 26 | Highly recommended |
| 4 | Attack Battle scenarios | 520 | 16 | Recommended |
| 5 | Architecture + cleanup | 580 | 24 | Nice-to-have |
| **Tổng** | | **2305 LoC** | **~86h** | |

## Hackathon scoring estimate

| State | Security 40 | Performance 20 | Intelligence 20 | Architecture 15 | Extensibility 10 | Dashboard 10 | Deploy 5 | Tổng /120 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Hiện tại (60% FIXED) | 25 | 17 | 10 | 9 | 7 | 9 | 4 | **81 (67.5%)** |
| Sau Sprint 1 | 27 | 17 | 11 | 11 | 7 | 9 | 4 | **86 (71.7%)** |
| Sau Sprint 1+2 | 32 | 17 | 14 | 11 | 7 | 9 | 4 | **94 (78.3%)** |
| Sau Sprint 1+2+3 | 37 | 17 | 17 | 11 | 8 | 9 | 4 | **103 (85.8%)** |
| Sau Sprint 1+2+3+4 | 38 | 17 | 19 | 11 | 8 | 9 | 4 | **106 (88.3%)** |
| Sau cả 5 Sprint | 39 | 17 | 19 | 14 | 9 | 9 | 5 | **112 (93.3%)** |

→ Hiện tại đã ở 67.5%; ưu tiên Sprint 1+2 (20h work) để lên 78%; nếu có thêm thời gian, Sprint 3 cho 86%.

## Ghi chú quan trọng

1. **§9 disqualification risk đã đóng**: F-CRITICAL-012 (hardcoded `evil/attacker` keywords) đã được fix. Không còn risk "loại ngay".

2. **AI detector**: hiện đã bật được (per session trước). AI có thể cover một số gap (Shellshock 67%→100%, XXE 47%→100%) nhưng KHÔNG thay thế được fix gốc — vì AI hay tăng FP trên Normal traffic, cần tune confidence_threshold.

3. **Round-1 dashboard auth chain** đã 6/7 layer fixed (chỉ thiếu compliance modes). Dashboard rubric (10/120) đã đạt ~90%.

4. **aegis-control quality cao**: 89% FIXED, code có F-CRITICAL-NNN comment dễ audit. Đây là crate đáng khen.

5. **aegis-security cần ưu tiên nhất**: 80% chưa fix; chứa core detection logic; impact 60/120 rubric (Security + Intelligence). Ưu tiên đầu tư.
