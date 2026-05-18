---
id: 2026-05-18-still-broken-critical
date: 2026-05-18T00:00Z
purpose: Danh sách 15 CRITICAL bug CHƯA FIX, ưu tiên theo impact Hackathon scoring
---

# 15 CRITICAL findings CHƯA FIX — ưu tiên theo Hackathon scoring impact

Sắp xếp theo: (a) Round-1 Pass/Fail risk, (b) rubric scoring impact, (c) effort vs reward.

---

## 🚨 Tier 1: Round-1 Pass/Fail risk (fix NGAY)

### 1. proxy F-CRITICAL-001 — H3 bypass toàn bộ security pipeline

**File**: `crates/aegis-proxy/src/listener/http3.rs:290`

```rust
// HIỆN TẠI (sai):
let resp = match crate::proxy::handle_request(hyper_req, ctx).await { ... };
```

**Fix**:
```rust
let peer = connection.remote_address();  // §10 identity
// ... extract body với cap ...
let (resp, decision) = data_plane::handle_data_request(hyper_req, peer, ...).await;
let resp = stamp_interop_response(resp, decision, ...);
```

**Impact**: §5 (6 header missing), §6 (audit không emit), §10 (no peer identity), tất cả detector/rate-limit/risk skip trên QUIC. ~80 LoC fix.

### 2. aegis-core F-CRITICAL-003 — AuditEvent thiếu `method`/`path`/`mode`

**File**: `crates/aegis-core/src/audit.rs`

Hiện tại struct thiếu 3 field §6 mandatory. Author tự ghi trong docstring "Still outstanding".

**Fix**:
```rust
pub struct AuditEvent {
    // ... existing fields ...
    pub method: String,        // §6 mandatory
    pub path: String,          // §6 mandatory (INCLUDING query string)
    pub mode: AuditMode,       // §6 mandatory (enforce | log_only)
}
```

Plus migration: ~10-15 populator call sites.

**Impact**: Mọi audit event emit ra §6-non-compliant → benchmark phase 2 fail correlation.

### 3. aegis-control F-CRITICAL-002 — Compliance modes theater

**File**: `crates/aegis-control/src/api/detectors.rs:113`

```rust
const COMPLIANCE_PINNED: &[DetectorClass] = &[];   // empty → no-op
```

Plus `grep min_tls_version` trong aegis-proxy: 0 hits → TLS stack không đọc compliance config.

**Fix**: Populate `COMPLIANCE_PINNED` per mode + wire TLS profile fields.

**Impact**: Round-1 "Tính hiệu lực" — operator bật "FIPS mode" trên dashboard nhưng không có effect thực. BTC verify bằng real traffic → "không đạt".

---

## 🟠 Tier 2: Rubric Security Effectiveness 40/120 (high impact)

### 4. security F-CRITICAL-001 — RiskTracker keyed by IpAddr only

**File**: `crates/aegis-security/src/risk/tracker.rs:74`

```rust
map: DashMap<IpAddr, Slot>,  // ← spec yêu cầu {IP + device_fp + session}
```

**Fix**: Đổi key thành `RiskKey` (đã có trong aegis-core). Migration touches tất cả mutators (record_malicious, record_clean, level, top, snapshot_wire, strike gate).

**Impact**: §5.5 Intelligence rubric headline; cũng làm cho F-CRITICAL-010 (same-device-IP detection) hoạt động được sau khi fix.

### 5. security F-CRITICAL-002 — Rate limit per-IP only

**File**: `crates/aegis-security/src/rate_limit/ip_limiter.rs:90`

```rust
map: DashMap<IpAddr, VecDeque<Instant>>,  // ← cần thêm session/user axis
```

**Fix**: Composite limiter (parallel IP + session + user limiters) hoặc generic `RateKey` enum.

**Impact**: §5.2 #02 violation. Distributed credential stuffing bypass dễ — Attack Battle scenario 02.

### 6. security F-CRITICAL-007 — Canary không call `auto_block`

**File**: `crates/aegis-security/src/risk/mod.rs:24-27,60-65`

```rust
canary_tags: vec!["recon_path"],  // ← hardcoded tag match
// scoring path set max score nhưng KHÔNG call state.auto_block(ip, ttl)
```

`aegis-core::config::RiskConfig::canary_paths` (config.rs:2063) exists nhưng không consumed.

**Fix**: Đọc `cfg.canary_paths` từ aegis-core; call `state.auto_block(ip, ttl)` khi match.

**Impact**: §5.5 mandate; Attack Battle scenario 08.

### 7. security F-CRITICAL-013 — response_filter chỉ strip 2 header

**File**: `crates/aegis-security/src/response_filter.rs:5`

```rust
const STRIP_HEADERS: &[&str] = &["server", "x-powered-by"];  // ← thiếu x-debug, x-internal, etc.
```

Plus thiếu: 5xx body cap, JSON field mask.

**Fix**: Mở rộng STRIP_HEADERS + prefix scanner; thêm 5xx body size guard; JSON field-aware redaction.

**Impact**: §5.7 violation. Response leak headers + bodies → graders deduct.

### 8. security F-CRITICAL-014 — brute_force per-IP POST-only

**File**: `crates/aegis-security/src/detectors/brute_force.rs:39,88`

```rust
state: Mutex<HashMap<IpAddr, Vec<Instant>>>,  // ← per-IP only
// + check method != POST → return
```

**Fix**: 3-axis tracker (per-user, per-IP-distinct-users for spraying, per-device for distributed stuffing). Body-parse for `username`. Method allowlist (POST/PUT/PATCH + Basic auth header).

**Impact**: §5.3 OWASP; Attack Battle scenario 02 distributed credential stuffing.

### 9. security F-CRITICAL-015 — bots.rs ignores `ja4_fingerprint` field

**File**: `crates/aegis-security/src/bots.rs:17` (field exists) + `:72-115` (classify() không đọc)

**Fix**: Read `ja4_fingerprint`; add `asn` + `asn_classification` fields; multi-signal classifier; challenge ladder.

**Impact**: §5.2 #05 (ASN classification), #08 (JA fingerprint), #04 (challenge ladder).

### 10. security F-CRITICAL-011 — JA4 sort + no GREASE strip

**File**: `crates/aegis-security/src/fingerprint/ja4.rs:57-60`

```rust
sorted_ciphers.sort_unstable();   // ← bỏ
sorted_exts.sort_unstable();      // ← bỏ
// + filter GREASE values (0x0A0A, 0x1A1A, ..., 0xFAFA)
```

**Fix**:
```rust
fn is_grease(v: u16) -> bool { (v & 0x0F0F) == 0x0A0A }
let ciphers: Vec<_> = cipher_suites.iter().copied().filter(|c| !is_grease(*c)).collect();
// KHÔNG sort
```

**Impact**: §5.2 #08 — Chrome's per-connection GREASE rotation phá device ID stability. Compound F-CRITICAL-010.

---

## 🟡 Tier 3: Intelligence rubric 20/120 + Architecture

### 11. security F-CRITICAL-003 — Velocity sequence engine

**File**: `crates/aegis-security/src/velocity.rs` (full file)

**Fix**: Net-new module ~300-400 LoC. Login→OTP→Deposit / withdraw-after-deposit / rapid-limit-change sequences.

**Impact**: Attack Battle scenario 06; Intelligence rubric headline.

### 12. security F-CRITICAL-004 — Behavioral signals 3/4 missing

**File**: `crates/aegis-security/src/behavior.rs:49-55`

**Fix**: Thêm 3 signal:
- Zero-depth session (first request to CRITICAL tier)
- Missing Referer on CRITICAL/HIGH
- Inter-request <50ms (absolute, không phải CoV)

Plus thêm `referer` + `tier` parameters vào `observe()`.

**Impact**: §5.2 #09; Attack Battle scenario 05.

### 13. security F-CRITICAL-010 — Same-device-different-IP detection

**File**: `crates/aegis-security/src/fingerprint/mod.rs`

**Fix**: Net-new `DeviceIpTracker` — reverse map device_id → Vec<(IpAddr, Instant)>. Detect rotation when distinct IPs ≥ threshold trong window.

**Impact**: §5.2 #08; Attack Battle scenario 04.

### 14. security F-CRITICAL-008 — Pipeline::inbound bypasses security

**File**: `crates/aegis-security/src/pipeline.rs:170-178`

**Fix**: Wire full pipeline (canary → blacklist → rate-limit → detectors → risk → rules) hoặc xóa trait.

**Impact**: Architecture rubric.

---

## 🟢 Tier 4: Schema discipline (lower direct impact, high upstream effect)

### 15. aegis-core F-CRITICAL-004 — `action: String` chưa thành enum

**File**: `crates/aegis-core/src/audit.rs:31`

```rust
pub action: String,   // ← cần đổi thành Action enum
```

**Fix**:
```rust
pub action: crate::decision::Action,
```

Plus derive Serialize cho `decision::Action` với `#[serde(rename_all = "snake_case", tag = "action")]`.

**Impact**: Type safety; cross-crate drift prevention. Author tự ghi "outstanding" trong docstring audit.rs:17.

---

## Tóm tắt theo effort vs impact

| Bug | LoC fix ước tính | Impact |
|---|---:|---|
| #1 H3 bypass | ~80 | Round-1 §5/§6/§10 fail trên QUIC |
| #2 AuditEvent thiếu fields | ~50 + migration | Round-1 §6 fail mọi event |
| #3 Compliance modes wire | ~100 | Round-1 "Tính hiệu lực" |
| #4 RiskTracker key shape | ~150 | Intelligence rubric |
| #5 Rate limit per-session | ~150 | Security rubric |
| #6 Canary auto_block | ~30 | Security rubric + Attack Battle |
| #7 response_filter §5.7 | ~100 | Security rubric |
| #8 brute_force 3-axis | ~200 | Security rubric + Attack Battle |
| #9 bots.rs JA4+ASN+ladder | ~200 | Security rubric + Intelligence |
| #10 JA4 sort/GREASE | ~15 | Intelligence rubric (cheapest!) |
| #11 Velocity sequence | ~400 | Intelligence + Attack Battle |
| #12 Behavior signals | ~50 | Intelligence + Attack Battle |
| #13 Same-device-IP map | ~120 | Intelligence + Attack Battle |
| #14 Pipeline consolidate | ~100 | Architecture |
| #15 action: enum | ~30 + migration | Type safety |

**Tổng**: ~1775 LoC fix để đóng tất cả 15 NOT_FIXED CRITICAL.

## Khuyến nghị Order of operations

1. **Tier 1** (Round-1 Pass/Fail) — không có nó là loại
2. **F-CRITICAL-011 (JA4 sort/GREASE)** — 15 LoC, cheapest fix
3. **F-CRITICAL-006 (Canary auto_block)** — 30 LoC + unlock Attack Battle scenario 08
4. **F-CRITICAL-012 (Behavior signals)** — 50 LoC + unlock Attack Battle 05
5. **Tier 2 còn lại** — bulk of Security Effectiveness rubric
6. **Tier 3 + Tier 4** — sau khi Tier 1-2 xong
