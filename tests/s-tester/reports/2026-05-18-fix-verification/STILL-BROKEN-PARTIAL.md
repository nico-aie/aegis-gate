---
id: 2026-05-18-still-broken-partial
date: 2026-05-18T00:00Z
purpose: 9 CRITICAL có fix PARTIAL — wire shape/intent OK nhưng còn gap
---

# 9 CRITICAL fix PARTIAL — còn gap nhỏ cần cleanup

Mức độ này ít gấp hơn NOT_FIXED nhưng vẫn nên đóng để hardened.

---

## aegis-core: 5 PARTIAL

### 1. F-CRITICAL-001 — `ts: DateTime` chưa đổi thành `ts_ms: i64`

**File**: `audit.rs:26`

```rust
pub ts: chrono::DateTime<chrono::Utc>,   // PARTIAL: wire shape correct qua serde rename
```

Wire JSON đúng `ts_ms` integer rồi, nhưng Rust type vẫn `DateTime`. Refactor for type clarity:

```diff
-pub ts: chrono::DateTime<chrono::Utc>,
+pub ts_ms: i64,
```

Cần touch populator sites: thay `ts: Utc::now()` → `ts_ms: Utc::now().timestamp_millis()`.

### 2. F-CRITICAL-002 — `client_ip: String` chưa đổi thành `IpAddr`

**File**: `audit.rs:34`

```rust
pub client_ip: String,    // PARTIAL: wire renamed to "ip" qua serde
```

Wire JSON key đúng "ip", nhưng type còn `String` → populator có thể quên strip port hoặc whitespace. Refactor:

```diff
-pub client_ip: String,
+pub ip: std::net::IpAddr,
```

### 3. F-CRITICAL-005 — `risk_score: Option<u32>` chưa thành `u8` clamped

**File**: `audit.rs:41`

Wire-shape clamp đã có (`serialize_risk_score_clamped`). Type level refactor:

```diff
-pub risk_score: Option<u32>,
+pub risk_score: u8,    // hoặc RiskScore(u8) newtype
```

Populator: nếu None → 0; nếu >100 → clamp. Build helper.

### 4. F-CRITICAL-006 — `RateLimited` chưa rename thành `RateLimit`

**File**: `decision.rs:14`

```rust
RateLimited { retry_after_s: u32 },   // ← cần đổi thành RateLimit
Timeout { deadline_ms: u32 },         // ✅ added
CircuitBreaker { retry_after_s: u32 }, // ✅ added
```

§5.1 contract: wire format `rate_limit` (snake_case), không phải `rate_limited`. Khi `#[derive(Serialize)] #[serde(rename_all = "snake_case")]` áp vào, variant `RateLimited` → "rate_limited" → KHÔNG khớp spec.

```diff
-RateLimited { retry_after_s: u32 },
+RateLimit { retry_after_s: u32 },
```

Plus update consumers.

### 5. F-CRITICAL-013 — `#[serde(deny_unknown_fields)]` chỉ trên 3 struct

**File**: `config.rs`

Hiện tại 3 struct có annotation (WafConfig, TierDetectorMask, DdosTierConfig). Spec yêu cầu mọi nested struct:

```rust
#[serde(deny_unknown_fields)]
pub struct RiskConfig { ... }

#[serde(deny_unknown_fields)]
pub struct RiskThresholds { ... }

#[serde(deny_unknown_fields)]
pub struct DetectorsConfig { ... }

#[serde(deny_unknown_fields)]
pub struct DdosConfig { ... }

#[serde(deny_unknown_fields)]
pub struct InteropConfig { ... }

#[serde(deny_unknown_fields)]
pub struct RouteConfig { ... }

#[serde(deny_unknown_fields)]
pub struct PoolConfig { ... }

#[serde(deny_unknown_fields)]
pub struct AuditConfig { ... }

#[serde(deny_unknown_fields)]
pub struct TlsConfig { ... }

#[serde(deny_unknown_fields)]
pub struct AcmeConfig { ... }

// ... etc — mọi struct nested trong WafConfig
```

Test mỗi struct: typo field name → expect serde error.

---

## proxy-full-audit: 2 PARTIAL

### 6. F-CRITICAL-006 — Dead modules quota / dr / traffic

**File**: `crates/aegis-proxy/src/lib.rs:40,46,55`

```rust
pub mod dr;        // zero callers
pub mod quota;     // zero callers
pub mod traffic;   // zero callers
// shed đã wired ở run.rs:713
```

Spec: "wired in OR deleted". Hiện tại 3 module ở giữa — nên:

**Option A — Wire**:
- `quota`: gọi `check_request_quota()` đầu `data_plane::handle_data_request`
- `dr`: thay `aegis-bin/snapshot.rs` (consolidate hai impl)
- `traffic`: wire vào upstream forward path nếu cần canary/mirror

**Option B — Xóa** (recommended):
```diff
-pub mod dr;
-pub mod quota;
-pub mod traffic;
```

Update README để gỡ claim về các feature này.

### 7. F-CRITICAL-010 — WS thiếu Sec-WebSocket-Accept verify

**File**: `proto/ws_forward.rs`

Defensive header parsing đã có (lines 143, 165, 208-221), nhưng thiếu recompute `Sec-WebSocket-Accept` từ client `Sec-WebSocket-Key`:

```rust
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
let expected_accept = {
    use sha1::{Sha1, Digest};
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut hasher = Sha1::new();
    hasher.update(client_ws_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    STANDARD.encode(hasher.finalize())
};
if upstream_ws_accept != expected_accept {
    return Err(WsError::AcceptMismatch);
}
```

---

## aegis-control: 1 PARTIAL

### 8. F-CRITICAL-014 — Rollback dispatcher còn thiếu ~11 action

**File**: `crates/aegis-control/src/api/rollback.rs:57-79`

Hiện tại allowlist 15 entries; thêm 4 rule_* actions. Vẫn thiếu:

```diff
 pub const ROLLBACKABLE_ACTIONS: &[&str] = &[
     ...
+    "pool_upsert", "pool_delete",
+    "route_upsert", "route_delete",
+    "alert_receivers_set",
+    "mtls_ca_bundle_set", "client_auth_mode_set",
+    "upstreams_config_set",
+    "ddos_set", "strikes_set", "rate_limit_set",
+    "compliance_modes_set", "tier_overrides_set",
 ];
```

Plus thêm `apply_*_rollback` function tương ứng (~30-50 LoC each) và mở rộng `RollbackTargets` struct.

---

## aegis-security: 1 PARTIAL

### 9. F-CRITICAL-005 — DDoS tier-aware

**File**: `crates/aegis-security/src/ddos.rs:209,136`

Config side đã có `tier_overrides: HashMap` (aegis-core F-CRITICAL-008 FIXED), nhưng detector vẫn ignore:

```rust
pub fn check(&self, ip: IpAddr) -> Decision {
    // ← chỉ đọc cfg.per_ip_limit, không đọc tier_overrides
}
```

**Fix**:
```diff
-pub fn check(&self, ip: IpAddr) -> Decision {
+pub fn check(&self, ip: IpAddr, tier: Tier) -> Decision {
+    let limit = self.cfg.tier_overrides
+        .get(&tier)
+        .unwrap_or(&self.cfg.default);
+    // ... + fail-close branching trên Tier::Critical khi internal error
 }
```

Plus `observe_only` mode phải gate `auto_block` (hiện tại auto_block fire unconditional).

---

## Tổng effort PARTIAL

| ID | Crate | LoC fix | Type |
|---|---|---:|---|
| #1, #2, #3 | aegis-core audit type | ~50 + migration | Refactor |
| #4 | aegis-core decision | ~30 + migration | Rename |
| #5 | aegis-core deny_unknown_fields | ~20 | Annotation |
| #6 | proxy dead modules | ~50 (xóa) | Cleanup |
| #7 | proxy WS verify | ~30 | Hardening |
| #8 | control rollback dispatcher | ~300 (11 actions × ~30 LoC) | Feature complete |
| #9 | security DDoS tier-aware | ~50 + plumb tier | Wire-in |

**Tổng**: ~530 LoC + audit migration.

PARTIAL fix có thể chấp nhận để qua benchmark — nhưng wire-shape clamp / rename / dead-code không gây trừ điểm rubric trực tiếp. Hoàn thành sau khi xong NOT_FIXED.
