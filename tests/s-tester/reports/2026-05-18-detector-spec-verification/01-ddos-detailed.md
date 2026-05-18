---
id: 2026-05-18-ddos-deep-dive
date: 2026-05-18T00:00Z
severity: CRITICAL
area: aegis-security · DDoS detector
component: crates/aegis-security/src/ddos.rs · crates/aegis-proxy/src/data_plane.rs · crates/aegis-control/src/api/gates.rs
spec_ref: §5.2 #03 (DDoS) + §5.8 (Graceful Degradation)
status: NOT_FIXED (F-CRITICAL-005 partial từ audit 2026-05-17 vẫn còn)
---

# DDoS detector — Deep dive theo yêu cầu user

## Yêu cầu của thể lệ (Hackathon_Doc/RULES.md §5.2 #03 + §5.8)

> **§5.2 #03 — DDoS / Volumetric Protection (BẮT BUỘC)**
>
> - Burst detection theo per-tier threshold (CRITICAL ≠ HIGH ≠ MEDIUM ≠ CATCH-ALL).
> - Threshold phải configurable qua dashboard, không hardcode.
> - Trên CRITICAL endpoints (/login /otp /deposit /withdrawal): khi rate-limiter backend lỗi → **fail-close** (chặn).
> - Trên MEDIUM/CATCH-ALL: khi backend lỗi → **fail-open** (cho qua + log).
> - Tính hiệu lực: operator PUT YAML/dashboard → áp dụng ≤10s.

> **§5.8 — Graceful Degradation**
>
> Cấu trúc rule phải khai báo `fail_mode_by_tier: { critical: fail_close, high: fail_close, medium: fail_open, catch_all: fail_open }`. Khi component panic / timeout, hành vi phải tuân thủ tier.

## Hiện trạng code (mapping line-by-line)

### Gap 1 — `DdosDetector::check()` thiếu param `tier`

[crates/aegis-security/src/ddos.rs:136-145](../../../../crates/aegis-security/src/ddos.rs#L136)

```rust
impl DdosRuntime {
    pub fn check(&self, peer_ip: IpAddr) -> CheckOutcome {
        // ...
    }
}
```

Signature chỉ nhận `peer_ip`, không nhận `tier`. Hệ quả: detector vật lý không thể đọc `cfg.tier_overrides.get(&tier)` — luôn áp dụng global `per_ip_limit`.

Call site ở data plane:

[crates/aegis-proxy/src/data_plane.rs:349](../../../../crates/aegis-proxy/src/data_plane.rs#L349)

```rust
let ddos_outcome = ddos.check(peer_ip);  // <-- không truyền tier
```

Hơn nữa, dòng 349 chạy **TRƯỚC** `classify_tier()` ở dòng 563, nên kể cả nếu sửa signature, vẫn cần restructure thứ tự gọi.

### Gap 2 — Không có nhánh fail-close per tier

[crates/aegis-proxy/src/data_plane.rs:417-421](../../../../crates/aegis-proxy/src/data_plane.rs#L417)

```rust
Err(e) => {
    tracing::warn!(error = ?e, "ddos: backend error, fail-open");
    // ...universal fail-open...
}
```

Mọi tier (CRITICAL, HIGH, MEDIUM, CATCH-ALL) đều fail-open khi backend lỗi. Spec yêu cầu CRITICAL phải fail-close (chặn) — đây là gap nghiêm trọng cho scenario "DDoS attack làm sập rate-limiter Redis → attacker tự do brute /withdrawal".

### Gap 3 — Schema config có nhưng không wire

[crates/aegis-core/src/config.rs:2473-2475](../../../../crates/aegis-core/src/config.rs#L2473)

```rust
// Schema only — consumer wiring lands in Phase E/F.
#[serde(default)]
pub tier_overrides: HashMap<Tier, DdosTierConfig>,
```

Schema đã có `tier_overrides`. NHƯNG impl `From<aegis_core::config::DdosConfig> for DdosConfig` ở `aegis-security/src/ddos.rs:49-61` **KHÔNG copy** field này. Khi parse YAML, tier_overrides bị im lặng vứt đi — operator nghĩ config có hiệu lực nhưng thực tế không.

### Gap 4 — Dashboard `DdosPutBody` thiếu field

[crates/aegis-control/src/api/gates.rs:117-127](../../../../crates/aegis-control/src/api/gates.rs#L117)

```rust
pub struct DdosPutBody {
    pub per_ip_limit: Option<u32>,
    pub per_ip_window_s: Option<u32>,
    pub block_ttl_s: Option<u32>,
    pub spike_multiplier: Option<f32>,
    pub tightened_per_ip_rps: Option<u32>,
    // <-- THIẾU: tier_overrides
}
```

Kể cả nếu fix gap 1+2+3, dashboard UI hiện tại không có ô để operator nhập `tier_overrides` qua PUT. Phải mở rộng body schema.

## Phần đã đúng

- ✅ ArcSwap hot-reload hoạt động — `DdosDetector::set_config()` ở `ddos.rs:199-201` swap `Arc::new(config)`, request kế tiếp đọc `self.config.load()` ở `ddos.rs:214`. Latency sub-millisecond, ≤10s OK.
- ✅ Endpoint `PUT /api/gates/ddos` tồn tại ở `admin_mutate.rs:3337-3419` (`handle_ddos_put`), có audit-mutate chain.
- ✅ Global threshold (`per_ip_limit`, `per_ip_window_s`) configurable qua dashboard.
- ✅ Không vi phạm §9 (không hardcode `evil/attacker`).

## Risk nếu không fix

- **Round-1 Pass/Fail risk: CAO**. Judge chỉ cần:
  1. PUT `/api/gates/ddos` với body `{"tier_overrides": {"CRITICAL": {"per_ip_limit": 5}}}` → response 200 (silent ignore) hoặc 400 (schema reject).
  2. Spam `/withdrawal` từ 1 IP với 100 RPS — quan sát rằng global `per_ip_limit` mới trigger, không phải CRITICAL-specific.
  3. Tắt Redis → spam `/login` — quan sát rằng request vẫn được serve (fail-open) thay vì 503 (fail-close).
- §5.2 #03 mục "tính hiệu lực" bị breach.

## Fix outline (ước tính ~50-80 LoC, 2-3h dev + test)

### Bước 1 — Mở rộng `DdosConfig` ở aegis-security

```rust
// ddos.rs
#[derive(Clone, Debug)]
pub struct DdosConfig {
    pub per_ip_limit: u32,
    pub per_ip_window_s: u32,
    pub block_ttl_s: u32,
    pub spike_multiplier: f32,
    pub tightened_per_ip_rps: Option<u32>,
    // MỚI:
    pub tier_overrides: HashMap<Tier, TierLimit>,
    pub failure_mode: HashMap<Tier, FailureMode>,
}

pub struct TierLimit {
    pub per_ip_limit: u32,
    pub per_ip_window_s: u32,
}

impl DdosConfig {
    pub fn limit_for(&self, tier: Tier) -> (u32, u32) {
        self.tier_overrides.get(&tier)
            .map(|t| (t.per_ip_limit, t.per_ip_window_s))
            .unwrap_or((self.per_ip_limit, self.per_ip_window_s))
    }

    pub fn fail_mode_for(&self, tier: Tier) -> FailureMode {
        self.failure_mode.get(&tier).copied().unwrap_or(FailureMode::FailOpen)
    }
}
```

### Bước 2 — `check()` nhận tier

```rust
impl DdosRuntime {
    pub fn check(&self, peer_ip: IpAddr, tier: Tier) -> CheckOutcome {
        let cfg = self.config.load();
        let (limit, window) = cfg.limit_for(tier);
        // ... existing logic dùng limit + window ...
    }
}
```

### Bước 3 — `data_plane.rs` re-order: classify tier TRƯỚC ddos check

```rust
// data_plane.rs
let tier = classify_tier(&req, &cfg);              // dời lên trước
let _failure_mode = cfg.ddos.fail_mode_for(tier);  // không discard

match ddos.check(peer_ip, tier) {
    Ok(CheckOutcome::Pass) => { /* continue */ }
    Ok(CheckOutcome::Block) => return ddos_block_response(),
    Err(e) => {
        tracing::warn!(error = ?e, ?tier, "ddos: backend error");
        match _failure_mode {
            FailureMode::FailClose => return service_unavailable(),  // 503
            FailureMode::FailOpen => { /* let through + bump risk */ }
        }
    }
}
```

### Bước 4 — `DdosPutBody` mở rộng

```rust
// gates.rs
pub struct DdosPutBody {
    // ...existing...
    pub tier_overrides: Option<HashMap<Tier, DdosPutTierBody>>,
    pub failure_mode: Option<HashMap<Tier, FailureMode>>,
}
```

### Bước 5 — `From` impl giữ lại tier_overrides

```rust
// ddos.rs
impl From<aegis_core::config::DdosConfig> for DdosConfig {
    fn from(c: aegis_core::config::DdosConfig) -> Self {
        Self {
            // ...existing fields...
            tier_overrides: c.tier_overrides.into_iter()
                .map(|(t, v)| (t, TierLimit { per_ip_limit: v.per_ip_limit, per_ip_window_s: v.per_ip_window_s }))
                .collect(),
            failure_mode: c.fail_mode_by_tier.clone(),
        }
    }
}
```

### Bước 6 — Test

- Unit: `check()` với tier=Critical đọc per-tier limit.
- Unit: backend err + tier=Critical + fail_mode=FailClose → return ServiceUnavailable.
- E2E: PUT dashboard với tier_overrides → next request áp dụng trong <1s.

## Trích spec gốc

Đoạn liên quan trong `Hackathon_Doc/RULES.md` §5.2 #03 và §5.8 (xem file gốc để đối chiếu chính xác — đoạn dưới là tóm tắt):

```
§5.2 #03 — DDoS / Volumetric Protection (BẮT BUỘC)

  Yêu cầu:
  - Threshold per-IP burst configurable per tier
  - Spike detection (1m/5m baseline)
  - Auto-block với TTL configurable
  - Tính hiệu lực: thay đổi config qua dashboard PUT phải có hiệu lực ≤10s

§5.8 — Graceful Degradation

  fail_mode_by_tier:
    critical: fail_close
    high: fail_close
    medium: fail_open
    catch_all: fail_open

  Khi component dependency (Redis, GeoIP, threat-feed) panic hoặc timeout,
  fail_mode_by_tier quyết định block-hay-cho-qua.
```
