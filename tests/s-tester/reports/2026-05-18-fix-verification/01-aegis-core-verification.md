---
folder: 2026-05-17-aegis-core-audit/
agent: Agent A (verification)
date: 2026-05-18T00:00Z
status: 6 FIXED / 5 PARTIAL / 2 NOT_FIXED (13 total)
---

# aegis-core fix verification — chi tiết

## Status table

| ID | Title | Status | Evidence |
|---|---|---|---|
| F-CRITICAL-001 | audit `ts: DateTime` → `ts_ms: i64` | **PARTIAL** | `audit.rs:26` vẫn `pub ts: chrono::DateTime<chrono::Utc>`. Wire shape fixed qua `#[serde(rename = "ts_ms", serialize_with = "serialize_ts_as_ms")]` (lines 21-26) — emit i64 millis. Type Rust vẫn không phải `i64`. |
| F-CRITICAL-002 | audit `client_ip` → `ip` | **PARTIAL** | `audit.rs:34` vẫn `pub client_ip: String`. Wire fixed qua `#[serde(rename = "ip")]` line 33. Type `String` vẫn không phải `IpAddr`. |
| F-CRITICAL-003 | audit thiếu `method` / `path` / `mode` | **NOT_FIXED** | `audit.rs` struct (lines 19-43) không có 3 field. Comment lines 15-17 tự ghi: "Still outstanding (filed for follow-up commit): F-CRITICAL-003". |
| F-CRITICAL-004 | audit `action: String` → enum | **NOT_FIXED** | `audit.rs:31` vẫn `pub action: String`. Comment line 17 tự ghi: "F-CRITICAL-004: convert `action: String` → enum" — outstanding. |
| F-CRITICAL-005 | `risk_score: Option<u32>` | **PARTIAL** | `audit.rs:41` vẫn `Option<u32>`. Wire-shape clamp qua `serialize_risk_score_clamped` (lines 68-74) — None→0, >100→100. Type vẫn không phải `u8`. |
| F-CRITICAL-006 | Action enum thiếu Timeout / CircuitBreaker | **PARTIAL** | `decision.rs:21` thêm `Timeout { deadline_ms: u32 }`, `:28` thêm `CircuitBreaker { retry_after_s: u32 }`. Nhưng variant cũ vẫn là `RateLimited` không phải `RateLimit` (line 14) — wire format khi serialize qua snake_case sẽ ra `rate_limited` không phải spec `rate_limit`. |
| F-CRITICAL-007 | RiskThresholds default 40/80 → 30/70 | **FIXED** | `config.rs:2208-2222` `Default` impl trả về `challenge_at: 30, block_at: 70`. Helper `default_challenge_at` = 30 (line 2198), `default_block_at` = 70 (line 2202). |
| F-CRITICAL-008 | DdosConfig `tier_overrides` | **FIXED** | `config.rs:2475` `pub tier_overrides: HashMap<Tier, DdosTierConfig>` với `#[serde(default)]`. `DdosTierConfig` struct line 2483. Test line 4420 verify YAML parse. |
| F-CRITICAL-009 | RlScope thiếu 4/6 variants | **FIXED** | `config.rs:1985-2000` enum có Global, Route, Tier(Tier), RoutePattern(String), Ip(String), UserSession, DeviceFingerprint — **đủ 6 spec scopes**. Test line 4483. |
| F-CRITICAL-010 | `WafConfig.fail_mode_by_tier` | **FIXED** | `config.rs:197` `pub fail_mode_by_tier: HashMap<Tier, FailureModeConfig>` với `#[serde(default)]`. Test `fail_mode_by_tier_parses_and_default_empty` line 4449. |
| F-CRITICAL-011 | DetectorsConfig per-tier mask | **FIXED** | `config.rs:2307` `pub per_tier: HashMap<Tier, TierDetectorMask>`. `TierDetectorMask` struct line 2316 với `#[serde(deny_unknown_fields)]`. |
| F-CRITICAL-012 | RiskConfig `canary_paths` | **FIXED** | `config.rs:2063` `pub canary_paths: Vec<String>` với `#[serde(default)]`. Default impl line 2078 init `Vec::new()`. |
| F-CRITICAL-013 | zero `#[serde(deny_unknown_fields)]` | **PARTIAL** | `grep -c "deny_unknown_fields" config.rs` returns 4 (3 attribute + 1 comment). Applied to: WafConfig (line 68), TierDetectorMask (2315), DdosTierConfig (2482). **Thiếu trên**: RiskConfig (2029), RiskThresholds (2184), DetectorsConfig (2229), DdosConfig (2439), InteropConfig (202), RouteConfig, PoolConfig, etc. |

## Cần fix tiếp

### F-CRITICAL-003 (NOT_FIXED) — TOP PRIORITY

`audit.rs` struct còn THIẾU `method`, `path`, `mode` — 3 field §6 mandatory:

```diff
 pub struct AuditEvent {
     pub schema_version: u32,
     pub ts: DateTime<Utc>,
     pub request_id: String,
     pub class: AuditClass,
     pub tenant_id: Option<String>,
     pub tier: Option<Tier>,
     pub action: String,                      // F-CRITICAL-004
     pub reason: String,
     pub client_ip: String,
+    /// §6 contract — uppercase HTTP method.
+    pub method: String,                       // hoặc http::Method
+    /// §6 contract — request path INCLUDING query string.
+    pub path: String,
+    /// §6 contract — policy mode at decision time.
+    pub mode: AuditMode,                      // enforce | log_only
     pub route_id: Option<String>,
     pub rule_id: Option<String>,
     pub risk_score: Option<u32>,
     pub fields: serde_json::Value,
 }
```

→ Migration cần touch mọi populator (proxy/admin_mutate.rs + accept.rs + admin_dispatch.rs). ~10-15 call sites.

### F-CRITICAL-004 (NOT_FIXED)

```diff
-pub action: String,
+pub action: crate::decision::Action,
```

`decision::Action` đã có đủ 6 variants (sau fix F-CRITICAL-006). Cần derive `Serialize` với
`#[serde(rename_all = "snake_case", tag = "action")]` để serialize ra spec format.

### F-CRITICAL-006 (PARTIAL) — rename variant

```diff
 pub enum Action {
     Allow,
     Block { status: u16 },
     Challenge { level: ChallengeLevel },
-    RateLimited { retry_after_s: u32 },
+    RateLimit { retry_after_s: u32 },
     Timeout { deadline_ms: u32 },
     CircuitBreaker { retry_after_s: u32 },
 }
```

§5.1 contract ghi rõ `rate_limit` (snake_case), không `rate_limited`. Strict regex grader sẽ fail.

### F-CRITICAL-013 (PARTIAL) — mở rộng deny_unknown_fields

Thêm `#[serde(deny_unknown_fields)]` cho ít nhất các struct sau:

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

// ... và mọi nested struct khác
```

Test với mỗi struct: typo field name → expect serde rejection at parse.

### F-CRITICAL-001 / 002 / 005 (PARTIAL) — refactor type

Nếu chỉ cần wire-shape pass spec thì PARTIAL fix hiện tại OK.
Nhưng để hardened type system + tránh populator bugs:

```diff
-pub ts: chrono::DateTime<chrono::Utc>,
+pub ts_ms: i64,

-pub client_ip: String,
+pub ip: std::net::IpAddr,

-pub risk_score: Option<u32>,
+pub risk_score: u8,    // hoặc RiskScore newtype clamped
```
