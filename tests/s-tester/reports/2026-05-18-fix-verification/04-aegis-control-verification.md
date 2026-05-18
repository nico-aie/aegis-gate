---
folder: 2026-05-17-aegis-control-audit/
agent: Agent D (verification)
date: 2026-05-18T00:00Z
status: 16 FIXED / 1 PARTIAL / 1 NOT_FIXED (18 total) — chất lượng cao
---

# aegis-control fix verification — chi tiết

## Status table

| ID | Title | Status | Evidence |
|---|---|---|---|
| F-CRITICAL-001 | Rule CRUD rebuild `Arc<RuleSet>` | **FIXED** | `api/rules.rs:317` `rebuild_active_ruleset`; gọi từ `aegis-proxy/admin_mutate.rs:1682,1765,1828,1890`; wired `accept.rs:538-539`. |
| F-CRITICAL-002 | COMPLIANCE_PINNED + TLS compliance | **NOT_FIXED** | `api/detectors.rs:113` vẫn `&[]`. `grep min_tls_version` trong aegis-proxy: 0 hits. |
| F-CRITICAL-003 | /healthz uptime/mode/rule-count | **FIXED** | `health.rs:14-23` schema; `admin_get.rs:108` populate qua `with_runtime_info(uptime, "enforce", rule_count)`. |
| F-CRITICAL-004 | Audit search time-range | **FIXED** | `api/audit.rs:106-107` thêm `ts_from`/`ts_to`; matcher 131-140; dispatcher parse `admin_get.rs:226-227`. |
| F-CRITICAL-005 | GitOpsLoader dead code | **FIXED** | Module deleted; `lib.rs:35` `// pub mod gitops;` commented out. |
| F-CRITICAL-006 | audit/witness.rs dead code | **FIXED** | Dead functions removed; `witness.rs:1-36` retain chỉ schema struct (load-bearing for `/api/audit/witness_lag`). |
| F-CRITICAL-007 | residency.rs dead code | **FIXED** | Module deleted; `lib.rs:38` confirm. |
| F-CRITICAL-008 | tracing_init.rs dead code | **FIXED** | Module deleted; `lib.rs:14` confirm. |
| F-CRITICAL-009 | mtls::verify_client_cert dead | **FIXED** | `admin_auth::mtls` module deleted; `mod.rs:12` `// pub mod mtls;`. |
| F-CRITICAL-010 | capabilities omits open_redirect | **FIXED** | `aegis-proxy/run.rs:1697` `"open_redirect".into()` thêm vào policies list. |
| F-CRITICAL-011 | Bus drain exits on Lagged | **FIXED** | `dashboard_services.rs:452-470` dùng match với `RecvError::Lagged` → continue, `Closed` → break. |
| F-CRITICAL-012 | interop/audit sync fs I/O | **FIXED** | `aegis-proxy/src/admin_dispatch.rs:1114` wrap `sink.append` trong `tokio::task::spawn_blocking`. |
| F-CRITICAL-013 | jsonl no fsync + chain on-disk | **FIXED** | `audit/sinks/jsonl.rs:319,340,389` gọi `sync_data()`; `:413-414` wrap trong `ChainEntry`; `:400` `resolve_seed_prev_hash` đóng cross-day linkage. |
| F-CRITICAL-014 | Rollback 13/25 missing | **PARTIAL** | `api/rollback.rs:57-79` thêm 4 rule_* actions; vẫn thiếu pool_*, route_*, alert_receivers_set, mtls_ca_bundle_set, client_auth_mode_set, ddos_set, rate_limit_set, strikes_set, upstreams_config_set, compliance_modes_set, tier_overrides_set. |
| F-CRITICAL-015 | SSRF via bot_token | **FIXED** | `slo/dispatch.rs:152-167` reject `:/\@?#%`, control/non-printable bytes, và `..`. |
| F-CRITICAL-016 | SliRingBuffer O(n) | **FIXED** | `slo.rs:222` `VecDeque<SliSample>`; `:236` `pop_front()` (O(1)). |
| F-CRITICAL-017 | DEFAULT_VIPTALK_BOT_TOKEN hardcoded | **FIXED** | `slo.rs:178-200` remove hardcoded constant; return `vec![]` với warn khi env vars missing. |
| F-CRITICAL-018 | Mock data analytics + tracking | **FIXED** | `api/analytics.rs:160-173` trả 503 `analytics_not_implemented` thay `0.0`; `tracking.rs:47-48` placeholder trả empty `slis: vec![]` (no fake 99.99%). |

## Cần fix tiếp

### 🟡 F-CRITICAL-002 (NOT_FIXED) — Compliance modes theater

**Vấn đề**:

```rust
// api/detectors.rs:113
const COMPLIANCE_PINNED: &[DetectorClass] = &[];
```

Comment hiện tại admit: "lock-by-mode left empty by design ... modes are still accepted as documentation tags ... they just no-op while this slice is empty."

**Plus TLS-side**: `grep min_tls_version | disallow_algorithms` trong aegis-proxy/src/ trả 0 hits → TLS stack vẫn không đọc compliance config fields.

**Hệ quả**: Operator bật FIPS/PCI/HIPAA/SOC2/GDPR mode → không có effect thực tế. Round-1 "Tính hiệu lực" Pass/Fail risk nếu BTC verify bằng real traffic.

**Fix**:

1. Populate `COMPLIANCE_PINNED` per mode:

```rust
// api/detectors.rs
fn compliance_pinned_for(modes: &ComplianceModes) -> Vec<DetectorClass> {
    let mut out = vec![];
    if modes.contains(&"pci") { out.extend([Sqli, Xss, PathTraversal, Ssrf, HeaderInjection]); }
    if modes.contains(&"hipaa") { out.extend([Sqli, Xss, PathTraversal, BodyAbuse]); }
    if modes.contains(&"fips") { /* full set */ }
    out
}
```

2. Wire TLS:

```rust
// aegis-proxy/src/listener/tls.rs::build_server_config
let min_version = match cfg.compliance.min_tls_version.as_deref() {
    Some("1.3") => &[&rustls::version::TLS13],
    Some("1.2") => &[&rustls::version::TLS12, &rustls::version::TLS13],
    _ => rustls::ALL_VERSIONS,
};
let builder = rustls::ServerConfig::builder()
    .with_protocol_versions(min_version)?;
```

### 🟠 F-CRITICAL-014 (PARTIAL) — Rollback dispatcher

Allowlist hiện 15 entries, vẫn thiếu ~11 mutation classes:

```rust
// api/rollback.rs:57-79 — thêm:
"pool_upsert", "pool_delete",
"route_upsert", "route_delete",
"alert_receivers_set",
"mtls_ca_bundle_set", "client_auth_mode_set",
"upstreams_config_set",
"ddos_set", "strikes_set", "rate_limit_set",
"compliance_modes_set", "tier_overrides_set",
```

Plus mỗi action cần `apply_*_rollback` function tương ứng — mỗi cái ~30-50 LoC.

`RollbackTargets` struct `:90-104` cũng cần thêm fields cho các store mới (routes, pools, receivers, ddos, etc.).

§5.9 bonus "config versioning + rollback" mới collect được ~50% — operators còn nhận 422 trên các mutation class bị thiếu.

## Đánh giá

aegis-control fix **xuất sắc** (16/18 = 89%). Code có F-CRITICAL-NNN
comment explicit ở mỗi fix site → dễ verify, dễ audit. Hai vấn đề
còn lại đều rõ ràng và fix size moderate.
