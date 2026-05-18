---
id: 2026-05-18-ddos-still-not-wired
date: 2026-05-18T00:00Z
severity: CRITICAL
area: security · DDoS protection · data-plane integration · dashboard API
component: crates/aegis-security/src/ddos.rs · crates/aegis-proxy/src/data_plane.rs · crates/aegis-control/src/api/gates.rs · crates/aegis-core/src/config.rs
interop_contract: official rules §5.2 #03 (DDoS per-tier threshold) + §5.8 (fail-close/fail-open per tier)
status: open · follow-up của F-CRITICAL-005 (audit 2026-05-17 — schema thêm vào, runtime + dashboard chưa wire)
test_mode: source-review
prior_finding: 2026-05-17-security-audit/F-CRITICAL-005-ddos-no-per-tier-no-fail-close.md
---

# F-CRITICAL-005 (re-report) · DDoS gate vẫn không enforce per-tier threshold + fail-close

## Tóm tắt

Audit ngày **2026-05-17** đã raise F-CRITICAL-005: DDoS detector vi phạm §5.2 #03 + §5.8. Sau đợt fix, verify ngày **2026-05-18** cho thấy status = **PARTIAL**:

- ✅ Schema config đã thêm `tier_overrides: HashMap<Tier, DdosTierConfig>` và `fail_mode_by_tier` (xem [config.rs:197](../../../../crates/aegis-core/src/config.rs#L197), [config.rs:2475](../../../../crates/aegis-core/src/config.rs#L2475)).
- ❌ Runtime [ddos.rs](../../../../crates/aegis-security/src/ddos.rs) **không đọc** các field schema này.
- ❌ Data plane [data_plane.rs:349](../../../../crates/aegis-proxy/src/data_plane.rs#L349) **không truyền tier** vào `check()`.
- ❌ Dashboard [gates.rs:117-127](../../../../crates/aegis-control/src/api/gates.rs#L117) **không có field `tier_overrides`** trong PUT body.

Tức là: operator có thể PUT YAML với `ddos.tier_overrides.critical.per_ip_limit: 30`, parse OK, nhưng runtime áp dụng global `per_ip_limit: 1000` cho mọi tier. **§5.2 #03 mục "tính hiệu lực" bị breach hoàn toàn**.

Spec §5.2 #03 + §5.8 đoạn nguyên văn:

> *"Burst detection + auto block + configurable threshold **per route tier**.
> Fail-close mode cho CRITICAL tier, fail-open cho MEDIUM/CATCH-ALL tier"*

> *"Fail-close mode cho CRITICAL tier (routes nhạy cảm): từ chối tất cả traffic
> nếu WAF internal error — an toàn hơn là để traffic pass-through. Fail-open
> mode cho MEDIUM & CATCH-ALL tier: allow-through nếu WAF overloaded."*

---

## DD-01 · `DdosConfig` runtime struct thiếu `tier_overrides` + `fail_mode_by_tier`

**Component:** [crates/aegis-security/src/ddos.rs:9-33](../../../../crates/aegis-security/src/ddos.rs#L9)

```rust
pub struct DdosConfig {
    pub enabled: bool,
    pub observe_only: bool,
    pub per_ip_limit: u64,         // ← single global value
    pub per_ip_window_s: u32,
    pub block_ttl_s: u64,
    pub spike_multiplier: f64,
    pub tightened_per_ip_rps: u64,
    // ❌ THIẾU: pub tier_overrides: HashMap<Tier, DdosTierLimit>
    // ❌ THIẾU: pub failure_mode: HashMap<Tier, FailureMode>
}
```

Schema phía `aegis-core::config::DdosConfig` đã có 2 field này, NHƯNG runtime struct của detector không có chỗ chứa → impl `From` dưới đây silently drop.

**Fix:** thêm 2 field + helper method:

```rust
pub struct DdosConfig {
    // ...existing...
    pub tier_overrides: HashMap<Tier, DdosTierLimit>,
    pub failure_mode: HashMap<Tier, FailureMode>,
}

#[derive(Clone, Debug)]
pub struct DdosTierLimit {
    pub per_ip_limit: u64,
    pub per_ip_window_s: u32,
}

impl DdosConfig {
    pub fn limit_for(&self, tier: Tier) -> (u64, u32) {
        self.tier_overrides.get(&tier)
            .map(|t| (t.per_ip_limit, t.per_ip_window_s))
            .unwrap_or((self.per_ip_limit, self.per_ip_window_s))
    }
    pub fn fail_mode_for(&self, tier: Tier) -> FailureMode {
        self.failure_mode.get(&tier).copied().unwrap_or(FailureMode::FailOpen)
    }
}
```

---

## DD-02 · `From<aegis_core::config::DdosConfig>` impl silently drop `tier_overrides`

**Component:** [crates/aegis-security/src/ddos.rs:49-61](../../../../crates/aegis-security/src/ddos.rs#L49)

```rust
impl From<aegis_core::config::DdosConfig> for DdosConfig {
    fn from(c: aegis_core::config::DdosConfig) -> Self {
        Self {
            enabled: c.enabled,
            observe_only: c.observe_only,
            per_ip_limit: c.per_ip_limit,
            per_ip_window_s: c.per_ip_window_s,
            block_ttl_s: c.block_ttl_s,
            spike_multiplier: c.spike_multiplier,
            tightened_per_ip_rps: c.tightened_per_ip_rps,
            // ❌ c.tier_overrides bị vứt đi
            // ❌ c.fail_mode_by_tier bị vứt đi (parent SecurityConfig, không phải DdosConfig
            //    nhưng chính là field §5.8 yêu cầu)
        }
    }
}
```

Hệ quả: parser YAML chấp nhận block `tier_overrides:`, test [config.rs:4420 `ddos_tier_overrides_parse_and_default_empty`](../../../../crates/aegis-core/src/config.rs#L4420) PASS, nhưng từ aegis-core sang aegis-security, field bị silent drop. Operator đọc test → tin rằng config có hiệu lực → thực tế không. Đây là pattern *"schema-only landmine"*.

**Fix:**

```rust
impl From<aegis_core::config::DdosConfig> for DdosConfig {
    fn from(c: aegis_core::config::DdosConfig) -> Self {
        Self {
            // ...existing fields...
            tier_overrides: c.tier_overrides.into_iter()
                .map(|(t, v)| (t, DdosTierLimit {
                    per_ip_limit: v.per_ip_limit,
                    per_ip_window_s: v.per_ip_window_s,
                }))
                .collect(),
            failure_mode: HashMap::new(),  // wire ở build_security_config khi
                                           // đã có visibility sang SecurityConfig::fail_mode_by_tier
        }
    }
}
```

Riêng `failure_mode` cần wire ở 1 tầng cao hơn vì `fail_mode_by_tier` thuộc `SecurityConfig` (line 197), không phải `DdosConfig`. Có 2 lựa chọn:

1. Thêm `failure_mode_by_tier` trực tiếp vào `aegis_core::config::DdosConfig`.
2. Pass `SecurityConfig::fail_mode_by_tier` xuống `DdosRuntime::new(...)` ở `aegis-proxy/src/run.rs`.

Đề nghị (1) — gom config tập trung, dễ test.

---

## DD-03 · `DdosDetector::check()` + `DdosRuntime::check()` thiếu param `tier`

**Component:** [crates/aegis-security/src/ddos.rs:136](../../../../crates/aegis-security/src/ddos.rs#L136), [ddos.rs:209](../../../../crates/aegis-security/src/ddos.rs#L209)

```rust
impl DdosRuntime {
    pub async fn check(&self, peer_ip: IpAddr) -> aegis_core::Result<DdosCheckOutcome> {
        let result = self.detector.check(self.state.as_ref(), peer_ip).await?;
        //                                                    ^^^^^^^
        //  ❌ không có tier — detector không biết mình đang xử request /login hay /static/css
        ...
    }
}
```

Signature `(peer_ip: IpAddr)` vật lý không cho phép detector đọc per-tier override. Phải đổi.

**Fix:**

```rust
impl DdosRuntime {
    pub async fn check(
        &self,
        peer_ip: IpAddr,
        tier: Tier,
    ) -> aegis_core::Result<DdosCheckOutcome> {
        let cfg = self.detector.config_snapshot();
        let (limit, window) = cfg.limit_for(tier);
        let result = self.detector.check_with_limits(
            self.state.as_ref(), peer_ip, limit, window,
        ).await?;
        Ok(DdosCheckOutcome { /* ... */ })
    }
}
```

Tách `check_with_limits` để giữ unit test cũ + cho phép path mới tiêm limits.

---

## DD-04 · Data plane gọi `ddos.check()` trước khi classify tier

**Component:** [crates/aegis-proxy/src/data_plane.rs:349](../../../../crates/aegis-proxy/src/data_plane.rs#L349)

```rust
// line 348-349
if let Some(ddos) = upstream_ctx.ddos.get() {
    match ddos.check(peer_ip).await {     // ← chạy TRƯỚC classify_tier
        ...
    }
}
```

`classify_tier(req, &cfg)` chạy ở dòng ~563 (xa hơn nhiều). Tức là kể cả khi DD-03 đã fix, vẫn cần restructure thứ tự gọi để `tier` đã sẵn ở dòng 349.

**Fix:** dời `classify_tier()` lên trước block DDoS:

```rust
// dời classify_tier lên đầu, trước block DDoS:
let tier = classify_tier(&req, &cfg);

if let Some(ddos) = upstream_ctx.ddos.get() {
    match ddos.check(peer_ip, tier).await {
        // ...
        Err(e) => {
            tracing::warn!(peer = %peer_ip, error = %e, ?tier, "ddos: backend error");
            match cfg.fail_mode_for(tier) {
                FailureMode::FailClose => return service_unavailable_503(...),
                FailureMode::FailOpen  => { /* let through */ }
            }
        }
    }
}
```

---

## DD-05 · Universal fail-open trên backend error (vi phạm §5.8)

**Component:** [crates/aegis-proxy/src/data_plane.rs:417-421](../../../../crates/aegis-proxy/src/data_plane.rs#L417)

```rust
Err(e) => {
    // Fail open — observe-only never blocks anyway,
    // and a state-backend hiccup must not drop traffic.
    tracing::debug!(peer = %peer_ip, error = %e, "ddos: backend error, fail-open");
}
```

Comment thừa nhận: fail-open áp dụng cho **mọi** request. Một Redis hiccup trong lúc attacker brute /withdrawal cũng được pass-through.

§5.8 mandate (đã quote ở Summary): CRITICAL phải fail-close. Hiện tại bị breach.

**Fix:** thay khối Err với logic per-tier (xem DD-04 fix outline). 503 cho CRITICAL/HIGH, log + fall through cho MEDIUM/CATCH-ALL.

---

## DD-06 · `DdosPutBody` dashboard thiếu `tier_overrides`

**Component:** [crates/aegis-control/src/api/gates.rs:117-127](../../../../crates/aegis-control/src/api/gates.rs#L117)

```rust
pub struct DdosPutBody {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub observe_only: bool,
    pub per_ip_limit: u64,
    pub per_ip_window_s: u32,
    pub block_ttl_s: u64,
    pub spike_multiplier: f64,
    pub tightened_per_ip_rps: u64,
    // ❌ THIẾU: pub tier_overrides: Option<HashMap<Tier, DdosPutTierBody>>,
    // ❌ THIẾU: pub failure_mode: Option<HashMap<Tier, FailureModeBody>>,
}
```

Kể cả khi DD-01 → DD-05 đã fix, operator vẫn không thể tune per-tier qua dashboard PUT. Phải mở rộng body schema + validate.

**Fix:**

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct DdosPutBody {
    // ...existing fields...
    #[serde(default)]
    pub tier_overrides: HashMap<Tier, DdosPutTierBody>,
    #[serde(default)]
    pub failure_mode: HashMap<Tier, FailureModeBody>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DdosPutTierBody {
    pub per_ip_limit: u64,
    pub per_ip_window_s: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub enum FailureModeBody { FailClose, FailOpen }
```

Validate ở `DdosPutBody::validate()` (line 131-162): mọi `per_ip_limit` per tier phải > 0, `per_ip_window_s` > 0.

---

## DD-07 (latent) · `observe_only` không gate `auto_block`

**Component:** [crates/aegis-security/src/ddos.rs:209+](../../../../crates/aegis-security/src/ddos.rs#L209) (chưa fix từ F-CRITICAL-005 cũ)

Spot-verified: trong nhánh detector check, khi breach ngưỡng, `state.auto_block(ip, ttl)` vẫn được gọi kể cả khi `observe_only=true`. Side-effect khi observe mode defeat mục đích của shadow rollout.

**Fix:**

```rust
if breach {
    if !cfg.observe_only {
        self.state.auto_block(ip, ttl).await.ok();
    }
}
```

---

## Impact

- **§5.2 #03 violation**: single global threshold không thoả mãn "configurable threshold **per route tier**".
- **§5.8 violation**: không có fail-close path cho CRITICAL. Trong Attack Battle scenario 01 (DDoS L4/L7 against WAF), một Redis hiccup degrade WAF thành "no WAF at all" cho cả `/login`, `/otp`, `/deposit`, `/withdrawal`.
- **§5.2 #03 "tính hiệu lực" violation**: operator PUT dashboard với `tier_overrides` → silent drop / 400 schema reject. Mục "thay đổi config phải có hiệu lực ≤10s" failed test sẵn lúc parse.
- **Security Effectiveness rubric (40/120)**: §5.2 #03 là "BẮT BUỘC".
- **Intelligence rubric (20/120)**: "Fail-close/fail-open behavior đúng per endpoint" đếm điểm trực tiếp.
- **Architecture rubric (15/120)**: schema-runtime divergence (config có nhưng runtime ignore) là anti-pattern.

## Round-1 Pass/Fail risk

**CAO**. Reproduction steps cho judge:

```sh
HOST="http://127.0.0.1:8080"
ADMIN="https://127.0.0.1:9443"

# 1. Verify schema parses tier_overrides — sẽ thành công vì schema OK
cat > /tmp/test.yaml <<EOF
ddos:
  tier_overrides:
    critical: { per_ip_limit: 5, per_ip_window_s: 60 }
EOF

# 2. Verify dashboard PUT — sẽ 400 hoặc silent ignore vì DdosPutBody không có field
curl -X PUT "$ADMIN/api/gates/ddos" \
  -H "X-Admin-Secret: $SECRET" \
  -d '{"per_ip_limit": 1000, "per_ip_window_s": 10, "block_ttl_s": 300,
       "spike_multiplier": 3.0, "tightened_per_ip_rps": 20,
       "tier_overrides": {"critical": {"per_ip_limit": 5, "per_ip_window_s": 60}}}'
# Expect: 200 with "tier_overrides" silently dropped by serde

# 3. Hammer /login at 10 RPS — sẽ KHÔNG bị block vì tier_overrides bị drop,
#    global per_ip_limit=1000 áp dụng
for i in $(seq 1 50); do curl -s "$HOST/login" -o /dev/null & done; wait
# Expect: 50 × 200/4xx (login fail) thay vì 429/503 ddos

# 4. Simulate Redis down → spam /login → đáng lẽ fail-close cho CRITICAL,
#    thực tế fail-open
# (Cần stop redis container, expectation: 503 cho /login, nhưng quan sát 200/4xx)
```

## Fix outline summary

| # | File | LoC | Ước tính |
|---|---|---:|---:|
| DD-01 | `aegis-security/src/ddos.rs` thêm `tier_overrides` + `failure_mode` field + helper | ~30 | 30 phút |
| DD-02 | `aegis-security/src/ddos.rs::From` impl preserve field | ~10 | 15 phút |
| DD-03 | `aegis-security/src/ddos.rs` `check()` nhận tier + `check_with_limits` | ~20 | 30 phút |
| DD-04 | `aegis-proxy/src/data_plane.rs` reorder `classify_tier` trước DDoS block | ~10 | 15 phút |
| DD-05 | `aegis-proxy/src/data_plane.rs` Err branch per-tier | ~15 | 20 phút |
| DD-06 | `aegis-control/src/api/gates.rs` `DdosPutBody` + validate | ~25 | 30 phút |
| DD-07 | `aegis-security/src/ddos.rs` gate auto_block on observe_only | ~5 | 10 phút |
| Tests | unit + integration | ~60 | 1h |
| **Tổng** | | **~175 LoC** | **~3.5h** |

## Test plan

### Unit (aegis-security/src/ddos.rs)

```rust
#[tokio::test]
async fn check_respects_per_tier_limit() {
    let cfg = DdosConfig {
        per_ip_limit: 1000,
        per_ip_window_s: 10,
        tier_overrides: HashMap::from([
            (Tier::Critical, DdosTierLimit { per_ip_limit: 5, per_ip_window_s: 60 }),
        ]),
        ..Default::default()
    };
    let runtime = DdosRuntime::new(cfg, mock_state());
    for _ in 0..5 {
        let r = runtime.check(test_ip(), Tier::Critical).await.unwrap();
        assert!(!r.blocked);
    }
    // 6th request must block:
    let r = runtime.check(test_ip(), Tier::Critical).await.unwrap();
    assert!(r.blocked);
}

#[tokio::test]
async fn check_default_tier_uses_global() {
    let cfg = DdosConfig { per_ip_limit: 1000, /* no override for Medium */ ..Default::default() };
    let runtime = DdosRuntime::new(cfg, mock_state());
    for _ in 0..50 {
        let r = runtime.check(test_ip(), Tier::Medium).await.unwrap();
        assert!(!r.blocked);
    }
}

#[tokio::test]
async fn fail_close_on_backend_error_for_critical() {
    let cfg = DdosConfig {
        failure_mode: HashMap::from([(Tier::Critical, FailureMode::FailClose)]),
        ..Default::default()
    };
    let runtime = DdosRuntime::new(cfg, broken_state());
    let r = runtime.check(test_ip(), Tier::Critical).await;
    assert!(matches!(r, Err(_)));  // caller phải interpret là FailClose → 503
}

#[tokio::test]
async fn observe_only_does_not_auto_block() {
    let cfg = DdosConfig { observe_only: true, per_ip_limit: 1, ..Default::default() };
    let state = mock_state();
    let runtime = DdosRuntime::new(cfg, state.clone());
    let _ = runtime.check(test_ip(), Tier::Medium).await.unwrap();
    let _ = runtime.check(test_ip(), Tier::Medium).await.unwrap();
    assert!(!state.is_auto_blocked(test_ip()).await);  // observe_only KHÔNG side-effect
}
```

### Integration (data plane)

```rust
#[tokio::test]
async fn data_plane_503_on_critical_when_redis_down() {
    let proxy = spawn_proxy_with_broken_redis().await;
    let resp = http_get(&proxy, "/login").await;
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers().get("X-WAF-Action").unwrap(), "ddos_fail_close");
}

#[tokio::test]
async fn data_plane_pass_on_static_when_redis_down() {
    let proxy = spawn_proxy_with_broken_redis().await;
    let resp = http_get(&proxy, "/static/main.css").await;
    assert_eq!(resp.status(), 200);  // fail-open cho CATCH-ALL
}
```

### Dashboard

```rust
#[tokio::test]
async fn dashboard_put_tier_overrides_takes_effect() {
    let proxy = spawn_proxy().await;
    // 1. PUT với tier_overrides
    let resp = put_admin(&proxy, "/api/gates/ddos", json!({
        "per_ip_limit": 1000, "per_ip_window_s": 10,
        "block_ttl_s": 300, "spike_multiplier": 3.0,
        "tightened_per_ip_rps": 20,
        "tier_overrides": { "critical": { "per_ip_limit": 5, "per_ip_window_s": 60 } }
    })).await;
    assert_eq!(resp.status(), 200);

    // 2. GET phải read-back tier_overrides
    let body = get_admin(&proxy, "/api/gates/ddos").await;
    assert_eq!(body["tier_overrides"]["critical"]["per_ip_limit"], 5);

    // 3. Hammer /login 6 lần → request thứ 6 phải block
    for i in 0..5 {
        let r = http_get(&proxy, "/login").await;
        assert_ne!(r.headers().get("X-WAF-Action"), Some(&"ddos_blocked".parse().unwrap()));
    }
    let r = http_get(&proxy, "/login").await;
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers().get("X-WAF-Action").unwrap(), "ddos_blocked");
}
```

## Severity rationale

**CRITICAL** vẫn giữ nguyên từ F-CRITICAL-005 (2026-05-17). Tình trạng PARTIAL hiện tại không hạ severity được vì:

1. Spec mandate `per-tier threshold` chưa enforce → §5.2 #03 fail.
2. Spec mandate `fail-close cho CRITICAL` chưa có → §5.8 fail.
3. Schema-runtime divergence tạo *false sense of security* — operator nghĩ đã config xong nhưng thực tế runtime ignore.
4. Attack Battle scenario 01 grade phần này trực tiếp.

Fix nằm trong Sprint 1 của [NEXT-STEPS.md](../2026-05-18-fix-verification/NEXT-STEPS.md) — bắt buộc trước Round-1.

## References

- Finding cũ: [F-CRITICAL-005-ddos-no-per-tier-no-fail-close.md](../2026-05-17-security-audit/F-CRITICAL-005-ddos-no-per-tier-no-fail-close.md)
- Verification report: [05-aegis-security-verification.md](../2026-05-18-fix-verification/05-aegis-security-verification.md) (entry F-CRITICAL-005 — PARTIAL)
- Spec verification: [01-ddos-detailed.md](../2026-05-18-detector-spec-verification/01-ddos-detailed.md)
- Hackathon spec §5.2 #03 + §5.8: `aegis-gate/Hackathon_Doc/RULES.md`
