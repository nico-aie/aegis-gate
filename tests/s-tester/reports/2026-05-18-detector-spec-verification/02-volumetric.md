---
id: 2026-05-18-volumetric-verification
date: 2026-05-18T00:00Z
area: Volumetric / network detectors
spec_ref: §5.2 #02 #03 #06 + §5.3 (brute force)
---

# Volumetric detectors — DDoS + Rate Limit + Brute Force + Blacklist

## 1. DDoS — §5.2 #03 — **FAIL**

Xem [01-ddos-detailed.md](01-ddos-detailed.md) (deep dive đầy đủ).

**Tóm tắt**:
- Spec: ❌ thiếu per-tier, ❌ thiếu fail-close cho CRITICAL.
- Dashboard: ⚠️ PUT `/api/gates/ddos` có sẵn nhưng body schema thiếu `tier_overrides`.
- Hot-reload: ✅ ArcSwap sub-ms.
- §9: ✅.

---

## 2. Rate Limit — §5.2 #02 — **PARTIAL**

### Spec mandate

> Per-IP **VÀ** per user-session — không chỉ per IP. Sliding window. Token bucket cho burst control.

### Code under test

[crates/aegis-security/src/rate_limit/ip_limiter.rs:77-92](../../../../crates/aegis-security/src/rate_limit/ip_limiter.rs#L77)

### A) Spec compliance — **PARTIAL**

- ✅ Sliding window per-IP: `DashMap<IpAddr, VecDeque<Instant>>` tại line 90. Log-based sliding window đúng spec.
- ❌ Per-session: hot path `data_plane.rs:432` gọi `ip_rate_limiter.consume(peer_ip)` — chỉ `IpAddr`. Không có session-id extraction. Helper `sliding::build_key(scope, rule_id, discriminator)` ở `rate_limit/sliding.rs:36` đã tồn tại + chấp nhận discriminator, nhưng call site không truyền session.
- ⚠️ Token bucket: helper `rate_limit/bucket.rs:15` có, nhưng không có production call site (chỉ test).

### B) Dashboard config — **PASS**

- Endpoint: `PUT /api/rate-limit` tại [admin_mutate.rs:3424](../../../../crates/aegis-proxy/src/admin_mutate.rs#L3424) (`handle_rate_limit_put`).
- Body: [gates.rs:201-205](../../../../crates/aegis-control/src/api/gates.rs#L201) — chỉ có `limit` + `window_seconds`. **Thiếu**: per-tier knob, per-session knob.

### C) Hot-reload — **PASS**

- `services.ip_rate_limiter.set_config(...)` ArcSwap::store tại `ip_limiter.rs:111-113`. Sub-ms.

### D) §9 — **PASS**

### Verdict

PARTIAL. Per-IP hoạt động + tune được qua dashboard. Per-session vắng mặt → credential-stuffing với rotation IP nhưng giữ 1 session token sẽ thoát.

---

## 3. Brute Force — §5.3 — **FAIL**

### Spec mandate

> Detect: (a) per-user failed login (cùng username), (b) per-IP-distinct-users (password spraying — 1 IP thử nhiều user khác nhau), (c) per-device. POST-only trên auth path. Method allowlist. Operator tune được threshold/window/score.

### Code under test

[crates/aegis-security/src/detectors/brute_force.rs:26-40](../../../../crates/aegis-security/src/detectors/brute_force.rs#L26)

```rust
pub struct BruteForceDetector {
    pub threshold: u32,
    pub window: Duration,
    pub score: u32,
    state: Mutex<HashMap<IpAddr, Vec<Instant>>>,   // <-- per-IP only
}
```

### A) Spec compliance — **FAIL**

- ❌ **Per-user failed login**: không có. `record_and_check(peer_ip)` chỉ counter theo IP, không parse username từ body.
- ❌ **Password spraying (per-IP-distinct-users)**: không có. Counter chỉ đếm số request, không đếm số username khác nhau.
- ❌ **Per-device**: không có.
- ✅ POST-only trên auth path: line 91-97.
- ✅ Auth path allowlist: line 110-135 (15 alias `/login`, `/signin`, `/auth/*`, etc.).

Grep confirm: `grep -r "spraying\|stuffing" aegis-security/` → 0 hit.

### B) Dashboard config — **FAIL**

- ❌ Không có PUT endpoint. Chỉ on/off được toggle qua mask chung `PUT /api/detectors`.
- ❌ Threshold (10), window (60s), score (40) **hardcoded** tại `brute_force.rs:43-49`, `Default::default()` constructor.
- ❌ Không có `BruteForcePutBody`, không có `set_config`, không có ArcSwap.

### C) Hot-reload — **FAIL**

Operator chỉ flip ON/OFF được qua mask. Không tune được threshold/window.

### D) §9 — **PASS**

### Verdict

FAIL. Detector tồn tại + đếm được rate per-IP, nhưng thiếu 2 chiều mà §5.3 yêu cầu (per-user, distinct-users). Round-1 risk: CAO.

### Fix outline

Tham khảo Sprint 3.3 trong [NEXT-STEPS.md](../2026-05-18-fix-verification/NEXT-STEPS.md#33--security-f-critical-014-brute_force-3-axis-200-loc-6h). Đại ý:

```rust
pub struct BruteForceDetector {
    // Per-username sliding window
    by_user: DashMap<String, VecDeque<Instant>>,
    // Per-IP cardinality counter (distinct usernames trong window)
    by_ip_users: DashMap<IpAddr, HashSet<String>>,
    // Per-device counter
    by_device: DashMap<DeviceId, VecDeque<Instant>>,
    cfg: ArcSwap<BruteForceConfig>,
}
```

Trip nếu BẤT KỲ axis nào vượt threshold riêng.

---

## 4. Blacklist + Whitelist — §5.2 #06 — **PARTIAL**

### Spec mandate

> Manual IP/CIDR blocklist + allowlist. FQDN blocklist. Threat-intel feed load lúc startup. Tor exit node list. Auto risk-boost cho known-bad IP.

### Code under test

- Manual: [crates/aegis-control/src/api/blacklist.rs:224-275](../../../../crates/aegis-control/src/api/blacklist.rs#L224)
- Threat-intel: [crates/aegis-security/src/ip_rep/asn.rs:53](../../../../crates/aegis-security/src/ip_rep/asn.rs#L53)

### A) Spec compliance — **PARTIAL**

- ✅ Manual blocklist/allowlist: `AccessListStore` full CRUD. `matches(peer_ip, lookup_ref)` được gọi tại `data_plane.rs:260`.
- ⚠️ FQDN: type `AccessListEntry` có field domain, nhưng path tra cứu trong `data_plane.rs` không scan FQDN (only IP).
- ❌ Threat-intel feed: `cfg.threat_intel` **không tồn tại** trong `aegis-core/src/config.rs` (grep: 0 hit). `admin_get.rs:322-328` tự khai báo: `"configured_in_yaml": false, "note": "Feed-management UI ships in Phase 4"`.
- ❌ Tor exit list: schema `asn.rs:53 tor_exits: Vec<IpAddr>` có, `classify()` tại line 99 đọc, nhưng `run.rs` không bao giờ populate (init rỗng tại line 79: `tor_exits: Vec::new()`).
- ⚠️ Auto risk-boost: schema có `tor_delta: 15` tại asn.rs:14, nhưng feed rỗng nên không kích hoạt.

### B) Dashboard config — **PASS**

- 654 LoC ở `api/blacklist.rs` — endpoint `list/get/put/delete/bulk_insert` đầy đủ.

### C) Hot-reload — **PASS**

- DashMap là storage backend → mọi put/delete áp dụng ngay cho lookup tiếp theo.

### D) §9 — **PASS**

### Verdict

PARTIAL. Manual blocklist OK, threat-intel feed loader chưa làm.

---

## Summary Volumetric

| Detector | Spec | Dashboard | Hot-reload | Verdict |
|---|---|---|---|---|
| DDoS | FAIL (no tier, no fail-close) | ⚠️ PUT có nhưng thiếu tier_overrides | ✅ | **FAIL** |
| Rate Limit | PARTIAL (IP only) | ✅ | ✅ | **PARTIAL** |
| Brute Force | FAIL (no spraying, no per-user) | ❌ on/off only | ❌ hardcoded | **FAIL** |
| Blacklist | PARTIAL (no feed load, no Tor) | ✅ CRUD đầy đủ | ✅ DashMap | **PARTIAL** |
