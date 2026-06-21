# Aegis-Gate WAF — Cơ chế Spike (DDoS surge) — review & đề xuất fix

> **Mục đích:** Gửi chuyên gia phân tích & fix. Báo cáo review cơ chế **Spike** (phát hiện lưu lượng đột tăng > N× bình thường → siết rate-limit) trong DDoS detector, chỉ ra lỗ hổng, hướng config chuẩn (có research), và cách test.
>
> - **Service:** `aegis-gate` (Rust WAF reverse proxy)
> - **Ngày:** 2026-06-20
> - **Severity:** 🔴 High — cơ chế surge-protection cho Round 3 Attack Battle (DDoS L7 flood)
> - **Phạm vi:** `crates/aegis-security/src/ddos.rs` (spike detection + enforcement), `config.rs` (DdosConfig)
>
> **Ghi chú phạm vi (chủ ý vận hành):** Việc EWMA baseline thích nghi theo lưu lượng kéo dài (spike tự nhả khi mức cao trở thành "bình thường mới") là **CHỦ ĐÍCH thiết kế — KHÔNG nằm trong phạm vi báo cáo này**. Báo cáo chỉ xử lý các vấn đề khác.

---

## TL;DR

Cơ chế Spike **phát hiện đúng** (EWMA baseline + multiplier, tick mỗi giây) nhưng có một lỗ hổng nghiêm trọng và vài điểm cần cải thiện:

| # | Vấn đề | Mức độ | Bản chất |
|---|---|---|---|
| 1 | **Spike phát hiện nhưng KHÔNG siết gì cả** | 🔴 Critical | `tightened_per_ip_rps` khai báo + validate + hiện dashboard nhưng **0 chỗ enforce**; `spike_active` chỉ dùng cho telemetry |
| 2 | **Per-node, không cluster-wide** | 🟡 Medium | Comment ghi "cluster-wide" nhưng `rolling_rps` là counter cục bộ |
| 3 | **Không hysteresis/dwell → flap** | 🟡 Medium | `spike_active` flip on/off mỗi tick, dễ dao động |

→ **Hệ quả:** Trong Attack Battle, một HTTP flood sẽ làm dashboard sáng đèn `ddos_spike_active = true` nhưng **rate-limit không hề siết lại** — IP tấn công vẫn được bắn tới `per_ip_limit` thường (60000/window). Spike mode hiện là **"observability theater"**.

---

## 1. Cơ chế hiện tại (đã verify trong code)

**Phát hiện (detection):** `tick_rps()` chạy mỗi giây ([ddos.rs:616](../aegis-gate/crates/aegis-security/src/ddos.rs#L616), ticker tại [run.rs:1069](../aegis-gate/crates/aegis-proxy/src/run.rs#L1069)):
- `rolling_rps` đếm request, swap về 0 mỗi tick.
- EWMA cập nhật `baseline_rps`.
- `spike_active = current > baseline × spike_multiplier && baseline > 10` (multiplier mặc định 3.0).

**Config (DdosConfig):**
```yaml
# config/dev.yaml
spike_multiplier: 3.0       # current > 3 × baseline → spike_active
tightened_per_ip_rps: 20    # "Per-IP RPS cap during cluster spike mode"
per_ip_limit: 60000         # limit thường (rất lỏng)
```

**Getter sẵn có để expose metric:** `current_rps()` / `baseline_rps()` / `is_spike_active()` ([ddos.rs:386-395](../aegis-gate/crates/aegis-security/src/ddos.rs#L386)).

---

## 2. CHỖ LỖI — phân tích chi tiết

### 2.1 [🔴 Critical] Spike phát hiện nhưng không siết — `tightened_per_ip_rps` là config chết

**Bằng chứng:**

1. Đường enforce thật là `check_local` ([ddos.rs:425](../aegis-gate/crates/aegis-security/src/ddos.rs#L425)) → gọi `cfg.limit_for(tier)`. Hàm này **không biết gì về spike**:
   ```rust
   // ddos.rs:86 — limit_for KHÔNG tham chiếu spike_active / tightened_per_ip_rps
   pub fn limit_for(&self, tier: Option<Tier>) -> (u64, u32) {
       match tier.and_then(|t| self.tier_overrides.get(&t)) {
           Some(l) => (l.per_ip_limit, l.per_ip_window_s),
           None    => (self.per_ip_limit, self.per_ip_window_s),  // ← luôn limit thường
       }
   }
   ```
2. `check_local` dùng thẳng kết quả đó làm ngưỡng block — **không có nhánh `if spike_active { dùng tightened }`**.
3. `grep tightened_per_ip_rps` toàn repo: chỉ xuất hiện ở **config schema / API gates / dashboard display / validate** ("must be > 0") — **0 chỗ trong đường enforcement** (`check_local`, `limit_for`, rate-limit).
4. `is_spike_active()` / `spike_active` chỉ được đọc để **đổ vào telemetry**:
   - field `spike_active` trong result struct ([ddos.rs:315,349](../aegis-gate/crates/aegis-security/src/ddos.rs#L315))
   - audit JSON `ddos_spike_active` ([data_plane.rs:623](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L623))
   - không có chỗ nào dùng nó để **đổi hành vi enforce**.

→ **Kết luận:** Spike mode bật cờ + log + hiện dashboard, nhưng **không siết bất kỳ limit nào**. Đây là pattern "config chết" (giống `QuotaConfig.read_timeout` ở report trước: khai báo, validate, surface — nhưng không enforce).

**Lưu ý đơn vị (quan trọng khi fix):** `tightened_per_ip_rps` là **RPS** (req/giây), còn `per_ip_limit` là **số request trên cả `per_ip_window_s`**. Khi nối enforcement phải quy đổi:
```
tightened_window_limit = tightened_per_ip_rps × per_ip_window_s
```
(vd 20 rps × 10 s = 200 request/window thay cho 60000).

**Hướng fix — vị trí chèn:** trong `check_local` ([ddos.rs:~444](../aegis-gate/crates/aegis-security/src/ddos.rs#L444)), sau khi lấy `limit_for`:
```rust
let (mut per_ip_limit, per_ip_window_s) = cfg.limit_for(tier);
// ── SPIKE ENFORCEMENT (mới) ──────────────────────────────
if self.is_spike_active() {
    let tightened = cfg.tightened_per_ip_rps
        .saturating_mul(u64::from(per_ip_window_s));   // RPS → per-window
    per_ip_limit = per_ip_limit.min(tightened);        // siết, không nới
}
// ─────────────────────────────────────────────────────────
```
**Cùng sửa cho biến thể Redis** `check_with_tier(state, …)` ([ddos.rs:588](../aegis-gate/crates/aegis-security/src/ddos.rs#L588)) nếu đường đó còn được bật ở config nào.

### 2.2 [🟡 Medium] Per-node, không cluster-wide

**Bằng chứng:** `rolling_rps: AtomicU64` ([ddos.rs:177](../aegis-gate/crates/aegis-security/src/ddos.rs#L177)) là counter **cục bộ trong process**, dù field config được mô tả là *"Cluster-wide RPS multiplier"* ([ddos.rs:50](../aegis-gate/crates/aegis-security/src/ddos.rs#L50)) và `tightened_per_ip_rps` ghi *"during cluster spike mode"*. Config cũng tự thừa nhận *"cluster-wire deferred"* ([dev.yaml:356](../aegis-gate/config/dev.yaml#L356)).

**Hệ quả:** Triển khai nhiều node sau LB → mỗi node chỉ thấy phần RPS của nó. Một spike chia đều cho N node có thể không node nào vượt ngưỡng cục bộ → spike không bật dù tổng cụm đang bị flood.

**Hướng fix:** nếu cần cluster-wide, cộng dồn `rolling_rps` qua Redis (vd `INCR` per-tick key + đọc tổng) hoặc gossip; nếu chấp nhận per-node thì **sửa lại tên/comment cho khớp** (tránh hiểu nhầm khi vận hành). Với hackathon single-node thì per-node là đủ — chỉ cần làm rõ.

### 2.3 [🟡 Medium] Không có hysteresis/dwell → flap

**Bằng chứng:** `tick_rps` đặt `spike_active = 1/0` **ngay trong tick đó** dựa trên so sánh tức thời ([ddos.rs:638-642](../aegis-gate/crates/aegis-security/src/ddos.rs#L638)). Không có yêu cầu "N tick liên tiếp" để bật, cũng không có cooldown để tắt.

**Hệ quả:** Traffic dao động quanh ngưỡng → `spike_active` nhấp nháy on/off mỗi giây → enforcement (sau khi nối ở 2.1) cũng bật/tắt liên tục, gây hành vi khó đoán cho cả traffic thường lẫn dashboard.

**Hướng fix:** thêm bộ đếm dwell:
- **Bật:** cần ≥ **2–3 tick liên tiếp** `current > threshold`.
- **Tắt:** cần ≥ **5–10 tick liên tiếp** dưới ngưỡng (cooldown).

---

## 3. Config sao cho chuẩn (theo research)

Research về adaptive rate-limiting / surge detection xác nhận:

| Khía cạnh | Khuyến nghị | Ghi chú research |
|---|---|---|
| **Detect ↔ Enforce** | Tách 2 tầng RÕ RÀNG: phát hiện (cờ) **và** siết thật. | Hiện chỉ có tầng phát hiện — thiếu nửa enforce (2.1). |
| **Ngưỡng** | `baseline × 3–5` là khoảng chuẩn cho surge; nâng cấp: **σ-band `baseline + k·σ`** (k=3–4) để tự thích nghi theo độ dao động. | EWMA + adaptive threshold; σ-band giảm báo nhầm khi traffic nhiễu. |
| **`spike_multiplier`** | giữ 3.0 (hoặc 3–5 tuỳ khẩu vị) | nằm trong khoảng chuẩn. |
| **`tightened_per_ip_rps`** | 20–50 RPS/IP — **bắt buộc enforce** | giá trị hiện 20 hợp lý, vấn đề là chưa nối. |
| **Hysteresis/dwell** | bật 2–3 tick / tắt 5–10 tick | chống flap (2.3). |
| **Granularity** | tick 1s ok; cân nhắc 500ms nếu cần bắt micro-burst | đánh đổi nhiễu vs độ trễ phát hiện. |

### Bảng config đề xuất

| Tham số | Hiện tại | Đề xuất |
|---|---|---|
| `spike_multiplier` | 3.0 | 3.0–5.0 (giữ) |
| `tightened_per_ip_rps` | 20 (**chưa enforce**) | 20–50, **PHẢI enforce** (2.1) |
| `per_ip_limit` (thường) | 60000 | giữ (baseline lỏng) |
| Hysteresis bật/tắt | — | 2 tick / 8 tick (2.3) |
| Phạm vi đếm | per-node | per-node (làm rõ) hoặc cluster qua Redis (2.2) |

---

## 4. Cách test

### Tầng 1 — Unit test `tick_rps` (deterministic)
Bơm chuỗi RPS giả lập, assert chuyển trạng thái:
1. **Warmup:** baseline hội tụ về mức bình thường sau N tick.
2. **Spike start:** `current` nhảy 5× → `spike_active == true`.
3. **Hysteresis (cho 2.3 sau khi fix):** dao động quanh ngưỡng → `spike_active` **không flap** (chỉ bật sau ≥2 tick, tắt sau cooldown).

### Tầng 2 — Test ENFORCEMENT (bắt lỗi 2.1 — quan trọng nhất)
- Ép `spike_active = true` (qua tick giả lập), cho 1 IP bắn ở mức **giữa `tightened` và `per_ip_limit`** (vd 100 rps; tightened=20×window, normal=60000).
- **Assert:** IP bị block/limit vì spike dùng ngưỡng tightened.
- **Hiện tại test này SẼ FAIL** (enforcement chưa nối) → đúng là test chứng minh lỗi 2.1. Sau fix phải PASS.
- Kèm test: khi `spike_active = false`, cùng IP/mức đó **không** bị block (đảm bảo chỉ siết lúc spike).

### Tầng 3 — Load test end-to-end (k6 / vegeta / wrk)
1. **Warm baseline:** ~1000 rps đều trong 60s (EWMA hội tụ).
2. **Spike:** nhảy đột ngột lên **5×** (5000 rps) từ **nhiều source IP** (xem lưu ý dưới).
3. **Assert đồng thời:**
   - `ddos_spike_active = true` trên dashboard/audit (observability).
   - IP tấn công bị siết về `tightened_per_ip_rps` (block rate tăng rõ).
   - Traffic hợp lệ rate thấp vẫn được phục vụ (BTC cho phép `collateral` nhưng không nên giết hết).
4. **Cooldown:** dừng spike → `spike_active` clear theo cooldown, traffic về bình thường.

**Metric quan sát:** `baseline_rps`, `current_rps`, gauge `spike_active`, block-rate per-IP — expose qua getter sẵn có ([ddos.rs:386-395](../aegis-gate/crates/aegis-security/src/ddos.rs#L386)).

> **Lưu ý môi trường test:** BTC quy ước nhiều `127.0.0.x` = nhiều client riêng biệt (Contract §6). Load test spike phải **giả lập nhiều source IP**, không bắn từ 1 IP — nếu không sẽ lẫn với hot-key contention (1 DashMap shard) và sai kết quả.

---

## 5. File/line map (đã verify 2026-06-20)

| Thing | File:line |
|---|---|
| `tick_rps` (EWMA + đặt spike_active) | [ddos.rs:616](../aegis-gate/crates/aegis-security/src/ddos.rs#L616) |
| Ticker 1s gọi `tick_rps` | [run.rs:1069](../aegis-gate/crates/aegis-proxy/src/run.rs#L1069) |
| `limit_for` (KHÔNG dùng spike/tightened) | [ddos.rs:86](../aegis-gate/crates/aegis-security/src/ddos.rs#L86) |
| `check_local` (đường enforce — nơi chèn fix 2.1) | [ddos.rs:425-444](../aegis-gate/crates/aegis-security/src/ddos.rs#L425) |
| `tightened_per_ip_rps` field (config chết) | [ddos.rs:54](../aegis-gate/crates/aegis-security/src/ddos.rs#L54), [config.rs:4219](../aegis-gate/crates/aegis-core/src/config.rs#L4219) |
| `spike_active` chỉ dùng telemetry | [ddos.rs:315,349](../aegis-gate/crates/aegis-security/src/ddos.rs#L315), [data_plane.rs:623](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L623) |
| `rolling_rps` (per-node, không cluster) | [ddos.rs:177](../aegis-gate/crates/aegis-security/src/ddos.rs#L177) |
| Biến thể Redis `check_with_tier` (cũng dùng limit_for) | [ddos.rs:588](../aegis-gate/crates/aegis-security/src/ddos.rs#L588) |
| Getter metric | [ddos.rs:386-395](../aegis-gate/crates/aegis-security/src/ddos.rs#L386) |

---

## 6. Tham chiếu

- BTC Rulebook §5.3 (DDoS Protection: burst + auto-block + threshold per tier), §7 (Attack vector #01 HTTP flood).
- [EWMA Statistic in Adaptive Threshold Algorithm (ResearchGate)](https://www.researchgate.net/publication/4266041_EWMA_Statistic_in_Adaptive_Threshold_Algorithm)
- [Adaptive EWMA Method for Abnormal Network Traffic / LDoS (Wiley)](https://onlinelibrary.wiley.com/doi/10.1155/2014/496376)
- [Network Anomaly Detection — baseline + σ tolerance (Kentik)](https://www.kentik.com/kentipedia/network-anomaly-detection/)
- [Anomaly Detection — EWMA / z-score / MAD (CDC pynssp)](https://cdcgov.github.io/pynssp/articles/anomaly_detection.html)

---

*Tóm tắt: Cơ chế Spike phát hiện đúng nhưng (1) KHÔNG nối enforcement — `tightened_per_ip_rps` là config chết, `spike_active` chỉ để telemetry → spike không siết gì; (2) đếm per-node dù mang tên cluster-wide; (3) thiếu hysteresis → flap. Fix trọng tâm: trong `check_local`, khi `spike_active` thì siết `per_ip_limit` xuống `tightened_per_ip_rps × window`. Test bắt buộc: test enforcement (hiện FAIL) + load test multi-IP spike 5×.*
