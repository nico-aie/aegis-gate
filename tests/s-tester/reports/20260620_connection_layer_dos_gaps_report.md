# Aegis-Gate WAF — 2 lỗ hổng tầng connection chống DoS (RUDY + Connection Exhaustion)

> **Mục đích:** Gửi chuyên gia phân tích & fix. Báo cáo chỉ ra 2 gap ở **tầng connection/transport** (trước tầng load-shedder), kèm **vị trí chèn code chính xác**, **cách giữ tương thích với drain protocol (SIGUSR2 handover)**, và tiêu chí nghiệm thu.
>
> - **Service:** `aegis-gate` (Rust WAF reverse proxy)
> - **Ngày:** 2026-06-20
> - **Severity:** 🔴 High — map thẳng vào **Attack Vector #01** của BTC (DDoS L4&7 / **Slowloris** / **RUDY** / **connection exhaustion**) trong Round 3 Attack Battle
> - **Phạm vi:** `accept.rs` (accept loop), `data_plane.rs` (body read), `config.rs` (`QuotaConfig`)
> - **Liên quan:** report load-shedder placement (2 gap này nằm *trước* tầng shedder — fix shedder xong vẫn còn 2 lỗ này)

---

## TL;DR

| # | Gap | Bản chất | Bằng chứng cốt lõi |
|---|---|---|---|
| 1 | **RUDY — thiếu request-body read deadline** | Slow-POST trickle body giữ kết nối vô thời hạn | `collect().await` **không timeout** ([data_plane.rs:866](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L866)); `QuotaConfig.read_timeout`/`total_deadline` **khai báo nhưng 0 chỗ enforce** |
| 2 | **Connection exhaustion — thiếu cap kết nối ở accept** | Mở vô số TLS conn, cạn fd/CPU trước khi vào L7 | `accept_loop` accept+spawn **vô điều kiện**; `InFlightCounter` chỉ **đếm** không **cap** ([hotbin.rs:510](../aegis-gate/crates/aegis-proxy/src/hotbin.rs#L510)) |

Cả hai đều bị **load-shedder bỏ lọt** vì shedder chạy *bên trong* handler L7, **sau** accept + bắt tay TLS + đọc body.

---

## GAP 1 — RUDY: thiếu request-body read deadline

### 1.1 Kịch bản tấn công (BTC vector #01)
Attacker gửi `POST` với `Content-Length` hợp lệ (trong cap), header gửi nhanh, rồi **trickle body vài byte mỗi vài giây**. WAF chờ đọc đủ body → mỗi connection ngậm 1 tokio task + 1 slot tài nguyên trong **phút/giờ**, CPU/bandwidth ~0 → vài trăm connection là cạn tài nguyên. Rate-limit không bắt được (lưu lượng cực thấp).

### 1.2 Bằng chứng (đã verify trong code)
WAF đọc body **không có timeout nào bọc quanh**:
```rust
// crates/aegis-proxy/src/data_plane.rs:866
let body_bytes = match http_body_util::Limited::new(body, max_body_bytes)
    .collect()
    .await          // ← chờ vô thời hạn cho tới khi đủ body
{ ... };
```
- `handle_data_request(...).await` tại [accept.rs:1885](../aegis-gate/crates/aegis-proxy/src/accept.rs#L1885) — **không** có `tokio::time::timeout` bọc ngoài.
- **`HEADER_READ_TIMEOUT: 10s`** ([accept.rs:45](../aegis-gate/crates/aegis-proxy/src/accept.rs#L45)) chỉ tính thời gian đọc **headers** → RUDY gửi headers nhanh, qua ải này rồi mới trickle body.
- **Body size-cap (`Limited`)** chỉ chặn body **quá to** → body nhỏ-mà-chậm không chạm cap.
- **🔑 Bằng chứng mạnh nhất:** `QuotaConfig` **đã có sẵn** các knob đúng ngữ nghĩa nhưng **chưa ai enforce**:
  ```rust
  // crates/aegis-core/src/config.rs (struct QuotaConfig)
  pub read_timeout: Duration,    // "Read timeout for the request (→ 408)"
  pub total_deadline: Duration,  // "Total request deadline (→ 504)"
  ```
  [quota.rs::check_request_quota](../aegis-gate/crates/aegis-proxy/src/quota.rs#L42) chỉ enforce `max_uri_length` / `max_header_size` / `client_max_body_size`. **`grep '.read_timeout|.total_deadline'` trên toàn bộ proxy+security = 0 usage** → đây là **config chết**.

### 1.3 Hướng fix — vị trí chèn chính xác

**Cách A (tối thiểu, đúng trọng tâm RUDY): bọc body read bằng `read_timeout` → 408.**
Sửa tại [data_plane.rs:866](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L866):
```rust
// TRƯỚC:
let body_bytes = match http_body_util::Limited::new(body, max_body_bytes)
    .collect().await { ... };

// SAU (sketch):
let read_to = upstream_ctx.quota.read_timeout;          // wire QuotaConfig vào ProxyContext
let collected = tokio::time::timeout(
    read_to,
    http_body_util::Limited::new(body, max_body_bytes).collect(),
).await;
let body_bytes = match collected {
    Err(_elapsed) => {                                   // hết giờ đọc body = RUDY
        return (
            Response::builder()
                .status(hyper::StatusCode::REQUEST_TIMEOUT)   // 408
                .body(crate::body::full(Bytes::from(
                    serde_json::json!({"error":"request_body_timeout"}).to_string()
                ))).unwrap(),
            DecisionTag::timeout("slow-body"),           // → X-WAF-Action: timeout (Contract §3)
        );
    }
    Ok(Ok(c)) => c.to_bytes(),
    Ok(Err(e)) => { /* giữ nguyên nhánh LengthLimitError / body_read_error hiện có */ }
};
```

**Cách B (bổ sung, phòng thủ sâu): total request deadline → 504.**
Bọc cả future handler tại call-site [accept.rs:1885](../aegis-gate/crates/aegis-proxy/src/accept.rs#L1885):
```rust
let (resp, decision) = match tokio::time::timeout(
    quota.total_deadline,
    handle_data_request(req, peer, /* … */),
).await {
    Ok(pair) => pair,
    Err(_) => (gateway_timeout_504(), DecisionTag::timeout("deadline")),
};
```
`request_start` đã có sẵn ([data_plane.rs:291](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L291)) nếu cần đo phần đã tiêu.

**Khuyến nghị:** làm **cả A và B**. A trả `408` đúng ngữ nghĩa "client gửi chậm"; B là lưới chặn cuối cho mọi nguồn treo (slow upstream, detector kẹt). Cả hai **chỉ cần wire knob đã có**, không cần thêm schema config.

### 1.4 Lưu ý action mapping (Contract v2.6 §3-4)
Slow-loris / connection-level → action **`timeout`** (không phải `rate_limit`). Trả `DecisionTag::timeout(...)` để `X-WAF-Action: timeout` đúng contract — BTC chấm mục này.

---

## GAP 2 — Connection exhaustion: thiếu cap kết nối ở accept

### 2.1 Kịch bản tấn công (BTC vector #01)
Attacker **mở thật nhiều kết nối TCP/TLS** (không cần gửi nhiều request). Mỗi conn tốn: 1 tokio task + bắt tay TLS (crypto đắt) + 1 fd. WAF chấp nhận vô tội vạ → cạn fd/CPU/memory ở **tầng kết nối**, trước khi bất kỳ logic per-request (kể cả load-shedder) chạy.

### 2.2 Bằng chứng (đã verify trong code)
Vòng `accept_loop` ([accept.rs:1512](../aegis-gate/crates/aegis-proxy/src/accept.rs#L1512)):
```rust
loop {
    let (mut stream, mut peer) = tcp.accept().await ...;   // accept VÔ ĐIỀU KIỆN
    ... clone handles ...
    let conn_inflight = upstream_ctx.inflight.clone();
    tokio::spawn(async move {                              // spawn VÔ ĐIỀU KIỆN
        let _admit = conn_inflight.admit();                // ← chỉ ĐẾM, KHÔNG cap
        ... TLS handshake ... serve_connection ...
    });
}
```
`InFlightCounter::admit()` chỉ là bộ đếm:
```rust
// crates/aegis-proxy/src/hotbin.rs:510
pub fn admit(&self) -> InFlightGuard {
    self.inner.fetch_add(1, SeqCst);     // chỉ +1, không so ngưỡng, không reject
    InFlightGuard { counter: self.inner.clone() }
}
```
Comment trong code ghi rõ nó dùng cho **drain lúc SIGUSR2** ("wait until in-flight == 0"), **không phải** để giới hạn. Grep `Semaphore|max_conn|backlog|somaxconn|socket2` ở tầng accept → **rỗng** (chỉ có giới hạn ngầm OS: `somaxconn`, `ulimit -n`; backlog mặc định tokio).

### 2.3 Hướng fix — vị trí chèn chính xác

**Thêm `Semaphore` (cap số connection đồng thời) acquire TRƯỚC `tokio::spawn`.**

1. Tạo cap ở `ProxyContext` (cạnh `inflight`, [proxy.rs:46](../aegis-gate/crates/aegis-proxy/src/proxy.rs#L46)):
```rust
pub conn_limit: Arc<tokio::sync::Semaphore>,   // khởi tạo = Semaphore::new(cfg.max_connections)
```
2. Sửa `accept_loop` tại [accept.rs:1512-1549](../aegis-gate/crates/aegis-proxy/src/accept.rs#L1512):
```rust
loop {
    let (mut stream, mut peer) = match tcp.accept().await { ... };

    // ── CONNECTION CAP (mới) ─────────────────────────────────
    // try_acquire: KHÔNG block accept loop. Hết slot = đóng ngay
    // ở tầng TCP (không thể gửi 503 trước TLS một cách rẻ).
    let permit = match upstream_ctx.conn_limit.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            conn_reject_metric.inc();          // observability cho dashboard
            drop(stream);                      // đóng connection, KHÔNG spawn
            continue;                          // ← quan trọng: không gọi inflight.admit()
        }
    };
    // ─────────────────────────────────────────────────────────

    ... clone handles ...
    let conn_inflight = upstream_ctx.inflight.clone();
    tokio::spawn(async move {
        let _permit = permit;                  // giữ permit suốt đời connection; drop khi xong
        let _admit  = conn_inflight.admit();   // GIỮ NGUYÊN — drain counter
        ... TLS handshake ... serve_connection ...
    });
}
```

**Vì sao `try_acquire_owned` + `continue` (không `acquire().await`):**
- `acquire().await` sẽ **block accept loop** khi hết slot → connection mới dồn vào OS backlog (vẫn tốn fd, và là một dạng nghẽn). `try_acquire` cho phép **từ chối tức thì** (đóng socket) — đúng tinh thần "reject rẻ ở cửa".
- Đóng ở tầng TCP là chấp nhận được cho connection-flood: chưa có TLS nên không gửi HTTP response nhã nhặn được. Per-request (sau TLS) thì load-shedder đã trả `503` như cũ.

**Bổ sung (rẻ, nên làm):** set backlog tường minh + kiểm tra OS:
- Dùng `socket2`/`TcpSocket` để `listen(backlog=4096)` thay vì mặc định, và tài liệu hoá yêu cầu `somaxconn` / `ulimit -n` cho deploy.

### 2.4 ⚠️ Tương thích với DRAIN PROTOCOL (SIGUSR2 handover) — BẮT BUỘC đọc

Đây là phần dễ làm hỏng nhất. Hai cơ chế **độc lập về mục đích** nhưng **cùng vòng đời = connection**:

| Cơ chế | Mục đích | Hành vi |
|---|---|---|
| `InFlightCounter` ([hotbin.rs:496](../aegis-gate/crates/aegis-proxy/src/hotbin.rs#L496)) | **Gauge** cho drain | `admit()` +1 khi conn bắt đầu, guard −1 khi conn kết thúc; handover chờ về 0 |
| `Semaphore conn_limit` (mới) | **Cap** cho admission | `try_acquire` lấy permit, drop khi conn kết thúc |

**Quy tắc để KHÔNG phá drain:**

1. **Connection bị từ chối (hết permit) KHÔNG được gọi `conn_inflight.admit()`.**
   → Trong sketch trên, ta `continue` **trước** khi tạo `conn_inflight` clone / spawn. Nếu admit() rồi mới reject thì drain counter bị thổi phồng bởi conn đã đóng → handover treo chờ mãi. **Thứ tự: check permit → reject sớm → mới admit.**

2. **Permit và inflight-guard phải cùng được drop khi connection kết thúc.**
   → Cả `_permit` và `_admit` đều là RAII, cùng move vào task, cùng drop khi task end. Không leak slot khi conn panic/cancel (giống lý do `admit_guard`/`InFlightGuard` hiện có).

3. **Drain (SIGUSR2) đã dừng accept connection mới** ở tầng handover → semaphore không xen vào điều kiện `inflight == 0`. Khi drain, không có `try_acquire` mới; các permit đang giữ sẽ tự nhả khi conn cũ đóng — đồng pha với inflight giảm về 0. **Không xung đột.**

4. **Không thay đổi ngữ nghĩa `InFlightCounter`** — giữ nguyên `admit()`/guard. Cap là một lớp *thêm vào trước*, không sửa gauge.

→ Tóm lại: cap là **lớp admission độc lập đặt trước `admit()`**; miễn là **reject xảy ra trước khi admit()** và **permit drop cùng connection**, drain protocol hoạt động y như cũ.

---

## 3. Bổ sung config (tái dùng tối đa knob đã có)

```yaml
# RUDY — đã có sẵn trong QuotaConfig, chỉ cần WIRE (không cần thêm field)
quota:
  read_timeout: "10s"      # → 408 khi body đọc quá lâu (hiện chưa enforce)
  total_deadline: "30s"    # → 504 deadline toàn request (hiện chưa enforce)

# Connection cap — field MỚI (đề xuất, đặt ở listener/runtime config)
listeners:
  data:
    - bind: "..."
      max_connections: 20000     # cap conn đồng thời / listener
      accept_backlog: 4096       # listen() backlog tường minh
```
- RUDY (Gap 1): **không cần schema mới** — `read_timeout`/`total_deadline` đã tồn tại, chỉ thiếu enforce.
- Connection cap (Gap 2): thêm `max_connections` (+ `accept_backlog`). Nên configurable, có default an toàn.

---

## 4. Tiêu chí nghiệm thu (acceptance)

**Gap 1 — RUDY:**
1. Mở connection gửi body 1 byte / 5s → WAF đóng với **`408` + `X-WAF-Action: timeout`** trong khoảng `read_timeout`, **không** giữ task vô hạn.
2. POST hợp lệ tốc độ bình thường (kể cả body lớn sát cap) **vẫn pass** — không false-timeout.
3. Verify bằng profiler/metric: số task treo ở `collect()` bị chặn ở mức bounded khi bị RUDY-flood.

**Gap 2 — Connection exhaustion:**
4. Mở > `max_connections` kết nối đồng thời → conn vượt ngưỡng bị **đóng ngay ở TCP** (không bắt tay TLS), CPU crypto không tăng vọt; conn trong ngưỡng vẫn phục vụ bình thường.
5. **Drain test (regression bắt buộc):** gửi SIGUSR2 handover trong lúc có cả conn bị-reject lẫn conn-đang-phục-vụ → `InFlightCounter` về 0 đúng, handover hoàn tất, **không treo**. (Chứng minh quy tắc §2.4.1 đúng.)
6. Connection-flood không còn kéo p99/throughput của traffic hợp lệ sụp (goodput plateau giữ vững — phối hợp với fix load-shedder).

---

## 5. File/line map (đã verify 2026-06-20)

| Thing | File:line |
|---|---|
| Body read **không timeout** (RUDY) | [data_plane.rs:866](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L866) |
| `handle_data_request` call (chèn total_deadline) | [accept.rs:1885](../aegis-gate/crates/aegis-proxy/src/accept.rs#L1885) |
| `HEADER_READ_TIMEOUT` (chỉ cover headers) | [accept.rs:45](../aegis-gate/crates/aegis-proxy/src/accept.rs#L45) |
| `QuotaConfig.read_timeout`/`total_deadline` (khai báo, **0 enforce**) | `config.rs` (struct `QuotaConfig`, ~2060-2074) |
| `check_request_quota` (chỉ enforce size, không timeout) | [quota.rs:42](../aegis-gate/crates/aegis-proxy/src/quota.rs#L42) |
| `accept_loop` (accept+spawn vô điều kiện) | [accept.rs:1512-1549](../aegis-gate/crates/aegis-proxy/src/accept.rs#L1512) |
| `InFlightCounter::admit` (count-only, không cap) | [hotbin.rs:510](../aegis-gate/crates/aegis-proxy/src/hotbin.rs#L510) |
| `InFlightGuard` Drop (−1 cho drain) | [hotbin.rs:537](../aegis-gate/crates/aegis-proxy/src/hotbin.rs#L537) |
| `ProxyContext.inflight` (nơi thêm `conn_limit`) | [proxy.rs:46](../aegis-gate/crates/aegis-proxy/src/proxy.rs#L46) |
| Load-shedder (chạy *sau* TLS+body, không cover 2 gap này) | [data_plane.rs:950](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L950) |

---

## 6. Tham chiếu

- BTC Rulebook §7 — Attack Battle, vector #01 (DDoS L4&7, Slowloris, **RUDY**, connection exhaustion); §5.8 Graceful Degradation.
- BTC Interop Contract v2.6 §3-4 — action `timeout` cho slow-loris/connection-level; `circuit_breaker` cho upstream.
- Cloudflare / OWASP — Slow HTTP DoS (Slowloris, RUDY/R-U-Dead-Yet): chống bằng request/body read deadline + connection cap, không bằng rate-limit theo request.

---

*Tóm tắt: hai gap đều ở tầng connection, nằm TRƯỚC load-shedder. (1) RUDY: `collect().await` không deadline — fix bằng cách wire `QuotaConfig.read_timeout`→408 (và `total_deadline`→504) đã có sẵn nhưng chưa enforce. (2) Connection exhaustion: `accept_loop` accept+spawn vô điều kiện, `InFlightCounter` chỉ đếm — fix bằng `Semaphore` cap acquire TRƯỚC spawn, reject-rẻ ở TCP. Giữ drain protocol an toàn bằng quy tắc: reject TRƯỚC khi admit(), permit drop cùng connection.*
