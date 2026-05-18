---
folder: 2026-05-17-proxy-full-audit/
agent: Agent C (verification)
date: 2026-05-18T00:00Z
status: 7 FIXED / 2 PARTIAL / 1 NOT_FIXED (10 total)
---

# proxy-full-audit fix verification — chi tiết

## Status table

| ID | Title | Status | Evidence |
|---|---|---|---|
| F-CRITICAL-001 | H3 bypass — không security pipeline | **NOT_FIXED** | `listener/http3.rs:290` VẪN gọi `crate::proxy::handle_request`. Không capture `connection.remote_address()`. Không gọi `data_plane::handle_data_request`. Không `stamp_interop_response`. |
| F-CRITICAL-002 | Admin listener không có session auth gate | **FIXED** | `accept.rs:947-970` chạy `admit()` trước dispatch. `admin_auth_middleware.rs:104,156,166,196` enforce IP allow-list → session/bearer → CSRF → identity injection. |
| F-CRITICAL-003 | TOTP không wired vào login | **FIXED** | `api/login.rs:210-256` gọi `totp::verify_and_consume` giữa `verify_password` và `LoginOutcome::Ok`. |
| F-CRITICAL-004 | X-Actor spoof | **FIXED** | `admin_mutate.rs:1434-1439` đọc injected `x-aegis-actor`; middleware strip `x-actor`; không còn `x-actor` reads in admin_mutate.rs. |
| F-CRITICAL-005 | CSRF/session entropy | **FIXED** | `csrf.rs:14-16` và `session.rs:178-185` dùng `uuid::Uuid::new_v4().simple()` (backed by getrandom = OS CSPRNG, tương đương OsRng). |
| F-CRITICAL-006 | Dead modules shed/quota/dr/traffic | **PARTIAL** | `shed::LoadShedder` đã wired (`run.rs:713` + `proxy.rs:140`). Nhưng `quota`, `dr`, `traffic` vẫn `pub mod` trong `lib.rs:40,46,55` với **zero callers** workspace-wide. Spec yêu cầu "wired in OR deleted". |
| F-CRITICAL-007 | In-memory token bucket broken | **FIXED** | `state/in_memory.rs:301-322` — `encode_bucket` store `ts.saturating_duration_since(bucket_epoch())`; `decode_bucket` reconstruct real `Instant` từ nanos. |
| F-CRITICAL-008 | Member.inflight RAII | **FIXED** | `proxy.rs:347` và `data_plane.rs:1620` dùng `member.inflight_guard()` (Drop-based). |
| F-CRITICAL-009 | CORS preflight unwrap | **FIXED** | `transform/cors.rs:141-143` dùng `let Ok(..) = HeaderValue::from_str(&allow_origin) else { return; }` thay `unwrap()`. |
| F-CRITICAL-010 | WS upstream header smuggling | **PARTIAL** | `proto/ws_forward.rs:143-148` enforce 16 KiB head cap; lines 208-221 validate header name/value qua `HeaderName::from_bytes` / `HeaderValue::from_str` với errors. **Thiếu**: `Sec-WebSocket-Accept` recompute / verify against client-supplied `Sec-WebSocket-Key`. |

## Cần fix tiếp

### 🚨 F-CRITICAL-001 (NOT_FIXED) — TOP PRIORITY

**Vấn đề**: HTTP/3 path tại `listener/http3.rs:290` vẫn:

```rust
let resp = match crate::proxy::handle_request(hyper_req, ctx).await {
    // bare router, no security pipeline
};
```

Hệ quả:
- Tất cả 6 §5 mandatory headers MISSING trên H3 responses
- §10 peer identity không capture (Quinn `connection.remote_address()` không đọc)
- Không có audit chain entry cho H3 traffic
- Detectors / rate-limit / risk / blacklist SKIPPED trên H3

Bất kỳ phase benchmark nào exercise H3 → contract failure trên mọi test case.

**Fix**:

```diff
-while let Some((req, mut stream)) = h3_conn.accept().await? {
+let peer = connection.remote_address();
+while let Some((req, mut stream)) = h3_conn.accept().await? {
     ...
-    let resp = match crate::proxy::handle_request(hyper_req, ctx).await {
-        Ok(r) => r,
-        Err(e) => { ... }
-    };
+    let request_start = std::time::Instant::now();
+    let (resp, decision) = crate::data_plane::handle_data_request(
+        hyper_req, peer,
+        &ctx.detectors, &ctx.mask, &ctx.risk,
+        &ctx.ip_rate_limiter, &ctx.load_gauge, &ctx.verbosity,
+        // ... (giống call site H1/H2 ở accept.rs:1129)
+    ).await;
+    let resp = crate::admin_dispatch::stamp_interop_response(
+        resp, decision, ctx.interop.as_ref(), peer, &method, &path, score, request_start,
+    );
     ...
 }
```

Cần plumb `DataPlaneCtx` (detectors, risk, rate limiter, etc.) vào `Http3Server` struct.

### F-CRITICAL-006 (PARTIAL) — xóa hoặc wire 3 module dead

`crates/aegis-proxy/src/lib.rs:40,46,55`:

```diff
-pub mod dr;
-pub mod quota;
-pub mod traffic;
```

Hoặc:
- Wire `quota` vào data plane (gọi `check_request_quota()` ở `data_plane::handle_data_request` đầu)
- Wire `dr` vào `aegis-bin/snapshot.rs` thay vì có 2 implementation song song
- Wire `traffic` vào upstream forward path nếu cần canary/mirror

Khuyến nghị: **xóa cả 3** vì hiện tại README mô tả các feature này mà code không deliver.

### F-CRITICAL-010 (PARTIAL) — thêm Sec-WebSocket-Accept verify

Thiếu: recompute expected `Sec-WebSocket-Accept` từ client `Sec-WebSocket-Key` và reject nếu upstream trả khác.

```rust
// proto/ws_forward.rs — sau khi parse upstream response head
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

Defense-in-depth: ngăn upstream-malicious cấu thành tunnel client không authorize.

## Đánh giá

7/10 fully fixed (70%). Issue lớn nhất: **H3 bypass** — một dòng code chưa đổi mà gây fail contract toàn bộ QUIC surface. Fix relatively straightforward (~80 LoC).
