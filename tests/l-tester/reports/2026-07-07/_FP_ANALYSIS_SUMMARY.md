# FP Analysis — Tổng hợp 18 class (run `20260707_141036`)

**Tổng FP: 5,822 / 1,039,741 effective (0.56%).** Mỗi class có file `<rule>.eval.md` chi tiết kèm root cause + phương hướng fix. Dữ liệu gốc ở `<rule>.txt` (có sẵn dòng `curl` để reproduce).

## Xếp theo số lượng & ưu tiên

| Rule | Fires | % | Ưu tiên | Bản chất FP (tóm tắt) |
|------|------:|---|---------|------------------------|
| `mass-assignment` | 1,318 | 0.13% | 🟡 | POST JSON API/analytics nhiều field bị coi là gán đặc quyền |
| `sqli` | 1,167 | 0.11% | 🟠 | Body bot-sensor/replay obfuscated tình cờ giống cú pháp SQL |
| `command-injection` | 1,100 | 0.11% | 🟠 | Ký tự `$ \| ; ` trong upload/telemetry (PDF, paypal logger, sensor) |
| `xss` | 481 | 0.05% | 🟠 | JS/JSONP hợp lệ trong param SDK (mtop Alibaba), ad tag |
| `template-injection` | 409 | 0.04% | 🟠 | `{{ }}`/`${ }` trong dữ liệu session-replay (onedrive/collect) |
| `ai` | 284 | 0.03% | 🟡 | ML model quá nhạy — cần tune threshold, không phải rule |
| `ssrf` | 281 | 0.03% | 🟠 | URL đầy đủ trong param ad-conversion (`=https://`) |
| `jwt-alg-none` | 208 | 0.02% | 🟢 | 1 site (target): base64 cookie bị parse nhầm thành JWT |
| `jwt-time-forged` | 152 | 0.01% | 🟢 | 1 site (ulta): tương tự, cookie analytics parse nhầm JWT |
| `path-traversal` | 109 | 0.01% | 🟢 | `..%00` trong ID tracking (bidswitch), không phải path |
| `recon-path` | 103 | 0.01% | 🟢 | 88% là 1 endpoint `swagger.json` + GraphQL introspection |
| `header-injection` | 66 | 0.01% | 🟢 | 1 site (manomano): `%0A` trong GraphQL query GET |
| `css-injection` | 40 | 0.00% | 🟢 | 1 endpoint Tealeaf replay (delta) |
| `open-redirect` | 35 | 0.00% | 🟢 | Param redirect ad-sync (`rurl=//`) hợp lệ |
| `method-override-bypass` | 25 | 0.00% | 🟢 | `X-HTTP-Method-Override: PUT` — REST hợp lệ (Gap/Staples) |
| `nosql-injection` | 20 | 0.00% | 🟢 | Key `$type` trong JSON cấu hình (SmartScreen/tRPC) |
| `body-deep-nesting` | 15 | 0.00% | 🟢 | Analytics JSON lồng sâu (LEGO) |
| `body-too-large` | 9 | 0.00% | 🟢 | Upload file thật ~57MB (TikTok/Box/Drive) |

## 4 nhóm root cause chung → fix "một phát ăn nhiều"

**1. Detector content chạy trên body opaque/telemetry/obfuscated** (`sqli`, `command-injection`, `template-injection`, `css-injection`, một phần `xss`)
→ Bỏ inspect (hoặc allowlist) các endpoint **bot-defense & session-replay & analytics**: Akamai `sensor_data`, Tealeaf `TealeafTarget.jsp`, PerimeterX, `/collect`, `/v2/recording`, `/msg`, `/ajax/bnzai`, `/_ajax/ae/createBatch`. Bỏ inspect body nhị phân (magic bytes `%PDF`, octet-stream, entropy cao). **Đây là nhóm chiếm ~2,700/5,822 FP (~46%)** — fix nhóm này giảm gần nửa FP.

**2. Detector query bắt "URL/`//`/`..`/JS trong giá trị param"** (`ssrf`, `open-redirect`, `path-traversal`, `header-injection`, một phần `xss`)
→ Chỉ chấm theo **ngữ cảnh + đích**: SSRF/redirect chỉ khi đích là domain ngoài allowlist / IP nội bộ; traversal chỉ khi có dấu phân cách `../` ở path (không phải `..` trong ID); CRLF chỉ khi đi vào response header. Allowlist endpoint ad/tracking/GraphQL. Tách null byte `%00` thành luật riêng.

**3. Parser JWT quá tham** (`jwt-alg-none`, `jwt-time-forged` — cùng nhau 360 FP, chỉ 2 site)
→ Chỉ nhận JWT khi đúng **3 phần `h.p.s` + decode ra JSON + có claim chuẩn**, và chỉ ở `Authorization: Bearer`/cookie tên `*token*`. Bỏ qua base64 session/visitor id và tài nguyên tĩnh `.js/.css/.svg`. Fix 2 điểm này xoá gần như toàn bộ 360 FP.

**4. Ngưỡng/đặc thù nghiệp vụ** (`mass-assignment`, `nosql-injection`, `method-override-bypass`, `body-deep-nesting`, `body-too-large`, `ai`)
→ Giới hạn theo route (size/độ sâu), whitelist key hệ thống (`$type`), chấp nhận `X-HTTP-Method-Override`, tune threshold ML. Nhiều cái nên hạ severity xuống **cảnh báo** thay vì block.

## Nhận xét chung

- FP rate 0.56% đã thấp, nhưng **tập trung cao**: chỉ ~30 site và một nhóm nhỏ endpoint (bot-sensor, replay, ad-tracking, GraphQL) gây phần lớn FP → allowlist theo (host, path) + phân biệt "ký tự đặc biệt trong dữ liệu vs trong sink thật" sẽ giảm mạnh.
- Ưu tiên xử lý theo thứ tự: **nhóm 1 (body telemetry) → nhóm 3 (JWT) → nhóm 2 (query URL) → nhóm 4**.
- Không class nào là tấn công thật lọt vào — tất cả đều là dương tính giả trên traffic hợp lệ.

---
*Chi tiết từng class: xem `<rule>.eval.md` trong thư mục này. Reproduce: dùng dòng `curl` trong mỗi entry của `<rule>.txt`.*
