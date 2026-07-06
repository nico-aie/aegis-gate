# Báo cáo cho chuyên gia: Cập nhật Detector để bắt các Serious Attack còn lọt

**Hệ thống:** Aegis-Gate WAF (`/Users/sabo/Workspace/waf/aegis-gate`)
**Nguồn:** `load_test/round2_analysis/MISSED_attacks_serious.json` (18 attack nghiêm trọng WAF miss)
**Mục tiêu:** Đề xuất cách vá **detector** để bắt các case này, **ưu tiên tránh false-positive (FP)**.
**Phạm vi:** Chỉ report + đề xuất — KHÔNG sửa code.

---

## 0. Kết luận nhanh (cho người bận)

| Detector | File | Miss | Nguyên nhân gốc | Độ khó vá |
|---|---|---|---|---|
| **SSRF** | `crates/aegis-security/src/detectors/ssrf.rs` | **14** | Pattern thiếu: loopback rút gọn (`127.1`), host single-label nội bộ (`redis:6379`), internal-TLD ngoài ngữ cảnh `@` | Thấp (thêm regex) |
| **Command injection** | `command_injection.rs` | 1 | `$IFS` không đứng sau shell-metachar nên không match; `cat$IFS/…` bị bỏ | Thấp |
| **NoSQL** | `nosql_injection.rs` | 1 | Body có quote bị escape `\"$ne\"` → pattern `"\$ne"` không khớp (thiếu chuẩn hoá JSON-escape) | Thấp |
| **CRLF header** | `header_injection.rs` | 1 | CRLF thô đã bị HTTP parser **tách header trước khi detector chạy** → không còn `\r\n` trong value | Trung bình (cần soi raw bytes) |
| **JS-RCE / proto-pollution** | (body_abuse / command_injection) | 1 | Payload Next.js RSC (`child_process.execSync`, `__proto__`, `constructor:constructor`) không có trong vocabulary | Trung bình |

**Tin tốt về kiến trúc:** cả SSRF/cmd/nosql detector **đã quét `req.body.peek(8192)`** (xem `ssrf.rs:108`, `nosql_injection.rs:91`, `command_injection` header-doc). Vậy phần lớn là **bổ sung pattern**, KHÔNG phải sửa kiến trúc — rủi ro thấp.

---

## 1. SSRF — 14 miss (ưu tiên cao nhất)

### Payload bị lọt
Đều là URL nội bộ nằm trong **field JSON body** (`email`, `url`) tại `PUT /api/profile`, `POST /api/integrations/preview`:
```
http://127.1                      http://127.0.1
http://internal-service:8080      http://database:3306
http://redis:6379                 http://elasticsearch:9200
http://kubernetes.default.svc.cluster.local
```

### Nguyên nhân (đọc `ssrf.rs`)
Detector **có** quét body (`ssrf.rs:108-114`), nhưng `SSRF_PATTERNS` (dòng 10-84) thiếu:

1. **Loopback rút gọn** — dòng 12 chỉ có `127\.0\.0\.1`. `127.1`, `127.0.1`, `127.256`… (dạng viết tắt hợp lệ, resolve về `127.0.0.0/8`) KHÔNG match.
2. **Host single-label nội bộ** (`redis`, `database`, `elasticsearch`, `internal-service`) — chỉ được match trong **ngữ cảnh userinfo `@`** (dòng 51-62, nhánh `[a-z0-9-]+(?:[:/?#]|$)`). URL thẳng `http://redis:6379` (không có `@`) không có pattern nào.
3. **Internal-TLD** (`.internal`/`.local`/`.svc`/`.cluster.local`) — cũng chỉ nằm trong nhánh userinfo `@` (dòng 59). `http://kubernetes.default.svc.cluster.local` thẳng (không `@`) bị bỏ.

### Đề xuất vá (thêm vào `SSRF_PATTERNS`)
1. **Toàn dải loopback `127.0.0.0/8`** — thay/bổ sung: `r"(?i)https?://127(?:\.\d{1,3}){1,3}"` → bắt `127.1`, `127.0.1`, `127.0.0.1`.
   *(FP: `127.x` trong URL công khai gần như không tồn tại → an toàn.)*
2. **Internal-TLD trong URL thẳng** (đưa ra ngoài ngữ cảnh `@`): `r"(?i)https?://[a-z0-9.-]+\.(?:internal|local|svc|cluster\.local)\b"`.
   *(FP: `.local` là mDNS/nội bộ, `.svc`/`.cluster.local` là K8s — không dùng công khai. An toàn. ⚠️ Lưu ý: `.local` đôi khi xuất hiện ở dev — cân nhắc chỉ challenge thay vì block nếu lo.)*
3. **Host single-label + port dịch vụ nội bộ** — chữ ký mạnh, FP thấp: `r"(?i)https?://[a-z0-9-]+:(?:22|3306|5432|6379|9200|9300|27017|11211|8080|9000|2379|5601|15672)\b"` (redis/mysql/pg/es/mongo/memcached…).
   *(FP: URL công khai có FQDN nhiều nhãn + thường port 80/443; single-label + port hạ tầng nội bộ là bất thường rõ. An toàn.)*
4. **(Tuỳ chọn, cẩn thận FP) Host single-label bất kỳ trong URL** `r"(?i)https?://[a-z0-9-]+(?::\d+)?(?:[/?#]|$)"` — bắt `http://internal-service:8080` không port đặc trưng. **Rủi ro FP cao hơn** (một số app dùng hostname nội bộ hợp lệ) → **chỉ nên bật khi field là URL-typed** hoặc để **observe/challenge**, không block cứng.

### Giảm FP cho SSRF (quan trọng)
- Detector đã có gate `form_body_is_opaque_beacon` (`ssrf.rs:113`) để bỏ qua sensor-beacon — **giữ nguyên**.
- Đề xuất #1, #2, #3 nhắm vào **IP loopback dải đầy đủ + internal-TLD + single-label:port-hạ-tầng** → các dấu hiệu này **không xuất hiện trong URL công khai hợp lệ**, FP gần như 0.
- Đề xuất #4 (single-label bất kỳ) mới có rủi ro → **tách riêng, chấm điểm thấp / challenge**, và cân nhắc chỉ áp cho endpoint nhận URL (`/api/integrations/preview`, field `url`/`callback_url`/`webhook`).
- Nên **có allowlist domain nội bộ hợp lệ** (nếu app thật sự gọi 1 vài host nội bộ) để loại trừ trước khi flag.

---

## 2. Command Injection — `cat$IFS/etc/passwd`

### Nguyên nhân (đọc `command_injection.rs`)
- Detector quét body (header-doc dòng 1-2), nhưng theo dòng 88-93: token evasion `$` chỉ được match **SAU shell-metachar** (`;`, `|`, `&&`, `$(`, backtick). `cat$IFS/etc/passwd` bắt đầu bằng **command trần `cat`**, không có metachar dẫn → không khớp.
- Dòng 108-111: pattern `${VAR}` đã **bị gỡ bỏ** để tránh FP với ad-tech macro (`${UUID}`, `${AUCTION_PRICE}`) → `$IFS`/`${IFS}` không còn được nhận.

### Đề xuất vá
- Thêm chữ ký **IFS-evasion** riêng, độc lập: `r"(?i)\$\{?IFS\}?"` (bắt `$IFS`, `${IFS}`, `$IFS$9`).
  *(FP: `$IFS` là biến bash đặc thù, **không xuất hiện trong input hợp lệ** — khác hẳn `${UUID}`. Rủi ro FP rất thấp, an toàn để tách khỏi lý do đã gỡ `${VAR}`.)*
- Bổ sung: **command trần + đường dẫn nhạy cảm** trong body — `r"(?i)\b(?:cat|less|head|tail|nl)\b[^a-z0-9]{1,4}/(?:etc|proc|root|var/log)/"` để bắt `cat<sep>/etc/passwd` kể cả khi `<sep>` là `$IFS`, tab, `%09`…
  *(FP: cân nhắc — chuỗi `cat /etc/...` hiếm trong input người dùng; nhưng nếu app có field free-text, để **observe/score** trước khi block.)*

---

## 3. NoSQL — `{\"$ne\":null}` (quote bị escape)

### Nguyên nhân (đọc `nosql_injection.rs`)
- Detector **có** pattern body `r#"(?i)"\$(?:ne|gt|…)"\s*:"#` (dòng ~63) và quét body (dòng 91-95).
- NHƯNG body thật là `{\"$ne\":null}` — **quote bị backslash-escape** (`\"`). Chuỗi `"$ne"` (quote-liền) **không xuất hiện** vì có `\` trước quote đóng → pattern miss.
- Đây là **JSON-string escaping / double-encoding** evasion.

### Đề xuất vá
- **Chuẩn hoá JSON-escape trước khi match**: bỏ `\` trước `"` (hoặc thêm biến thể) — tương tự cách đã `url_decode`. Sau chuẩn hoá `\"$ne\"` → `"$ne"` → khớp pattern hiện có.
- Hoặc nới pattern chấp nhận backslash tuỳ chọn: `r#"(?i)\\?"\$(?:ne|gt|gte|lt|lte|in|nin|eq|regex|where|…)\\?"\s*:"#`.
  *(FP: vẫn giữ điều kiện quote + tên operator đóng (closed vocabulary) + dấu `:` → FP thấp như bản gốc; chỉ mở thêm cho dạng escape.)*

---

## 4. CRLF Header Injection — `x-custom: value\r\nX-Injected: __V10_CRLF__`

### Nguyên nhân (đọc `header_injection.rs`)
- Detector quét **header value** tìm `%0d%0a`/`\r\n` (dòng 13-17, 72-73).
- NHƯNG payload dùng **CRLF thô (`\r\n`)** → **HTTP parser của WAF đã TÁCH thành 2 header** trước khi detector chạy. Detector chỉ thấy `x-custom: value` (sạch) + `x-injected: __V10_CRLF__` (header riêng) → không còn `\r\n` để bắt.
- Lưu ý: nếu payload là **`%0d%0a` (đã mã hoá)** thì pattern hiện tại **BẮT ĐƯỢC** (value giữ nguyên `%0d%0a`). Chỉ **CRLF thô** mới lọt do parser tách sớm.

### Đề xuất vá (khó hơn — cần thêm tầng)
1. **Soi raw header-block bytes trước khi parse** — tìm dấu hiệu smuggling ở tầng ingress (trước khi `http` parser tách). Đây là cách triệt để.
2. **(Nhẹ hơn) Phát hiện header "bị tiêm"**: cờ khi thấy header **không chuẩn / trùng lặp / tên khả nghi** xuất hiện sau một header do client kiểm soát (vd nhiều `x-injected`, header có tên lạ kề header free-text). Rủi ro FP cao hơn → chỉ nên **observe/log**.
3. **Phòng thủ đầu ra (khuyến nghị mạnh):** đảm bảo WAF **strip mọi CR/LF** khỏi giá trị header trước khi **forward lên upstream** hoặc **phản chiếu vào response** — chặn response-splitting tại nguồn, độc lập với việc phát hiện.

*Ưu tiên: (3) trước (phòng thủ chắc chắn, FP ~0), rồi (1) nếu muốn phát hiện chủ động.*

---

## 5. JS-RCE / Prototype-Pollution — Next.js RSC (`POST /` multipart)

### Payload
```
{"then":"$1:__proto__:then", ... "_prefix":"var res=process.mainModule.require('child_process').execSync('printenv',…)…", "_formData":{"get":"$1:constructor:constructor"}}
```
= prototype pollution (`__proto__`, `constructor:constructor`) + **Node RCE** (`child_process.execSync`) qua React Server Components.

### Đề xuất vá
- Bổ sung vocabulary cho **body_abuse / template_injection**: `__proto__`, `constructor\s*:\s*constructor`, `constructor\.constructor`, `process\.mainModule`, `child_process`, `execSync|spawnSync|\.exec\(`, `require\(['"]child_process`.
  *(FP: các token này **không xuất hiện trong JSON dữ liệu hợp lệ** của app fintech — `__proto__`/`child_process`/`execSync` là đặc thù exploit. FP rất thấp. Cẩn thận với `constructor` đơn lẻ (có thể xuất hiện) → chỉ flag `constructor:constructor`/`constructor.constructor`.)*
- Quét cả **body multipart** (payload này nằm trong `multipart/form-data`).

---

## 6. Nguyên tắc tránh FP (xuyên suốt — theo yêu cầu)

1. **Ưu tiên chữ ký "không thể hợp lệ"**: `127.x` loopback, `.svc/.cluster.local`, port hạ tầng nội bộ, `$IFS`, `__proto__`, `child_process.execSync` — các token này **không tồn tại trong traffic hợp lệ** → thêm thẳng, FP ~0.
2. **Chữ ký mơ hồ hơn** (single-label host bất kỳ, command trần) → **tách riêng, chấm điểm thấp / challenge / observe**, KHÔNG block cứng; cân nhắc chỉ áp cho endpoint nhận URL.
3. **Chuẩn hoá trước khi match**: url-decode (đã có), **thêm JSON-unescape** (`\"`→`"`), double-decode — nhiều miss là do encoding, không phải thiếu pattern.
4. **Field-aware nếu có thể**: SSRF/command chỉ đáng ngờ khi ở field URL/text người dùng nhập; nếu WAF parse được field JSON, giới hạn phạm vi để giảm FP (đánh đổi chi phí — xem chú thích chi phí ở `nosql_injection.rs:29-40`).
5. **Giữ các gate FP đã có**: `form_body_is_opaque_beacon` (sensor beacon), bỏ `Referer` khỏi SSRF, đã gỡ `${VAR}` chung — **đừng revert**; chỉ thêm token cụ thể.
6. **Regression 2 chiều bắt buộc**: sau khi thêm pattern, chạy lại cả tập **benign** (`waf_allowed_api_normal`, `btc_round2_benign`) để đo FP, KHÔNG chỉ đo bắt được attack.

---

## 7. Thứ tự ưu tiên đề xuất

| # | Việc | Bắt thêm | Rủi ro FP | Công sức |
|---|---|---|---|---|
| 1 | SSRF: loopback dải đầy đủ + internal-TLD + single-label:port | 14 | Rất thấp | Nhỏ |
| 2 | Cmd: chữ ký `$IFS`/`${IFS}` độc lập | 1 | Rất thấp | Nhỏ |
| 3 | NoSQL: chuẩn hoá `\"` trước match | 1 | Rất thấp | Nhỏ |
| 4 | JS-RCE/proto: thêm vocab `__proto__`/`child_process`/`execSync` | 1 | Thấp | Nhỏ |
| 5 | CRLF: strip CR/LF khi forward + (tuỳ) soi raw bytes | 1 | Rất thấp (defense) | Trung bình |

## 8. Kế hoạch test sau khi vá
- **Bắt attack**: `python3 load_test/test_recon_detection.py` (đổi sang tập serious) hoặc bắn lại 18 payload trong `MISSED_attacks_serious.json` → mục tiêu 18/18 có detector fire (dùng IP sạch, tránh reputation che).
- **Đo FP**: bắn `dataset/BTC_round2/btc_round2_benign.json` + `round2_analysis/waf_allowed_api_normal.json` → FP content phải < 1%.
- **Truy nguồn**: mỗi payload có `source_request_id`/`hash` trong `MISSED_attacks_serious.json`.

---

*Mọi tham chiếu code theo bản hiện tại của `aegis-gate`. Đề xuất chỉ mang tính hướng dẫn cho chuyên gia — cần review + test trên môi trường trước khi áp production.*
