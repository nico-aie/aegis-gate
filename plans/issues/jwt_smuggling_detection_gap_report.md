# Báo cáo phân tích gap phát hiện: JWT Attacks & HTTP Request Smuggling

**Ngày:** 2026-06-16
**Phạm vi:** WAF `aegis-gate` — rule engine (`crates/aegis-security/src/detectors`)
**Bộ test:** `dataset/testing_dataset/{jwt_attack,http_smuggling}_samples.json` (NovaBet hackathon)
**Mục đích:** Cung cấp dữ liệu trực quan để chuyên gia đánh giá có nên sửa rule engine hay không.
**Trạng thái:** PHÂN TÍCH — chưa áp dụng bất kỳ thay đổi code nào cho JWT/smuggling.

---

## 0. Tóm tắt điều hành (Executive Summary)

| Loại | Mẫu | Detect (live) | Bắt được | Miss | Trong đó FIX được | Trong đó NGOÀI tầm WAF |
|---|---|---|---|---|---|---|
| JWT Attacks | 600 | **72.7%** | 266 (rule A1) + AI | ~334 | **~178** (jku/x5u 85 + exp 72 + kid abs 21) | ~249 (HS256/RS256 alg-confusion, cần key) |
| HTTP Smuggling | 500 | **73.3%** | incidental (AI/CRLF) | ~134 | **toàn bộ** (cần detector + hardening parser) | 0 (nhưng phụ thuộc parser layer) |

**Kết luận nhanh:**
- **JWT:** phần lớn miss (~249/334 ≈ 75%) là **alg-confusion HS256/RS256** — về cấu trúc **không thể phát hiện bằng WAF không giữ key**, ép bắt sẽ false-positive mọi token HS256 hợp lệ. Đây là ranh giới WAF↔gateway. Phần **fix được, FP thấp**: `jku`/`x5u` external (85), `exp` giả mạo (72), `kid` absolute-path (21).
- **Smuggling:** WAF **chưa có detector chuyên biệt**; 73% hiện tại là **tình cờ** (AI + rule CRLF bắt nội dung body). Fix được gần như toàn bộ, nhưng cần xử lý đúng **ở tầng parser** (quan trọng hơn regex) — và **phải verify trước** việc detector có nhìn thấy raw framing headers không.

---

## 1. Lưu ý về phương pháp test (đọc trước khi đánh giá)

Bộ test gửi qua HTTP client (`urllib`). Một HTTP client **không cho gửi** header framing trùng lặp/mâu thuẫn thật (nó tự chuẩn hoá `Content-Length`/`Transfer-Encoding`). Vì vậy bộ test **mô phỏng** smuggling bằng:

- **Tên header biến thể:** `Content-Length2`, `Transfer-Encoding2` (hậu tố "2") — để giả lập "trùng" mà client vẫn gửi đi.
- **CRLF nhúng trong giá trị header:** `Transfer-Encoding: "chunked\r\nX-Smuggled: GET /api/transactions HTTP/1.1"`.
- **Pseudo-header HTTP/2:** `:method`, `:path`, `:scheme`, `:authority` (mô phỏng h2→h1 downgrade).

> ⚠️ **Hệ quả quan trọng cho chuyên gia:** một detector regex quét `RequestView.headers` sẽ thấy được các header mô phỏng này (`Content-Length2`, TE có CRLF...). NHƯNG **smuggling thật trên dây** phụ thuộc cách HTTP parser của WAF (`hyper`) xử lý/khử framing nhập nhằng — và `hyper` có thể đã **tiêu thụ/chuẩn hoá/từ chối** `Content-Length`/`Transfer-Encoding` **trước khi** request tới detector. **Cần verify** `RequestView` có expose raw framing headers không trước khi quyết định viết detector (xem §2.2, mục "Cần xác minh").

---

# PHẦN 1 — JWT ATTACKS

## 1.1 Detector hiện tại

File: `crates/aegis-security/src/detectors/jwt_inspection.rs` (Phase A1).
Cơ chế: Base64URL-decode **phần header (part 0)** của JWT trong `Authorization: Bearer` và mọi giá trị `Cookie`, rồi pattern-match shape tấn công. **Không verify chữ ký, không giữ key** (theo thiết kế — ranh giới WAF vs gateway).

Phase A1 bắt (score 80):
- `jwt_alg_none` — `alg` = `none`/`null`/rỗng (mọi case).
- `jwt_x5c_inline` — header nhúng key material (`x5c`/`jwk`).
- `jwt_kid_injection` — `kid` chứa traversal/SQLi/URL scheme.

## 1.2 Phân bố 600 mẫu (giải mã thật)

`alg`: **HS256 = 297 | RS256 = 156 | none = 147** (none + None).
Header param: `jku = 85 | x5c = 71 | kid = 69`.

| Nhóm | Số | A1 bắt? | Fix được? |
|---|---|---|---|
| `alg: none` | 147 | ✅ | (đã bắt) |
| `x5c`/`jwk` inline key | 71 | ✅ | (đã bắt) |
| `kid` injection (`../`, sqli, url) | 48 | ✅ | (đã bắt) |
| **`jku` external URL** | **85** | ❌ MISS | ✅ **CÓ (keyless)** |
| `kid` absolute-path/special (`/dev/null`...) | 21 | ❌ MISS | ✅ CÓ (mở rộng pattern kid) |
| `exp` giả mạo (>10 năm tương lai) | 72 | ❌ MISS | ✅ CÓ (Phase A3, decode payload) |
| **HS256 / RS256 alg-confusion (không header lạ)** | **~249** | ❌ MISS | ❌ **KHÔNG (cần key/app context)** |

> Lưu ý: các nhóm fix-được có thể chồng lấn (vd token vừa `jku` vừa `exp` giả). Tổng "fix được" ước tính **~150–178** mẫu riêng biệt.

## 1.3 Ví dụ cụ thể (header + payload giải mã + token thật)

### ✅ ĐÃ BẮT — `alg: none`
```
Cookie: sid=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
  header  : {"alg": "none", "typ": "JWT"}
  payload : {"user": "admin", "role": "admin"}      ← bypass chữ ký
```

### ✅ ĐÃ BẮT — `x5c` inline key (self-signed key injection)
```
Cookie: sid=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlD...
  header  : {"alg": "RS256", "typ": "JWT", "x5c": ["MIICIjANBgkqhkiG9w0B...attackerCert=="]}
  payload : {"user": "admin", "role": "admin"}
```

### ❌ MISS — `jku` external (KEY-INJECTION — FIX ĐƯỢC, keyless)
```
Cookie: sid=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzОi8v...
  header  : {"alg": "RS256", "typ": "JWT", "jku": "https://attacker.evil.com/jwks.json"}
  payload : {"user": "admin", "role": "admin"}
```
> Kẻ tấn công trỏ `jku` (JWKS URL) tới server của họ → app tải public key của attacker → token "hợp lệ". **Phát hiện được hoàn toàn bằng cấu trúc, không cần key**: chỉ cần thấy claim `jku`/`x5u` trong header JWT (hoặc trỏ host ngoài). Đây là **Phase A2** trong plan `plans/future/jwt-and-smuggling-detection.md`.

### ❌ MISS — `kid` absolute-path (FIX ĐƯỢC — mở rộng pattern kid)
```
  header  : {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
```
> `kid: /dev/null` (ép app dùng key rỗng/đoán được). Pattern `kid_injection` hiện chỉ bắt `../`, SQLi, URL scheme — **trượt** absolute path `/dev/null`, `/proc/...`. 21 mẫu.

### ❌ MISS — `exp` giả mạo (FIX ĐƯỢC — Phase A3)
```
  header  : {"alg": "HS256", "typ": "JWT"}
  payload : {"user": "admin", "role": "admin", "exp": 4102444800}   ← năm 2100
```
> `exp` xa bất thường (token "bất tử"). Cần decode part 1 (payload) và so `exp` với ngưỡng. 72 mẫu.

### ❌ MISS — HS256/RS256 alg-confusion (NGOÀI TẦM WAF không-key)
```
  header  : {"alg": "HS256", "typ": "JWT"}      ← KHÔNG có claim lạ
  payload : {"user": "admin", "role": "admin"}
```
> Token này **giống hệt** một token HS256 hợp lệ về cấu trúc. WAF không biết app **mong đợi** RS256 (để phát hiện việc hạ xuống HS256), cũng không có public key để thử verify. **Ép flag mọi `alg:HS256` = false-positive 100% traffic HS256 hợp lệ.** Đây là việc của gateway/app (cấu hình "expected alg" + key), không phải WAF chung. ~249 mẫu (~42% bộ test).

## 1.4 Đề xuất sửa JWT (chưa áp dụng)

| # | Đề xuất | File | Logic (gợi ý) | Vớt thêm | FP risk | Effort |
|---|---|---|---|---|---|---|
| J1 | **Rule `jku`/`x5u`** (Phase A2) | `jwt_inspection.rs` | Sau khi decode header part 0: nếu có claim `jku` hoặc `x5u` → flag score 80 (key-injection). Optional: chỉ flag khi URL trỏ host ≠ host request. | ~85 (+14%) | **Rất thấp** — `jku`/`x5u` gần như không xuất hiện trong JWT hợp lệ tại edge | Nhỏ |
| J2 | **Mở rộng `kid_injection`** | `jwt_inspection.rs` | Thêm vào pattern kid: absolute path (`^/`), `/dev/`, `/proc/`, `null` | ~21 (+3.5%) | Thấp | Rất nhỏ |
| J3 | **`exp` forgery** (Phase A3) | `jwt_inspection.rs` | Decode part 1; flag nếu `exp` > now + N năm (vd 5y). Cân nhắc `log_only` vì một số app dùng token đời rất dài. | ~72 (+12%) | Trung bình (token đời dài hợp lệ) → nên `log_only` hoặc ngưỡng rộng | Nhỏ |
| — | HS256/RS256 alg-confusion | — | **KHÔNG đề xuất sửa ở WAF** — cần key/app-context. Thuộc gateway. | — | — | — |

**Trần thực tế của JWT detection (WAF không-key):** alg:none + x5c/jwk + kid + jku/x5u + exp ≈ **~85–88%**. Phần ~12–15% còn lại (HS256 confusion thuần) thuộc gateway. → 72.7% hiện tại còn dư địa **~13–15%** nếu làm J1+J2+J3.

---

# PHẦN 2 — HTTP REQUEST SMUGGLING

## 2.1 Hiện trạng

**KHÔNG có detector smuggling chuyên biệt** trong `crates/aegis-security/src/detectors/` (grep `transfer-encoding|content-length|smuggl|chunked` không có file detector nào). 73.3% detect hiện tại là **tình cờ**: body của payload chứa request nhúng (`GET /admin/dashboard HTTP/1.1\r\nHost:...`) → trip rule CRLF/header_injection hoặc AI; phần không trip gì thì lọt.

## 2.2 Phân bố 500 mẫu (theo pattern header)

| Kỹ thuật | Số | Tín hiệu |
|---|---|---|
| TE + CL cùng lúc (CL.TE / TE.CL) | 251 | có cả `Transfer-Encoding` và `Content-Length` |
| Transfer-Encoding obfuscation (TE.TE) | 85 | `Transfer-Encoding` + `Transfer-Encoding2`, hoặc giá trị lạ |
| Content-Length trùng/mâu thuẫn (CL.CL) | 93 | `Content-Length` + `Content-Length2` khác giá trị |
| HTTP/2 downgrade (H2.TE / H2.CL) | 71 | pseudo-headers `:method`/`:path` + TE/CL |

## 2.3 Ví dụ cụ thể (header + body thật)

### CL.TE / TE.CL — TE và CL cùng lúc (251 mẫu)
```
Headers: {"Host": "...", "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": "6", "Transfer-Encoding": "chunked", "Transfer-Encoding2": "chunked"}
Body   : "0\r\n\r\nGET /api/profile HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\nFoo: x"
```
> Front-end dùng CL, back-end dùng TE (hoặc ngược lại) → "0\r\n\r\n" kết thúc chunk sớm, phần sau (`GET /api/profile...`) bị back-end coi là request **thứ 2** → smuggled.

### CL.CL — duplicate Content-Length (93 mẫu)
```
Headers: {"Host": "...", "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": "13", "Content-Length2": "6"}
Body   : "GET /api/rewards/claim HTTP/1.1\r\nHost: sec-team.waf-exams.info"
```
> Hai Content-Length khác nhau → front/back-end chọn khác nhau → desync.

### TE.TE — Transfer-Encoding obfuscation / header split (85 mẫu)
```
Headers: {"Host": "...", "Content-Type": "application/x-www-form-urlencoded",
          "Transfer-Encoding": "chunked\r\nX-Smuggled: GET /api/transactions HTTP/1.1"}
Body   : "0\r\n\r\n"
```
> **CRLF nhúng trong giá trị `Transfer-Encoding`** tách thành header giả `X-Smuggled: GET ...`.

### H2.TE — HTTP/2 downgrade smuggling (71 mẫu)
```
Headers: {":method": "POST", ":path": "/", ":scheme": "https", ":authority": "...",
          "transfer-encoding": "chunked", "content-type": "application/x-www-form-urlencoded"}
Body   : "0\r\n\r\nGET /admin/dashboard HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\nX-Evil: header"
```
> HTTP/2 không dùng TE/CL, nhưng nếu gateway hạ xuống HTTP/1.1 mà giữ lại `transfer-encoding` của client → desync ở back-end.

## 2.4 Đề xuất sửa Smuggling (chưa áp dụng) — 2 tầng

### Tầng 1 (QUAN TRỌNG NHẤT) — Hardening parser/framing ở `aegis-proxy`
Smuggling về bản chất là lỗi **diễn giải framing**, không phải nội dung. Phòng thủ thật là proxy phải **chuẩn hoá/từ chối** request có framing nhập nhằng TRƯỚC khi forward:
- Có **đồng thời** `Transfer-Encoding` và `Content-Length` → **reject 400** (RFC 7230 §3.3.3).
- Có **>1 `Content-Length`** hoặc giá trị CL không nhất quán → reject 400.
- `Transfer-Encoding` chứa giá trị lạ (không phải đúng `chunked`), có khoảng trắng/CRLF/case obfuscation → reject.
- Khi hạ HTTP/2→HTTP/1.1: **loại bỏ** `transfer-encoding`/`content-length` do client gửi, tự sinh lại framing.

> Đây là việc ở lớp `aegis-proxy` (data plane), không phải detector regex. Bắt được ~100% các lớp TE+CL/CL.CL/TE.TE.

### Tầng 2 (Defense-in-depth) — Detector chuyên biệt `http_smuggling`
Nếu muốn một tín hiệu rõ ràng trong audit/score (ngoài việc reject ở parser):

| # | Rule (gợi ý) | Ví dụ khớp | FP risk |
|---|---|---|---|
| S1 | Có đồng thời TE và CL header | TE.CL/CL.TE 251 mẫu | Rất thấp (hợp lệ không gửi cả hai) |
| S2 | ≥2 header `Content-Length*` hoặc `Transfer-Encoding*` | `Content-Length2`, `Transfer-Encoding2` | Rất thấp |
| S3 | Giá trị TE/CL chứa CRLF hoặc ký tự ngoài `[0-9]`/`chunked` | TE = `chunked\r\nX-Smuggled:...` | Rất thấp |
| S4 | (phụ) Body **bắt đầu bằng** request-line nhúng: `(?i)^\s*\d*\r?\n?\r\n[A-Z]+ /\S* HTTP/1\.` | `0\r\n\r\nGET /admin... HTTP/1.1` | Thấp |

> **⚠️ CẦN XÁC MINH TRƯỚC (blocker cho tầng 2):** liệu `RequestView.headers` (sau khi `hyper` parse) còn giữ được `Transfer-Encoding`/`Content-Length` thô và các header trùng tên không? `hyper` thường **tự khử** các header framing này. Nếu detector **không thấy** chúng → tầng 2 vô dụng và **bắt buộc** làm tầng 1. Cần một thử nghiệm nhỏ: gửi request TE+CL và log `req.headers` thấy gì.

## 2.5 Khuyến nghị Smuggling
1. **Ưu tiên Tầng 1** (parser hardening) — đúng bản chất, bao phủ rộng, không phụ thuộc detector thấy gì.
2. Tầng 2 (detector) chỉ làm **sau khi** xác minh raw framing headers tới được detector; nếu không, bỏ qua tầng 2.
3. Lưu ý nhóm H2 downgrade (71) phải xử lý ở **lớp dịch h2→h1**, không phải regex.

---

## 3. Bảng quyết định tổng hợp (cho chuyên gia)

| Hạng mục | Vớt thêm | FP risk | Effort | Cần retrain AI? | Khuyến nghị |
|---|---|---|---|---|---|
| JWT — J1 `jku`/`x5u` | +14% | rất thấp | nhỏ | ❌ | **NÊN** |
| JWT — J2 `kid` abs-path | +3.5% | thấp | rất nhỏ | ❌ | NÊN |
| JWT — J3 `exp` forgery | +12% | trung bình → `log_only` | nhỏ | ❌ | CÂN NHẮC |
| JWT — HS256 confusion | — | — | — | — | **KHÔNG** (gateway) |
| Smuggling — Tầng 1 parser | ~rộng | thấp | trung bình | ❌ | **NÊN** (fix gốc) |
| Smuggling — Tầng 2 detector | bổ trợ | rất thấp | nhỏ | ❌ | chỉ sau khi verify |

**Không hạng mục nào cần train lại model AI** — tất cả là rule engine / parser layer.

---

## Phụ lục A — Nguồn dữ liệu
- JWT: `dataset/testing_dataset/jwt_attack_samples.json` (600 mẫu, payload trong `Cookie: sid=<jwt>`).
- Smuggling: `dataset/testing_dataset/http_smuggling_samples.json` (500 mẫu).
- Detector liên quan: `crates/aegis-security/src/detectors/jwt_inspection.rs`; (smuggling: chưa có).
- Plan tham chiếu (theo doc-comment trong code): `plans/future/jwt-and-smuggling-detection.md`, memory `project_waf_vs_gateway_boundary`.

## Phụ lục B — Cách tái tạo số liệu
Giải mã/phân loại bằng script Python: lấy token từ `Cookie`, Base64URL-decode part 0 (header) + part 1 (payload), đối chiếu với logic Phase A1 (`alg` none / `x5c`/`jwk` / `kid` patterns). Smuggling: phân loại theo sự hiện diện của `Transfer-Encoding`/`Content-Length*`/pseudo-headers `:method`.
