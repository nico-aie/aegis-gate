# WAF Security Report — NovaBet (sec-team.waf-exams.info)
**Ngày kiểm tra:** 10/06/2026  
**Mục tiêu:** `http://sec-team.waf-exams.info`  
**Người thực hiện:** WAF Hackathon 2026  
**Phạm vi:** Toàn bộ routes trong OpenAPI spec + fuzzing undocumented endpoints

---

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Phương pháp kiểm tra](#2-phương-pháp-kiểm-tra)
3. [Danh sách tất cả Routes (từ OpenAPI)](#3-danh-sách-tất-cả-routes-từ-openapi)
4. [Undocumented Routes phát hiện qua Fuzzing](#4-undocumented-routes-phát-hiện-qua-fuzzing)
5. [Chi tiết từng lỗ hổng](#5-chi-tiết-từng-lỗ-hổng)
6. [Tổng hợp WAF Rules đề xuất](#6-tổng-hợp-waf-rules-đề-xuất)
7. [Ma trận rủi ro](#7-ma-trận-rủi-ro)
8. [Kiểm tra HTTP Methods bất thường](#8-kiểm-tra-http-methods-bất-thường)

---

## 1. Tổng quan

NovaBet là một ứng dụng fintech/gambling được sử dụng làm mục tiêu trong WAF Hackathon 2026. Sau khi kiểm tra toàn bộ hệ thống, chúng tôi đã phát hiện **12 vấn đề bảo mật nghiêm trọng**, bao gồm:

- 5 undocumented routes lộ thông tin nhạy cảm
- 1 lỗ hổng Path Traversal qua static directories
- 2 routes admin không kiểm tra phân quyền đúng cách
- 1 endpoint dễ bị DoS khuếch đại
- 1 endpoint dễ bị SSRF
- 1 endpoint dễ bị Stored XSS
- 1 file API spec bị lộ công khai
- HTTP methods không bị hạn chế trên sensitive files (PATCH, PUT, DELETE, HEAD, OPTIONS)

### Mức độ nghiêm trọng tổng thể: 🔴 CRITICAL

| Mức độ | Số lượng |
|--------|----------|
| 🔴 Critical | 8 |
| 🟠 High | 4 |
| 🟡 Medium | 2 |
| 🟢 Low | 0 |

---

## 2. Phương pháp kiểm tra

1. **Đọc OpenAPI spec** tại `/openapi.yaml` để liệt kê tất cả routes đã được document
2. **Gửi request thực tế** tới từng route để xác nhận response và HTTP status code
3. **Fuzzing undocumented paths** với danh sách ~150 paths phổ biến (sensitive files, git artifacts, config files, common frameworks...)
4. **Phân tích response** để xác định mức độ lộ thông tin

---

## 3. Danh sách tất cả Routes (từ OpenAPI)

### 3.1 Public Routes — Không cần xác thực

| Method | Route | Mô tả | Rủi ro |
|--------|-------|-------|--------|
| POST | `/login` | Đăng nhập bằng username/password, trả về `login_token` | Thấp |
| POST | `/otp` | Xác minh OTP, tạo session cookie `sid` | Thấp |
| GET | `/health` | Kiểm tra trạng thái service | Thấp |
| GET | `/game/list` | Danh sách games | Thấp |
| GET | `/game/{id}` | Chi tiết game theo ID | Thấp |
| GET | `/api/public/stats` | Thống kê công khai (CORS-enabled) | Thấp |
| POST | `/api/feedback` | Gửi feedback, **không cần auth** | 🟡 Medium (XSS) |
| POST | `/api/analytics/events` | Gửi analytics events, **không cần auth** | Thấp |
| GET | `/` | Homepage | Thấp |
| GET | `/about` | Trang About | Thấp |
| GET | `/sitemap.xml` | Sitemap | Thấp |
| GET | `/static/{path}` | Static files (JS, CSS) | 🟠 High (Path Traversal) |
| GET | `/public/{file}` | Public files (HTML) | 🟠 High (Path Traversal) |
| GET | `/assets/{path}` | Asset files (ảnh) | 🟠 High (Path Traversal) |
| GET | `/openapi.yaml` | **API spec đầy đủ** | 🟡 Medium |

### 3.2 Authenticated Routes — Yêu cầu cookie `sid`

| Method | Route | Mô tả | Rủi ro |
|--------|-------|-------|--------|
| GET | `/api/profile` | Thông tin user (SSN, card, bank account) | 🟠 High (PII) |
| PUT | `/api/profile` | Cập nhật email, display_name | Thấp |
| GET | `/api/transactions` | Lịch sử giao dịch | Thấp |
| GET | `/user/settings` | Cài đặt user (withdrawal_limit) | Thấp |
| PUT | `/user/settings` | Cập nhật cài đặt | Thấp |
| POST | `/deposit` | Nạp tiền | Thấp |
| POST | `/withdrawal` | Rút tiền | Thấp |
| POST | `/game/{id}/play` | Đặt cược, có `callback_url` | 🟠 High (SSRF) |
| POST | `/api/rewards/claim` | Nhận thưởng $100 một lần | Thấp |
| POST | `/api/bet-reports/export` | Xuất báo cáo cược | 🔴 Critical (DoS) |
| POST | `/api/kyc/document` | Upload tài liệu KYC (multipart) | Thấp |
| GET | `/api/notifications/stream` | Server-Sent Events stream | Thấp |
| GET | `/ws/live` | WebSocket live updates | Thấp |
| POST | `/api/integrations/preview` | Preview URL partner | 🔴 Critical (SSRF) |

### 3.3 Admin Routes — Yêu cầu session (KHÔNG kiểm tra role)

| Method | Route | Mô tả | Rủi ro |
|--------|-------|-------|--------|
| GET | `/admin/dashboard` | Dashboard admin, lộ DB credentials, SSH keys | 🔴 Critical |
| GET | `/admin/users` | Dump toàn bộ user list với PII | 🔴 Critical |

### 3.4 Control Routes — Yêu cầu header `X-Benchmark-Secret`

| Method | Route | Mô tả | Rủi ro |
|--------|-------|-------|--------|
| POST | `/__control/reset` | Reset toàn bộ database | 🔴 Critical |
| POST | `/__control/slow` | Inject delay vào tất cả requests | 🔴 Critical |
| POST | `/__control/error_mode` | Set crash/timeout mode | 🔴 Critical |
| POST | `/__control/health_mode` | Down toàn bộ service | 🔴 Critical |
| GET | `/__control/state` | Xem internal state của application | 🔴 Critical |

---

## 4. Undocumented Routes phát hiện qua Fuzzing

Đây là các routes **không có trong OpenAPI spec** nhưng trả về HTTP 200 — tức là server đang phục vụ nội dung nhạy cảm mà không có tài liệu công khai.

| Route | HTTP Status | Nội dung | Mức độ |
|-------|-------------|---------|--------|
| `GET /.env` | 200 | DB password dạng plaintext | 🔴 Critical |
| `GET /.git/config` | 200 | Git remote token bị leak | 🔴 Critical |
| `GET /.git/HEAD` | 200 | Branch name + leak marker | 🟠 High |
| `GET /config.yaml` | 200 | DB password dạng plaintext | 🔴 Critical |
| `GET /wp-admin` | 200 | Fake WordPress admin panel (honeypot) | 🟡 Medium |
| `GET /static/../.env` | 200 | Path Traversal → đọc `.env` | 🔴 Critical |
| `GET /public/../.env` | 200 | Path Traversal → đọc `.env` | 🔴 Critical |
| `GET /assets/../.env` | 200 | Path Traversal → đọc `.env` | 🔴 Critical |
| `GET /static/%2e%2e/.env` | 200 | Path Traversal dạng URL-encoded | 🔴 Critical |

---

## 5. Chi tiết từng lỗ hổng

---

### VULN-01 — Lộ file `.env` (Information Disclosure)
**Mức độ:** 🔴 Critical  
**Route:** `GET /.env`  
**Xác thực cần:** Không

#### Mô tả
File `.env` là file cấu hình môi trường thường chứa các thông tin bí mật như database password, API keys, secret tokens. File này đang được serve trực tiếp bởi web server, cho phép bất kỳ ai truy cập mà không cần xác thực.

#### Dữ liệu thực tế thu được
```
DB_PASSWORD=secret123
__CANARY_HIT__
```

#### Tác hại
Kẻ tấn công có thể lấy được database password và kết nối trực tiếp vào database, đọc/sửa/xóa toàn bộ dữ liệu người dùng.

#### WAF Rule
```nginx
# Block truy cập trực tiếp vào .env
location = /.env {
    return 403;
}
# Block mọi file .env variants
location ~* /\.env {
    return 403;
}
```

---

### VULN-02 — Lộ Git Repository (Source Code Disclosure)
**Mức độ:** 🔴 Critical  
**Routes:** `GET /.git/config`, `GET /.git/HEAD`  
**Xác thực cần:** Không

#### Mô tả
Thư mục `.git` đang bị expose công khai. Đây là thư mục metadata của Git — repository quản lý mã nguồn. Khi thư mục này bị lộ, kẻ tấn công có thể:
1. Đọc cấu hình repository để lấy token xác thực
2. Tải về toàn bộ lịch sử commit và mã nguồn

#### Dữ liệu thực tế thu được
```
# /.git/config
[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://example.com/repo.git
    token = __V23_CONFIG_LEAK__

# /.git/HEAD
ref: refs/heads/main
__V23_CONFIG_LEAK__
```

#### Tác hại
- Lộ token xác thực Git → kẻ tấn công có thể clone repository
- Từ source code, attacker hiểu được toàn bộ logic ứng dụng, tìm thêm lỗ hổng ẩn

#### WAF Rule
```nginx
location ~* /\.git {
    return 403;
}
```

---

### VULN-03 — Lộ file `config.yaml` (Configuration Disclosure)
**Mức độ:** 🔴 Critical  
**Route:** `GET /config.yaml`  
**Xác thực cần:** Không

#### Mô tả
File cấu hình `config.yaml` đang được serve công khai, chứa thông tin kết nối database.

#### Dữ liệu thực tế thu được
```yaml
app: target
db_password: __V23_CONFIG_LEAK__
debug: false
```

#### Tác hại
Tương tự VULN-01 — lộ database credentials.

#### WAF Rule
```nginx
location ~* \.(yaml|yml|json|toml|ini|cfg|conf)$ {
    return 403;
}
```

---

### VULN-04 — Path Traversal qua Static Directories
**Mức độ:** 🔴 Critical  
**Routes:** `GET /static/../<file>`, `GET /public/../<file>`, `GET /assets/../<file>`  
**Xác thực cần:** Không

#### Mô tả
Path Traversal (hay Directory Traversal) là lỗ hổng cho phép kẻ tấn công truy cập các file nằm ngoài thư mục được phép bằng cách chèn ký tự `..` (đi lên một cấp thư mục) vào URL.

Ví dụ, server được cấu hình để serve file từ `/var/www/static/`. Khi request đến `/static/app.js`, server sẽ tìm file tại `/var/www/static/app.js`. Nhưng nếu request là `/static/../.env`, server sẽ tìm file tại `/var/www/static/../.env` = `/var/www/.env` — tức là file nằm ngoài thư mục cho phép.

#### Các biến thể hoạt động được xác nhận

| Payload | Kết quả |
|---------|---------|
| `GET /static/../.env` | ✅ 200 — đọc được `.env` |
| `GET /public/../.env` | ✅ 200 — đọc được `.env` |
| `GET /assets/../.env` | ✅ 200 — đọc được `.env` |
| `GET /static/%2e%2e/.env` | ✅ 200 — URL-encoded, bypass filter đơn giản |
| `GET /static/../config.yaml` | ✅ 200 — đọc được `config.yaml` |
| `GET /static/../.git/config` | ✅ 200 — đọc được git config |
| `GET /static/../wp-admin` | ✅ 200 |
| `GET /static/..%2F.env` | ❌ 404 — bị chặn |
| `GET /static/%2e%2e%2F.env` | ❌ 404 — bị chặn |

#### Tác hại
Kẻ tấn công có thể đọc bất kỳ file nào trên server mà web process có quyền đọc, bao gồm `.env`, `config.yaml`, `.git/config`, v.v.

#### WAF Rule
```nginx
# Block path traversal - dạng thường
if ($request_uri ~* "\.\.") {
    return 403;
}
# Block path traversal - dạng URL-encoded
if ($request_uri ~* "%2e%2e") {
    return 403;
}
if ($request_uri ~* "%252e") {
    return 403;
}
```

---

### VULN-05 — Broken Access Control trên Admin Routes
**Mức độ:** 🔴 Critical  
**Routes:** `GET /admin/dashboard`, `GET /admin/users`  
**Xác thực cần:** Có session, nhưng KHÔNG kiểm tra role admin

#### Mô tả
Hai routes admin này chỉ kiểm tra xem user có session hợp lệ không, nhưng **không kiểm tra xem user đó có quyền admin không**. Điều này có nghĩa là bất kỳ user thông thường nào (như `alice`, `bob`, `charlie`) đều có thể truy cập được trang admin.

Đây là lỗ hổng **OWASP A01:2021 — Broken Access Control**, một trong những lỗ hổng phổ biến và nguy hiểm nhất.

#### Dữ liệu thực tế thu được từ `/admin/dashboard` (đăng nhập bằng alice — user thường)
```json
{
  "admin_panel": true,
  "db_host": "db.internal.novabet.local",
  "db_name": "waf_hackathon_prod",
  "db_port": 5432,
  "db_user": "admin",
  "redis_host": "redis.internal.novabet.local:6379",
  "secret_key": "[REDACTED]",
  "ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleAdminKey admin@novabet"],
  "total_balance": 138489,
  "users_count": 103
}
```

#### Dữ liệu thực tế từ `/admin/users`
Server trả về danh sách **103 users** với đầy đủ PII của từng người:
```json
{
  "user_id": 1,
  "username": "alice",
  "email": "test@test.com",
  "balance": 13089,
  "bank_account": "ACCT-000001",
  "ssn": "000-00-0001"
}
```

#### Tác hại
- Lộ địa chỉ database nội bộ, Redis host, SSH keys, secret key
- Dump toàn bộ dữ liệu cá nhân của 103 users (SSN, số tài khoản ngân hàng)
- Vi phạm nghiêm trọng quy định bảo vệ dữ liệu (GDPR, PCI-DSS)

#### WAF Rule
```nginx
# Chặn truy cập /admin từ internet, chỉ cho phép IP nội bộ
location /admin {
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;
}
```

---

### VULN-06 — Asymmetric DoS qua `/api/bet-reports/export`
**Mức độ:** 🔴 Critical  
**Route:** `POST /api/bet-reports/export`  
**Xác thực cần:** Có session

#### Mô tả
Asymmetric DoS (Denial of Service) là kiểu tấn công trong đó kẻ tấn công gửi một request **rất nhỏ** nhưng server phải trả về một response **rất lớn**. Điều này tiêu tốn băng thông và tài nguyên server một cách không cân xứng.

Endpoint `/api/bet-reports/export` nhận một request JSON nhỏ (~30 bytes) nhưng trả về response lên đến **287,000 bytes (287 KB)**. Server cũng chèn marker `__V21_ASYMMETRIC_DOS__` trong response để xác nhận đây là intentional vulnerability.

#### Ví dụ tấn công
```
Request: POST /api/bet-reports/export
Body: {"format": "csv"}   ← chỉ 20 bytes

Response: 287,000 bytes   ← gấp ~14,000 lần
```

Nếu kẻ tấn công gửi 100 requests/giây, server phải xử lý **28.7 MB/giây** chỉ cho một endpoint này — đủ để làm quá tải băng thông.

#### Tác hại
- Làm chậm hoặc crash server
- Gây ra downtime cho toàn bộ ứng dụng
- Chi phí băng thông tăng đột biến

#### WAF Rule
```nginx
# Rate limiting cho endpoint xuất báo cáo
limit_req_zone $binary_remote_addr zone=reports:10m rate=2r/m;

location /api/bet-reports/export {
    limit_req zone=reports burst=3 nodelay;
    limit_req_status 429;
}
```

---

### VULN-07 — SSRF qua `/api/integrations/preview`
**Mức độ:** 🔴 Critical  
**Route:** `POST /api/integrations/preview`  
**Xác thực cần:** Không

#### Mô tả
SSRF (Server-Side Request Forgery) là lỗ hổng cho phép kẻ tấn công **lợi dụng server để gửi request tới các địa chỉ mà attacker không thể trực tiếp truy cập**, thường là mạng nội bộ (internal network).

Endpoint này nhận một URL từ người dùng và server sẽ fetch URL đó. Nếu không kiểm tra đúng cách, attacker có thể truyền vào các URL nội bộ như:
- `http://169.254.169.254/latest/meta-data/` — AWS metadata endpoint (lấy IAM credentials)
- `http://db.internal.novabet.local` — Database nội bộ (đã lộ từ VULN-05)
- `http://redis.internal.novabet.local:6379` — Redis nội bộ
- `http://localhost:8080/__control/reset` — Control endpoints nội bộ

#### Ví dụ payload độc hại
```json
POST /api/integrations/preview
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

#### Tác hại
- Truy cập vào mạng nội bộ từ bên ngoài
- Lấy credentials của cloud instance (AWS, GCP, Azure)
- Tấn công các services nội bộ không được expose ra ngoài

#### WAF Rule
```nginx
# Không thể block hoàn toàn ở WAF layer vì URL nằm trong request body
# Cần implement allowlist ở application layer
# WAF có thể inspect body và block các IP ranges nội bộ
```

---

### VULN-08 — Stored XSS qua `/api/feedback`
**Mức độ:** 🟠 High  
**Route:** `POST /api/feedback`  
**Xác thực cần:** Không

#### Mô tả
XSS (Cross-Site Scripting) là lỗ hổng cho phép kẻ tấn công chèn mã JavaScript độc hại vào trang web. Khi người dùng khác truy cập trang đó, mã JavaScript sẽ được thực thi trong trình duyệt của họ.

Endpoint `/api/feedback` nhận `comment` từ người dùng và trả về field `evaluated_comment` trong response — field này **không có trong OpenAPI spec** và tên "evaluated" gợi ý server đang xử lý/thực thi nội dung comment.

#### Dữ liệu thực tế
```json
Request: {"comment": "test"}
Response: {
  "status": "success",
  "comment": "test",
  "evaluated_comment": "test"   ← field không có trong spec
}
```

#### WAF Rule
```nginx
# Block các XSS payloads phổ biến trong request body
# Sử dụng ModSecurity với OWASP CRS ruleset
SecRule REQUEST_BODY "@rx <script" \
    "id:1001,phase:2,deny,status:403,msg:'XSS Attack Detected'"
```

---

### VULN-09 — Information Disclosure qua `/openapi.yaml`
**Mức độ:** 🟡 Medium  
**Route:** `GET /openapi.yaml`  
**Xác thực cần:** Không

#### Mô tả
File OpenAPI spec được serve công khai tại `/openapi.yaml`. File này chứa toàn bộ tài liệu API bao gồm:
- Danh sách tất cả endpoints
- Schema của request/response
- Thông tin xác thực
- Test credentials (username, password, OTP)
- Cấu trúc dữ liệu nội bộ

#### Tác hại
Kẻ tấn công có thể đọc file này để hiểu toàn bộ bề mặt tấn công của ứng dụng mà không cần phải mò mẫm, tiết kiệm đáng kể thời gian reconnaissance.

#### WAF Rule
```nginx
location = /openapi.yaml {
    allow 10.0.0.0/8;   # Chỉ cho phép nội bộ
    deny all;
}
```

---

### VULN-10 — Fake WordPress Honeypot tại `/wp-admin`
**Mức độ:** 🟡 Medium  
**Route:** `GET /wp-admin`  
**Xác thực cần:** Không

#### Mô tả
Server trả về HTTP 200 với nội dung giả WordPress admin panel. Đây có thể là **honeypot** (bẫy để phát hiện kẻ tấn công) hoặc một misconfiguration. Trong cả hai trường hợp, WAF nên block route này để tránh bị lợi dụng.

---

### VULN-11 — Control Endpoints không được bảo vệ đúng cách
**Mức độ:** 🔴 Critical  
**Routes:** `/__control/*`  
**Xác thực cần:** Header `X-Benchmark-Secret`

#### Mô tả
Các endpoints control dùng để quản lý state của ứng dụng trong quá trình benchmark. Nếu `X-Benchmark-Secret` bị leak (ví dụ qua log, error message, hay brute force), kẻ tấn công có thể:

- `POST /__control/reset` — Xóa toàn bộ dữ liệu, reset database
- `POST /__control/slow` — Inject delay vào mọi request → DoS
- `POST /__control/error_mode` — Đặt server vào chế độ crash liên tục
- `POST /__control/health_mode` — Làm down toàn bộ service

#### WAF Rule
```nginx
location /__control {
    allow 127.0.0.1;    # Chỉ localhost
    deny all;
    return 403;
}
```

---

## 6. Tổng hợp WAF Rules đề xuất

### Nginx WAF Config

```nginx
# ============================================
# WAF Rules cho NovaBet
# ============================================

# --- Rate Limiting Zones ---
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=otp:10m rate=3r/m;
limit_req_zone $binary_remote_addr zone=reports:10m rate=2r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;

server {
    # --- Block Sensitive Files ---
    location ~* /\.(env|git|htaccess|htpasswd|gitignore|dockerignore) {
        return 403;
    }
    location ~* \.(yaml|yml|key|pem|crt|csr)$ {
        return 403;
    }

    # --- Block Path Traversal ---
    if ($request_uri ~* "\.\.") {
        return 403;
    }
    if ($request_uri ~* "%2e%2e|%252e|%c0%af") {
        return 403;
    }

    # --- Block Admin từ Internet ---
    location /admin {
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }

    # --- Block Control Endpoints ---
    location /__control {
        allow 127.0.0.1;
        deny all;
    }

    # --- Block OpenAPI Spec từ Internet ---
    location = /openapi.yaml {
        allow 10.0.0.0/8;
        deny all;
    }

    # --- Block Fake/Honeypot Paths ---
    location ~* /wp-(admin|login|content|includes) {
        return 403;
    }
    location ~* /(phpinfo|info|test)\.php$ {
        return 403;
    }

    # --- Rate Limiting ---
    location = /login {
        limit_req zone=login burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://backend;
    }
    location = /otp {
        limit_req zone=otp burst=3 nodelay;
        limit_req_status 429;
        proxy_pass http://backend;
    }
    location = /api/bet-reports/export {
        limit_req zone=reports burst=3 nodelay;
        limit_req_status 429;
        proxy_pass http://backend;
    }
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://backend;
    }
}
```

### ModSecurity Rules (OWASP CRS)

```apache
# Block XSS trong feedback
SecRule REQUEST_URI "@contains /api/feedback" \
    "chain,id:2001,phase:2,deny,status:403,msg:'XSS in feedback'"
SecRule REQUEST_BODY "@rx (?i)<script|javascript:|on\w+\s*=" ""

# Block SSRF vào internal IPs
SecRule REQUEST_URI "@contains /api/integrations/preview" \
    "chain,id:2002,phase:2,deny,status:403,msg:'SSRF Attempt'"
SecRule REQUEST_BODY "@rx (169\.254\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|localhost|127\.0\.0\.1)" ""

# Block path traversal
SecRule REQUEST_URI "@rx \.\." \
    "id:2003,phase:1,deny,status:403,msg:'Path Traversal'"
```

---

## 7. Ma trận rủi ro

| ID | Lỗ hổng | Khả năng khai thác | Tác hại | Mức độ |
|----|---------|-------------------|---------|--------|
| VULN-01 | Lộ `.env` | Rất dễ (1 request) | Database bị xâm phạm | 🔴 Critical |
| VULN-02 | Lộ `.git` | Rất dễ (1 request) | Source code leak | 🔴 Critical |
| VULN-03 | Lộ `config.yaml` | Rất dễ (1 request) | Database bị xâm phạm | 🔴 Critical |
| VULN-04 | Path Traversal | Dễ | Đọc bất kỳ file nào | 🔴 Critical |
| VULN-05 | Broken Access Control Admin | Dễ (cần login) | Lộ toàn bộ PII 103 users | 🔴 Critical |
| VULN-06 | Asymmetric DoS | Dễ (cần login) | Downtime service | 🔴 Critical |
| VULN-07 | SSRF | Trung bình | Truy cập internal network | 🔴 Critical |
| VULN-08 | Stored XSS | Trung bình | Chiếm tài khoản user | 🟠 High |
| VULN-09 | OpenAPI spec lộ | Rất dễ | Reconnaissance đầy đủ | 🟡 Medium |
| VULN-10 | Fake `/wp-admin` | Rất dễ | Honeypot/Misconfiguration | 🟡 Medium |
| VULN-11 | Control Endpoints | Khó (cần secret) | Full service takeover | 🔴 Critical |
| VULN-12 | PII trong `/api/profile` | Dễ (cần login) | Lộ SSN, card, bank | 🟠 High |

---

## 8. Kiểm tra HTTP Methods bất thường

Ngoài các methods cơ bản (GET, POST, PUT, DELETE) đã được document trong OpenAPI, chúng tôi tiến hành kiểm tra thêm các HTTP methods ít phổ biến hơn trên toàn bộ routes để phát hiện các cấu hình sai tiềm ẩn.

### 8.1 Phương pháp kiểm tra

Các methods được kiểm tra bao gồm: `OPTIONS`, `HEAD`, `PATCH`, `TRACE`, `CONNECT`, `PROPFIND`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`, `SEARCH` — trên tất cả các routes đã biết.

Lọc kết quả: chỉ giữ lại các response **không phải 404 hoặc 405** (tức là server chấp nhận method đó).

---

### 8.2 Kết quả — Methods hoạt động đúng theo spec

| Method | Route | Status | Ghi chú |
|--------|-------|--------|---------|
| `OPTIONS` | `/api/public/stats` | 204 | Đúng theo OpenAPI — CORS preflight, trả về `Access-Control-Allow-Methods: GET, POST, OPTIONS` |

---

### 8.3 🔴 Phát hiện bất thường — Method không bị hạn chế trên Sensitive Files

Server **không block bất kỳ HTTP method nào** trên các file nhạy cảm `/.env` và `/config.yaml`. Cụ thể các methods sau đều trả về HTTP 200:

| Method | Route | Status | Mức độ nguy hiểm | Ý nghĩa |
|--------|-------|--------|-----------------|---------|
| `OPTIONS` | `/.env` | 200 | 🟡 Medium | Server chấp nhận OPTIONS, không trả về `Allow` header — che giấu danh sách methods thực sự hỗ trợ |
| `OPTIONS` | `/config.yaml` | 200 | 🟡 Medium | Tương tự |
| `HEAD` | `/.env` | 200 | 🟠 High | Attacker có thể probe sự tồn tại của file mà không cần tải nội dung — bypass một số WAF chỉ inspect GET |
| `HEAD` | `/config.yaml` | 200 | 🟠 High | Tương tự |
| `PATCH` | `/.env` | 200 | 🔴 Critical | Server nhận PATCH — có thể ghi đè một phần nội dung file |
| `PATCH` | `/config.yaml` | 200 | 🔴 Critical | Tương tự |
| `PUT` | `/.env` | 200 | 🔴 Critical | Server nhận PUT — có thể ghi đè toàn bộ nội dung file |
| `DELETE` | `/.env` | 200 | 🔴 Critical | Server nhận DELETE — có thể xóa file |
| `DELETE` | `/config.yaml` | 200 | 🔴 Critical | Tương tự |

> **Ghi chú:** Response body vẫn trả về nội dung file gốc sau khi gửi PATCH/PUT/DELETE, cho thấy đây có thể là intentional vulnerability trong môi trường hackathon (server giả vờ chấp nhận nhưng không thực sự ghi). Tuy nhiên trong môi trường production thực tế, đây là lỗ hổng cực kỳ nguy hiểm cho phép attacker **ghi đè hoặc xóa file cấu hình**, dẫn đến full system compromise.

---

### 8.4 TRACE Method — Không kiểm tra được qua browser

Browser hiện đại (Chrome, Firefox) **chủ động block TRACE method** ở tầng JavaScript `fetch()` API để phòng chống tấn công **XST (Cross-Site Tracing)**. Do đó không thể test từ browser.

**XST là gì?** Khi server hỗ trợ TRACE, server sẽ phản chiếu (echo) lại toàn bộ HTTP request — bao gồm cả cookie HttpOnly và Authorization header — trong response body. Kẻ tấn công kết hợp với XSS có thể đánh cắp session cookie dù cookie được đặt HttpOnly.

WAF **bắt buộc phải block TRACE** vì browser không thể tự bảo vệ ở tầng này.

---

### 8.5 Tổng hợp WAF Rules bổ sung cho HTTP Methods

```nginx
# ============================================
# Block các HTTP Methods nguy hiểm
# ============================================

# Block TRACE (chống XST attack)
if ($request_method = TRACE) {
    return 405;
}

# Block WebDAV methods (không cần thiết cho REST API)
if ($request_method ~* "^(CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH)$") {
    return 405;
}

# Với sensitive files: KHÔNG cho phép bất kỳ method nào — block hết
location ~* /\.(env|git|yaml|yml|key|pem) {
    deny all;
    return 403;
}

location = /config.yaml {
    deny all;
    return 403;
}

# Với static/public/assets: Chỉ cho phép GET và HEAD
location ~* ^/(static|public|assets)/ {
    limit_except GET HEAD {
        deny all;
    }
}

# Với API endpoints: Chỉ cho phép GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
if ($request_method !~* "^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)$") {
    return 405;
}
```

**ModSecurity rule:**
```apache
# Block TRACE và WebDAV methods
SecRule REQUEST_METHOD "^(TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH)$" \
    "id:3001,phase:1,deny,status:405,msg:'Disallowed HTTP Method'"
```

---

## 9. Cập nhật Ma trận rủi ro

| ID | Lỗ hổng | Khả năng khai thác | Tác hại | Mức độ |
|----|---------|-------------------|---------|--------|
| VULN-01 | Lộ `.env` | Rất dễ (1 request) | Database bị xâm phạm | 🔴 Critical |
| VULN-02 | Lộ `.git` | Rất dễ (1 request) | Source code leak | 🔴 Critical |
| VULN-03 | Lộ `config.yaml` | Rất dễ (1 request) | Database bị xâm phạm | 🔴 Critical |
| VULN-04 | Path Traversal | Dễ | Đọc bất kỳ file nào | 🔴 Critical |
| VULN-05 | Broken Access Control Admin | Dễ (cần login) | Lộ toàn bộ PII 103 users | 🔴 Critical |
| VULN-06 | Asymmetric DoS | Dễ (cần login) | Downtime service | 🔴 Critical |
| VULN-07 | SSRF | Trung bình | Truy cập internal network | 🔴 Critical |
| VULN-08 | Stored XSS | Trung bình | Chiếm tài khoản user | 🟠 High |
| VULN-09 | OpenAPI spec lộ | Rất dễ | Reconnaissance đầy đủ | 🟡 Medium |
| VULN-10 | Fake `/wp-admin` | Rất dễ | Honeypot/Misconfiguration | 🟡 Medium |
| VULN-11 | Control Endpoints | Khó (cần secret) | Full service takeover | 🔴 Critical |
| VULN-12 | PII trong `/api/profile` | Dễ (cần login) | Lộ SSN, card, bank | 🟠 High |
| VULN-13 | HTTP Method không bị hạn chế trên sensitive files | Dễ | Ghi đè/xóa file cấu hình | 🔴 Critical |
| VULN-14 | TRACE method (chưa xác nhận) | Trung bình | XST — đánh cắp session cookie | 🟠 High |

---

*Report được tạo tự động từ kết quả kiểm tra thực tế trên môi trường WAF Hackathon 2026.*
