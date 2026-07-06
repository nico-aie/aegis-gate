# Báo cáo: Response Filtering chống rò rỉ thông tin bảo mật

**Hệ thống:** Aegis-Gate WAF (`/Users/sabo/Workspace/waf/aegis-gate`)
**Nguồn:** `SUSPICIOUS_200_findings.json` + `SUSPICIOUS_200_malicious_findings.json` (leak thật, upstream trả 200)
**Mục tiêu:** Vì sao response filtering hiện tại để lọt secret, và đề xuất phương án cải thiện (cho chuyên gia fix). **Chỉ report — không sửa code.**

---

## 0. Tóm tắt điều hành

Upstream trả về **200** cho nhiều request và **rò rỉ credential thật** (DB password, secret key, SSH key, password hash, DB name/host). BTC **cố tình cắm marker** (`__V22_ADMIN_ACL__`, `__V23_CONFIG_LEAK__`, `__V29_SSRF_WHITELIST_BYPASS__`) để chấm điểm khả năng chống leak.

WAF **có response filtering** (`response_filter.rs` + `dlp/`), nhưng **để lọt 100% các secret này** vì 3 lý do gốc:
1. **DLP pattern lệ thuộc format** — `env_secret` chỉ match `KEY=VALUE` (env-file), **không** match JSON/YAML (`key: value`), `.htaccess` (`SetEnv KEY VALUE`), SQL dump.
2. **Từ điển secret thiếu** — `stripe_key` vỡ vì underscore (`sk_live_wafhack2026_prod_key` không match), **không có** pattern cho password hash (bcrypt `$2b$`), SSH key, field JSON `secret_key`/`admin_secret`/`db_password`, internal hostname.
3. **Tầng quan sát leak (`egress_leak`) chỉ chạy khi `status >= 500`** — nhưng mọi leak ở đây là **200** → không nhìn thấy. `egress_sensitive` thì **sampled + observe-only** (không chặn).

> ⚠️ **Response filtering là tuyến phòng thủ CUỐI (defense-in-depth).** Gốc rễ là **request lẽ ra phải bị CHẶN** (recon file config/backup → chỉ `allow`; `/admin/dashboard` không có admin-ACL detector). Nên fix **cả 2 tầng**: chặn request + lọc response.

---

## 1. Cái gì đã rò rỉ (bằng chứng)

| Endpoint | Status/WAF | Rò rỉ | Marker BTC |
|---|---|---|---|
| `GET /admin/dashboard` | 200, allow, rule=none | `secret_key=sk_live_wafhack2026_prod_key`, `db_host/db_user/db_name`, `redis_host`, `ssh_keys=[ssh-ed25519…]`, `total_balance` | `__V22_ADMIN_ACL__` |
| `GET /config.yaml` | 200, recon-path→**allow** | `db_password: __V23_CONFIG_LEAK__` | `__V23_CONFIG_LEAK__` |
| `GET /.htaccess` | 200, recon-path→**allow** | `# SetEnv DB_PASS wafhack2026_staging`, DB_HOST | `__V23_CONFIG_LEAK__` |
| `GET /backup.sql.bak` | 200, recon-path→**allow** | Dump bảng `users`: `username + bcrypt password_hash + balance` | `__V23_CONFIG_LEAK__` |
| `GET /openapi.yaml` | 200, recon-path→**allow** | Toàn bộ API schema (bề mặt tấn công) | — |

---

## 2. Response filtering hiện tại làm gì (đọc code)

**Tầng REWRITE thật** — `crates/aegis-security/src/response_filter.rs`:
- `inject_security_headers` (nosniff/HSTS/…), `should_strip_header` (bỏ header nội bộ).
- `scrub_stack_traces` — Node/Python/Java/Go traces.
- `mask_internal_ips` — **chỉ IP** (RFC1918/loopback/link-local/IPv6 ULA). **KHÔNG mask internal hostname** (`db.internal.novabet.local`).
- `mask_json_fields`, `filter_chunk`.

**Tầng DLP** — `crates/aegis-security/src/dlp/mod.rs` (dùng bởi redact path `Pipeline::on_body_frame`):
- Pattern: `credit_card, ssn, iban, email, phone, aws_key (AKIA…), aws_secret, github_token, stripe_key, slack_token, pem_private_key, jwt, env_secret`.

**Tầng QUAN SÁT (observe-only, không chặn)** — `egress_leak.rs` (5xx-only, default OFF), `egress_sensitive.rs` (sampled, chỉ secret-marker + card PAN), `egress_volume.rs`.

---

## 3. Vì sao từng secret lọt (đối chiếu pattern)

Đã test trực tiếp các pattern DLP với payload thật — **tất cả FALSE (không match):**

| Secret rò rỉ | Pattern liên quan | Vì sao MISS |
|---|---|---|
| `db_password: __V23_CONFIG_LEAK__` (YAML) | `env_secret` = `^KEY=VALUE$` | YAML dùng `:` không phải `=` → miss |
| `"db_user":"admin"` (JSON) | `env_secret` | JSON dùng `:` + key có quote → miss |
| `# SetEnv DB_PASS wafhack2026_staging` (.htaccess) | `env_secret` | Phân tách bằng **space**, trong comment → miss |
| `sk_live_wafhack2026_prod_key` | `stripe_key` = `sk_(live\|test)_[A-Za-z0-9]{24,}` | Value có **underscore** — `[A-Za-z0-9]` không gồm `_` → miss |
| bcrypt `$2b$12$LJ3m4ks…` | *(không có)* | Không có pattern cho password-hash |
| `ssh-ed25519 AAAA…admin@novabet` | `pem_private_key` = `-----BEGIN … PRIVATE KEY-----` | SSH key format khác PEM → miss |
| `admin_secret`, `secret_key`, `db_host/db_name` (JSON) | *(không có)* | Không có pattern generic cho field JSON tên nhạy cảm |
| `db.internal.novabet.local` | `mask_internal_ips` | Chỉ mask IP, **không mask hostname nội bộ** |

**Kết luận:** DLP hiện tại bắt được secret ở dạng **env-file (`=`)** và vài **token có shape cố định** (AKIA, gh_, xox), nhưng **mù với JSON/YAML/SQL/.htaccess** và **thiếu** password-hash/SSH/internal-hostname/generic-secret-field.

---

## 4. Rule BTC (contract v2.6)

- **Response filtering là feature BẮT BUỘC, có chấm điểm** (Official Rules — mục "mandatory features … response filtering").
- Contract §5.2: response **MUST NOT contain secrets, raw credentials, session tokens, stack traces, or sensitive user data**.
- BTC cắm marker `__V**__` trong body chính là **case chấm điểm leak** → mất điểm trực tiếp nếu WAF để lọt.

---

## 5. Đề xuất phương án Response Filtering (cho chuyên gia)

### A. Phát hiện secret theo CẤU TRÚC key-value, độc lập format (quan trọng nhất)
Thay vì chỉ `KEY=VALUE`, nhận diện **key nhạy cảm + separator bất kỳ** (`:`/`=`/space) trên JSON/YAML/env/htaccess:
- Key chứa: `password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|credential|db[_-]?pass|passphrase|client[_-]?secret`.
- Match cả 3 shape:
  - env/.htaccess: `^\s*KEY\s*[=]\s*VALUE` và `SetEnv\s+KEY\s+VALUE`
  - JSON: `"KEY"\s*:\s*"VALUE"`
  - YAML: `^\s*KEY\s*:\s*VALUE`
- **Redact VALUE** (không xoá cả response) → giữ cấu trúc, giảm FP.

*(FP thấp: response hợp lệ hiếm khi trả field tên đúng `password`/`secret_key`/`db_pass` kèm giá trị. Nếu app có field UI như `password_strength` → giá trị là số/enum, có thể allowlist.)*

### B. Bổ sung từ điển secret-shape
- **Password hash**: bcrypt `\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}`, argon2 `\$argon2`, sha-crypt `\$6\$`, MD5-crypt `\$1\$`.
- **SSH key**: `ssh-(rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/=]{20,}`, `-----BEGIN OPENSSH PRIVATE KEY-----`.
- **Generic API/secret key**: nới `stripe_key` cho phép `_`: `sk_(live|test)_[A-Za-z0-9_]{16,}`; thêm `sk_live_`/`pk_live_`/`rk_live_`, `AIza[0-9A-Za-z_-]{35}` (Google), `xoxb/xoxp` (đã có).
- **JWT/PEM** (đã có) — giữ.

### C. Phát hiện internal-infrastructure disclosure
- Internal hostname: `[a-z0-9-]+\.(internal|local|svc|cluster\.local)\b`, `*.novabet.local`, `redis://`/`mongodb://`/`postgres://` connection string trong body → mask/redact (mở rộng `mask_internal_ips` sang hostname).

### D. Chặn (không chỉ redact) cho content nhạy cảm
Với **file cấu hình/backup/admin** (`.yaml/.env/.htaccess/.sql/.bak/backup`, hoặc content-type `text/yaml`/`application/sql`, hoặc path recon), nếu body chứa secret → **trả response bị chặn (403/empty)** thay vì redact từng dòng — vì các file này **không nên được serve** dù đã redact. Gắn với **request-side recon block** (xem §7).

### E. Mở scope sang response 200 (có perf-gate)
- `egress_leak`/scan hiện chỉ 5xx. Cần scan **200** cho content-type nhạy cảm (`json/yaml/sql/text/csv/html`) và path nhạy cảm.
- **Perf-gate để không đánh vào hot-path**: chỉ full-scan khi (a) request đã bị detector recon/nghi ngờ flag, HOẶC (b) content-type/đuôi là config/backup, HOẶC (c) response nhỏ. Với traffic 200 sạch phổ biến → bỏ qua như hiện tại.

### F. Giữ nguyên các quyết định đúng đã có
- **observe-before-redact** (`egress_sensitive.rs` §4) — giữ.
- Card PAN cần **density threshold** — giữ (tránh FP 1 PAN trong hoá đơn).
- `scrub_stack_traces`, strip internal header — giữ, mở rộng thêm khung Ruby/PHP/.NET nếu cần.

---

## 6. Tránh False-Positive (theo yêu cầu)

1. **Redact VALUE, không xoá response** → app vẫn hoạt động, chỉ giá trị nhạy cảm thành `[REDACTED]`.
2. **Key-based detection FP thấp**: field tên `password/secret_key/db_pass` kèm value gần như luôn là leak; nhưng **allowlist** field vô hại theo tên nếu app cần (vd `password_hint_enabled`, `has_password`).
3. **Secret-shape FP thấp**: bcrypt/SSH/PEM/JWT/`sk_live_` có shape đặc thù, không đụng dữ liệu thường.
4. **Ngưỡng mật độ** cho PII (email/phone/card) — giữ, vì random digit dễ FP.
5. **Perf + FP**: chỉ full-scan response khi nghi ngờ (recon-flagged / content-type nhạy cảm) → không đụng 200 sạch.
6. **Regression 2 chiều**: sau khi thêm pattern, chạy lại tập benign (response app hợp lệ) để đo FP-redact (đừng redact nhầm dữ liệu hợp lệ như số dư, ID…).

---

## 7. Gốc rễ: phải fix CẢ request-side (đừng chỉ dựa response filtering)

Response filtering là **lưới cuối**. Song song cần:
- **Recon file nhạy cảm → BLOCK** (không `allow`): `/config.yaml`, `/.htaccess`, `/backup.sql.bak`, `.env`, `.sql`, `.bak` — nâng recon score ≥ ngưỡng chặn (xem `SUSPICIOUS_200_malicious_findings.json`, `MISSED_attacks_recon.json`).
- **Admin-path ACL**: `/admin/*` phải challenge/block nếu chưa auth (hiện `block-admin-path` fire 0 lần — `/admin/dashboard` lọt). Đây là leak nặng nhất (`__V22_ADMIN_ACL__`).
- **SSRF whitelist đúng** (`__V29__`) + **SSTI** (`/api/feedback`) — xem `DETECTOR_UPDATE_report.md`.

Phòng thủ **2 lớp**: (1) chặn request tới file/endpoint nhạy cảm; (2) nếu vẫn tới upstream và body có secret → response filter redact/chặn.

---

## 8. Thứ tự ưu tiên + test

| # | Việc | Bắt thêm | FP | Công sức |
|---|---|---|---|---|
| 1 | DLP structural key-value (JSON/YAML/env/htaccess) cho key nhạy cảm | config.yaml, .htaccess, admin/dashboard | Thấp | Vừa |
| 2 | Thêm secret-shape: bcrypt, SSH, `sk_..._` có underscore | backup.sql.bak, secret_key | Rất thấp | Nhỏ |
| 3 | Mask internal hostname (mở rộng mask_internal_ips) | db.internal.novabet.local | Thấp | Nhỏ |
| 4 | Scan response 200 cho content-type/path nhạy cảm (perf-gated) | tất cả 200-leak | Thấp (nếu gate đúng) | Vừa |
| 5 | Block-on-leak cho config/backup + request-side recon block | ngăn serve file | Rất thấp | Vừa |

**Test sau khi fix:**
- **Chống leak**: bắn lại các endpoint trong 2 file findings → body không được chứa marker `__V22__`/`__V23__`, secret phải thành `[REDACTED]` hoặc response bị chặn.
- **Đo FP**: bắn tập benign (`btc_round2_benign`, response app hợp lệ) → không redact nhầm dữ liệu hợp lệ (số dư, tên, ID…).
- **Perf**: đo overhead khi bật scan 200 (dùng `load_test/btc_load_test.py`), đảm bảo trong SLA.

---

*Tham chiếu code theo bản hiện tại: `response_filter.rs`, `dlp/mod.rs`, `detectors/egress_*.rs`. Đề xuất mang tính hướng dẫn — cần chuyên gia review + test trước khi lên production. Contract BTC: `Hackathon_Doc/EN_waf_interop_contract_v2.6.md` §5.2.*
