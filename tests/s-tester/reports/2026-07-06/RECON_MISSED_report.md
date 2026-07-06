# Báo cáo: Recon-Path bị WAF bỏ sót — phân loại ưu tiên & hướng fix

**Hệ thống:** Aegis-Gate WAF (`/Users/sabo/Workspace/waf/aegis-gate`)
**Nguồn:** `MISSED_attacks_recon.json` (1,960 request / **1,650 path distinct** WAF không có detector nào bắt)
**Kèm theo:** `recon_CRITICAL.json` · `recon_HIGH.json` · `recon_MEDIUM.json` · `recon_LOW.json` (đã tách theo severity, đọc & phân loại từng path)
**Mục tiêu:** Đưa chuyên gia bức tranh đầy đủ + thứ tự ưu tiên để mở rộng recon detector. **Chỉ report — không sửa code.**

---

## 0. Tóm tắt

WAF **không bắt 1,650 recon path** (round-1 chỉ chặn nhờ reputation IP — sẽ **lọt khi BTC xoay IP**). Đây phần lớn là **dò file bí mật/credential**: `.env`, `.aws`, `wp-config.php`, `sendgrid/sparkpost/mailjet keys`, `.git`, `docker-compose`, DB dump, phpinfo…

Đã kiểm chứng đây **không phải probe vô hại**: một số file **tồn tại thật và bị serve (200)**, lộ **DB password + password hash + secret key** (xem `SUSPICIOUS_200_malicious_findings.json`: `/config.yaml`, `/.htaccess`, `/backup.sql.bak`).

**Phân loại theo mức độ nguy hiểm nếu file bị serve:**

| Mức | Distinct | Request | Nội dung lộ ra |
|---|---|---|---|
| 🔴 **CRITICAL** | **755** | 885 | Credential/key/secret thô: `.env`, `.aws/credentials`, private key, `wp-config.php`, mail-service keys, DB dump, connection string |
| 🟠 **HIGH** | **307** | 359 | Source/VCS/CI/IaC/config: `.git`, `docker-compose`, `.gitlab-ci`, `config.json/yaml`, `.properties`, backup archive |
| 🟡 **MEDIUM** | **554** | 669 | Info-disclosure/debug/admin: `phpinfo`, `_profiler`, `/admin`, log, `/vendor`, `xmlrpc` |
| ⚪ **LOW** | **34** | 47 | Public-by-design / dir / template: `.well-known/*`, `robots.txt`, `.env.example`, dir listing |

*(Cách phân loại: severity = nội dung nhạy cảm **nhất** của file gốc; đuôi backup `.bak/.old/~~` chỉ là cách serve raw, không hạ severity. Script tái tạo: `classify_recon.py`.)*

---

## 1. 🔴 CRITICAL (755) — rò rỉ credential trực tiếp

**Nếu file tồn tại & bị serve → chiếm tài khoản/hạ tầng ngay.** Các họ:

| Họ | Ví dụ path |
|---|---|
| Env/secret files | `/.env`, `/.env.prod`, `/config.env`, `/.envrc`, `/secrets.json`, `/app/secrets.json` |
| Cloud creds | `/.aws/credentials`, `/aws_access_keys`, `/aws_credentials`, `/.aws/s3/credentials.ini`, `/private/gcp_credentials.json` |
| Mail-service keys | `/sendgrid.env`, `/sparkpost_keys.json`, `/api_keys/mailjet_keys.json`, `/backup/mandrill.json`, `mailer_dsn_keys.json` (SMTP user:pass) |
| Private keys | `id_rsa`, `*.pem`, `*.p12`, `*.jks`, `*.keystore` |
| API keys | `/apikeys.cfg`, `/api_keys.properties`, `/keys.json`, `/keys.php` |
| DB creds/dump | `*.sql`, `/backup.sql.bak`, `database.yml`, `ConnectionStrings.config`, `.pgpass`, `.my.cnf` |
| App config có DB pass | `wp-config.php` (≥150 biến thể đuôi), `config.php`, `application.properties`, `web.config`, `.htaccess`, `settings.py` |
| FTP/deploy creds | `.ftpconfig`, `.vscode/sftp.json`, `remote-sync.json` |

**Đã xác nhận rò rỉ thật (200):** `/config.yaml` (db_password), `/.htaccess` (DB_PASS), `/backup.sql.bak` (users table + bcrypt hash).

---

## 2. 🟠 HIGH (307) — source / VCS / CI-CD / config

Lộ mã nguồn, lịch sử repo, cấu hình hạ tầng → dẫn tới secret/logic:
- **VCS**: `.git/*`, `.git/config`, `.gitattributes`, `.svn`, `.hg`
- **CI/CD**: `.gitlab-ci.yml`, `.github/workflows/*.yml`, `jenkinsFile`, `.travis`, `.circleci`, `.drone`
- **IaC/container**: `docker-compose*.json/yml`, `Dockerfile`, `terraform`, `.tfstate`, `.tfvars`, `kubeconfig`
- **Generic config**: `config.json/yaml/js/ini`, `settings.*`, `*.properties`, `*.conf`, `server.xml`, `web.xml`, `.cordova/config.json`, `.lanproxy/config.json`
- **Shell/deploy**: `*.sh` (`build.sh`, `cron.sh`, `deploy`), `.bash_history`, `.zshenv`, `Makefile`
- **Archive/backup**: `backup.zip/tar/gz`, `*.war`, `*.jar`, source-backup (`.php.bak`, `~~`)

---

## 3. 🟡 MEDIUM (554) — info-disclosure / debug / admin

Lộ cấu hình/env/cấu trúc (đôi khi kèm secret qua env), nhưng không phải file credential thô:
- **phpinfo / profiler** (đông nhất ~460): `phpinfo`, `linusadmin-phpinfo.php`, `xampp/phpinfo`, `_profiler/*`, `app_dev.php` — *lưu ý: phpinfo/profiler leak biến môi trường, có thể chứa DB creds → cân nhắc nâng lên HIGH nếu app dùng env-config.*
- **Debug/monitor**: `/actuator/info`, `/metrics`, `server-status`, `error_log`, `debug.log`, `/logs/*`
- **Admin surface**: `/wp-admin`, `/administrator`, `/manager/html`, `/adminer`, `/install.php`, `/setup.php`
- **Framework internals**: `/vendor/*`, `/node_modules/*`, `.map`, `xmlrpc.php`, `/cgi-bin`, `/owa/`, `autodiscover`

---

## 4. ⚪ LOW (34) — public-by-design / dir / template

Không phải leak thật, thường không cần chặn (chặn có thể gây FP):
- `.well-known/*` (jwks.json, openid-configuration, apple-app-site-association — **công khai theo thiết kế**)
- `robots.txt`, `sitemap.xml`, `favicon`
- `.env.example`, `.env-sample` (template — không chứa secret thật)
- Dir listing: `/wp-content/`, `/bin/`, `/.cache/`, `/env/bin/activate`

---

## 5. Vì sao WAF miss (đã test trực tiếp)

Từ `recon_detection_result.json` (bắn lại sau update, IP sạch): **detector chỉ bắt 11.3%**. Nguyên nhân gốc trong recon detector (`crates/aegis-security/src/detectors/recon.rs`):
1. **Khớp theo tên file + đuôi cụ thể**, không theo **keyword/stem** → bắt `secrets.json` nhưng sót `credentials.*`; bắt `wp-config.txt` nhưng sót `.ini/.json/.inc`; bắt `phpinfo.php.backup` nhưng sót `phpinfo` trần / `_profiler/phpinfo`.
2. **Từ điển thiếu họ**: `credentials`, `mailjet/mailer_dsn`, `aws_access_keys`, `.ftpconfig/sftp`, `ConnectionStrings`, `.properties`, `docker-compose`, `_profiler`, `phpinfo` (trần).
3. **Chấm điểm quá thấp** (~25 < ngưỡng chặn) → dù bắt cũng chỉ `allow` (xem `/config.yaml`, `/.htaccess`, `/backup.sql.bak` → recon-path fire nhưng action=allow → file bị serve).
4. **Không normalize path** → bypass `//wp-config.php` (double-slash) lọt.

---

## 6. Đề xuất fix (cho chuyên gia) — ưu tiên tránh FP

### 6.1 Đổi sang khớp KEYWORD/STEM, không theo tên+đuôi cứng
- Bắt path chứa keyword nhạy cảm **bất kể prefix/dir/đuôi**: `\.env`, `wp-config`, `config`, `credential`, `secret`, `apikey`, `aws`, `_profiler`, `phpinfo`, `docker-compose`, `.git`, `backup`, mail-service (`sendgrid|sparkpost|mailjet|mandrill|mailgun`), private-key (`id_rsa|\.pem|\.p12`).
- **Đuôi rộng** cho nhóm config/secret: `.php .json .ya?ml .ini .env .conf .properties .inc .bak .old .save .swp .rar .gz .tar .0-9 .copy .orig .txt`.
- **Normalize path** trước match: gộp `//`→`/`, giải mã `%2e`/`%2f`, hạ chữ, bỏ đuôi backup lặp.

### 6.2 Chấm điểm THEO SEVERITY (quan trọng)
- **CRITICAL / HIGH** (755 + 307): score **≥ ngưỡng BLOCK** — file credential/config/backup **không bao giờ nên được serve** → chặn cứng, không chỉ `allow`.
- **MEDIUM** (554): score đủ để **challenge**, hoặc block nếu strict.
- **LOW** (34): **không chặn** (`.well-known`, template, dir) → tránh FP với traffic hợp lệ.

### 6.3 Tránh False-Positive
1. **LOW list là allowlist** — `.well-known/*` (jwks/openid là công khai), `robots.txt/sitemap/favicon`, `.env.example/.sample` (template) → **không** flag. Đây là chỗ dễ FP nhất.
2. **Chỉ recon là path-based, không đụng body hợp lệ** → recon không gây FP trên POST data.
3. **Static asset hợp lệ**: nếu app thật sự serve `/config.js` (frontend runtime config), thêm allowlist path cụ thể (xem `recon_excluded_static.json` đã tách trước đó).
4. **Regression**: sau khi thêm keyword, bắn lại tập benign (`btc_round2_benign`, `waf_allowed_api_normal`) để đảm bảo không chặn nhầm asset/endpoint hợp lệ.

### 6.4 Kết hợp response filtering (defense-in-depth)
Ngay cả khi request lọt, response filter phải redact/chặn secret trong body — xem `RESPONSE_FILTERING_report.md`.

---

## 7. Thứ tự ưu tiên triển khai

| # | Việc | Bao phủ | Rủi ro FP |
|---|---|---|---|
| 1 | Thêm keyword + block cho **CRITICAL** (755): env/aws/mail-keys/wp-config/private-key/DB-dump/credentials | Chặn leak nặng nhất | Rất thấp (file này không hợp lệ) |
| 2 | Thêm keyword + block cho **HIGH** (307): .git/docker/CI/config/backup | Chặn source/config | Thấp |
| 3 | **MEDIUM** (554): challenge/score phpinfo/profiler/admin/log | Giảm info-disclosure | Thấp–TB (allowlist admin hợp lệ nếu có) |
| 4 | Normalize `//`, giải mã, đuôi rộng | Chống bypass | Rất thấp |
| 5 | Giữ **LOW** (34) là allowlist | Tránh FP | — |

**Test sau fix:** `python3 load_test/test_recon_detection.py --confirm` (đổi `--file recon_CRITICAL.json` để đo riêng từng tier) → mục tiêu CRITICAL/HIGH bắt ~100% & **block**, LOW vẫn allow. Đo FP trên benign.

---

*Files kèm: `recon_{CRITICAL,HIGH,MEDIUM,LOW}.json` (mỗi record có url/method/type/status/occurrences/headers). Script phân loại: `classify_recon.py` (deterministic, chạy lại được). Mọi path truy về log gốc qua `MISSED_attacks_recon.json`.*
