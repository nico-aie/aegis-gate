---
id: 2026-05-18-owasp-injection-verification
date: 2026-05-18T00:00Z
area: OWASP injection detectors
spec_ref: §5.3 (OWASP Top-8: SQLi, XSS, Path Traversal, SSRF, HTTP Header Injection, Brute Force, Recon, Body Abuse)
---

# OWASP injection detectors — §5.3

> **Tóm tắt nhóm này**: Đây là cụm detector chất lượng cao nhất. 7/8 PASS, 1/8 (Brute Force) FAIL (chi tiết ở [02-volumetric.md](02-volumetric.md) — Brute Force xếp vào nhóm volumetric theo §5.3 nhưng audit kỹ thuật theo cụm volumetric).

## 1. SQL Injection — **PASS**

[crates/aegis-security/src/detectors/sqli.rs:12-41](../../../../crates/aegis-security/src/detectors/sqli.rs#L12)

### Spec coverage 10/10

- UNION SELECT, SELECT/INSERT/UPDATE/DELETE, OR 1=1, comment-based (`--`, `/* */`), time-based (WAITFOR/SLEEP/BENCHMARK), stacked queries, file ops (LOAD_FILE, INTO OUTFILE), information_schema/sys.objects, hex/CHAR encoding, advanced shapes (GROUP BY HAVING, CASE WHEN).

### Mutation-resistance
- URL decode qua `super::url_decode` (line 57).
- Header scan: Cookie + Referer + X-Forwarded-For + User-Agent (line 67-71).
- ⚠️ Open issue (F-MEDIUM M-01): `--\s*$` end-anchor — bypassed bởi `1' OR 1=1-- -` (có content sau `--`). Vẫn dùng được nhưng có blind spot.

### Dashboard wiring
- `PUT /api/detectors` qua [api/detectors.rs:183-228](../../../../crates/aegis-control/src/api/detectors.rs#L183).
- ArcSwap propagation qua `SharedDetectorMask::load()` ở [mask.rs:421](../../../../crates/aegis-security/src/detectors/mask.rs#L421).
- Runtime check: `mask.is_enabled_id(d.id())` ở [detectors/mod.rs:210](../../../../crates/aegis-security/src/detectors/mod.rs#L210).

### §9: PASS · Score: 40 (Challenge tier)

---

## 2. XSS — **PASS**

[crates/aegis-security/src/detectors/xss.rs](../../../../crates/aegis-security/src/detectors/xss.rs)

### Spec coverage 7/7 + GAP-012 fix

- Script tags + event handlers (line 12, 16) — ⚠️ open M-02: event handler list enumerated, missing `onpointerdown/onauxclick/oncopy/onpaste`. Fix: replace với generic `on\w+\s*=`.
- JavaScript/VBScript protocols (line 14-15).
- HTML entity decoding (line 27, 40) + 3-stage chain (raw → url-decoded → entity-decoded) tại line 56-67 — **GAP-012 fix**.
- DOM methods (innerHTML, location, eval) (line 31-38).
- SVG/data URI (line 22, 26).

### Mutation-resistance
- URL decode (line 62) + entity decode (line 63) + raw scan.
- Header scan: Cookie + Referer + UA (line 79-87).

### Dashboard wiring
- Same chain như SQLi.

### §9: PASS · Score: 35 (Challenge tier)

---

## 3. Path Traversal — **PASS**

[crates/aegis-security/src/detectors/path_traversal.rs](../../../../crates/aegis-security/src/detectors/path_traversal.rs)

### Spec coverage 7/7 + GAP-002 overlong UTF-8

- Basic `../` `..\` (line 12-13).
- URL encoding `%2e%2e` + double encoding (line 14-19).
- ⚠️ Open M-02: hầu hết pattern thiếu `(?i)` → `%2E%2E%2F` uppercase hex bypass.
- Overlong UTF-8 `%c0%ae`, `%c0%af` (line 37-39) — **GAP-002 fix**.
- Sensitive files `/etc/passwd`, `/proc/self` (line 20-21).
- Windows paths `c:/`, `boot.ini`, UNC (line 22-25).
- Null byte (line 26).
- Docker socket probe (line 45).

### Mutation-resistance
- URL decode (line 61).
- Body scan (line 65-70).
- ⚠️ Open M-03 (F-HIGH D-03): không scan headers — `X-Original-URL: ../../etc/passwd` thoát.

### Dashboard wiring: same chain.

### §9: PASS · Score: 45 (Challenge tier)

---

## 4. SSRF — **PASS**

[crates/aegis-security/src/detectors/ssrf.rs](../../../../crates/aegis-security/src/detectors/ssrf.rs)

### Spec coverage 7/7 + GAP-004 + BYPASS-03f

- Loopback (127.x, ::1) — line 12, 14.
- AWS metadata 169.254.169.254 — line 15.
- RFC 1918 (10.x, 172.16-31, 192.168) — line 18-20.
- Alt protocols (file://, gopher://, dict://, ftp://) — line 21-24.
- URL-userinfo bypass (`http://evil.com:80@internal`) — line 40 (**GAP-004 fix**).
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`) — line 52, 57 (**BYPASS-03f fix**).
- IP encoding variants (hex, octal, decimal) — line 25-27.
- ⚠️ Open D-07 (F-HIGH): chỉ scope `https?://` — scheme-relative `//169.254.169.254/...` bypass; missing schemes `ldap://`, `redis://`, `mongodb://`.

### Mutation-resistance
- URL decode (line 80, 83, 88) cho query/path/body.
- Header scan: x-original-url, x-rewrite-url (line 98-101).
- Self-trip regression guard (test line 275-299).

### Dashboard wiring: same chain.

### §9: PASS · Score: 50

---

## 5. HTTP Header Injection — **PASS** (đã fix F-CRITICAL-012)

[crates/aegis-security/src/detectors/header_injection.rs](../../../../crates/aegis-security/src/detectors/header_injection.rs)

### Spec coverage 5 vector

- CRLF injection (line 12-17).
- Response header injection (Set-Cookie, Location — line 18-20).
- Method-override (DELETE/PUT/PATCH — line 285-302).
- X-Forwarded-Host poisoning (line 71-78, 107-163).
- URL-override-header auth bypass (X-Original-URL, X-Rewrite-URL — line 226-323).

### §9: PASS — **F-CRITICAL-012 ĐÃ FIX**

- Trước fix: hardcode `"evil"`, `"attacker"`, `"malicious"`, `"phish"` keyword match (vi phạm §9 disqualify).
- Sau fix (2026-05-17): chuyển sang structural needles — URI schemes (javascript:/data:/vbscript:/file:) + HTML metachars (`<>"'`) tại line 147-160.

### Mutation-resistance
- URL decode (line 41, 312).
- Multi-header scan (line 45-53, 61-78, 98-101, 286-288, 305-308).

### Dashboard wiring: same chain.

### Score: 35-40

---

## 6. Brute Force — **FAIL**

Xem chi tiết ở [02-volumetric.md](02-volumetric.md#3-brute-force--53--fail).

---

## 7. Recon — **PASS**

[crates/aegis-security/src/detectors/recon.rs](../../../../crates/aegis-security/src/detectors/recon.rs)

### Spec coverage 8+ class

- Sensitive files (.env, .git, .aws/credentials) — line 12-48.
- Admin paths (wp-admin, /admin, /actuator) — line 22-24, 53, 93.
- Source-control enum (.git/.svn/.hg) — line 13-15.
- Framework probes (Spring Actuator, Laravel Ignition, Jenkins) — line 53-76.
- Scanner UA (sqlmap/nikto/nmap/burp/zap) — line 111-137.
- Docker REST API probes — line 44 (SEC-L001).
- Kubernetes API — line 65-67.
- Elasticsearch/Kibana — line 74.
- ⚠️ Open D-09 (F-HIGH): chưa có OPTIONS-method abuse counter, chưa có per-IP 4xx-burst counter.

### Mutation-resistance
- UA: case-insensitive `(?i)` (line 111-137).
- Path: không URL decode (đúng — recon path là static file names, không bao giờ URL-encoded thực tế).

### Dashboard wiring: same chain.

### §9: PASS — sqlmap/nikto là legitimate scan tool detection, không phải benchmark-rigging keyword.

### Score: PATH=25, TOOL=30 (Probe tier)

---

## 8. Body Abuse — **PASS**

[crates/aegis-security/src/detectors/body_abuse.rs](../../../../crates/aegis-security/src/detectors/body_abuse.rs)

### Spec coverage 5 vector

- Oversize (configurable max) — line 65-72.
- Deep JSON nesting — line 76-90.
- Mass-assignment (role, is_admin, api_key, password_hash) — line 35-42, 92-97.
- XXE entity declarations — line 51-54, 114-120.
- Prototype pollution (__proto__, constructor.prototype) — line 99-104, 128-164 (**GAP-010 fix**).
- ⚠️ Open M-04: mass-assign regex match inside string values (FP class). Fix: JSON-parse instead.
- ⚠️ Open M-05: pre-filter case-sensitive cho `__proto__/constructor` → `__PROTO__` bypass.
- ⚠️ Open D-08 (F-HIGH): không có decompression-bomb check (gzip 1KB → 10GB).

### Mutation-resistance
- JSON-aware nesting depth counter (line 167-203).
- Case-insensitive proto-pollution check (line 142-164).

### Dashboard wiring: same chain.

### §9: PASS · Score: 30-60 (OVERSIZE=30, DEEP=35, PROTO=45, MASS=50, XXE=60)

---

## Summary OWASP

| Detector | Coverage | Mutation | Dashboard | §9 | Verdict |
|---|---|---|---|---|---|
| SQLi | 10/10 | URL+headers | ✅ | ✅ | **PASS** |
| XSS | 7/7 + entity decode | URL+entity+headers | ✅ | ✅ | **PASS** |
| Path Traversal | 7/7 + overlong UTF-8 | URL+body | ✅ | ✅ | **PASS** |
| SSRF | 7/7 + userinfo + IPv6 | URL+headers | ✅ | ✅ | **PASS** |
| Header Injection | 5 vectors | URL+multi-header | ✅ | ✅ (đã fix F-CRITICAL-012) | **PASS** |
| Brute Force | per-IP only | N/A | ❌ | ✅ | **FAIL** (xem 02-volumetric.md) |
| Recon | 8+ class, 40+ patterns | UA case-insensitive | ✅ | ✅ | **PASS** |
| Body Abuse | 5 vector + proto-pollution | JSON-aware nesting | ✅ | ✅ | **PASS** |

## Ghi chú

- ArcSwap chain mask hot-reload chứng minh ổn: tất cả 8 detector đều bật/tắt được qua `PUT /api/detectors` với latency O(1) is_enabled_id check ở data plane.
- Mặc dù 7/8 PASS ở spec compliance, vẫn còn ~10 mutation-resistance gap mức MEDIUM (xem [F-MEDIUM-ALL.md](../2026-05-17-security-audit/F-MEDIUM-ALL.md) M-01..M-09) và ~6 gap mức HIGH (xem [F-HIGH-detectors.md](../2026-05-17-security-audit/F-HIGH-detectors.md) D-01..D-09).
- Tổng impact: Security rubric 40/120 — cụm OWASP đóng góp ~15/40 và đạt ổn ~12/15 (80%).
