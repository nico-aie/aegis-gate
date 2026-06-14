# Phân tích WAF Miss trên Production Log — Rule hay Retrain AI?

**Nguồn:** `dataset/production_logs/audit-2026-06-{10,11,12}.ndjson` (1,187 requests, 3 ngày)
**Ngày phân tích:** 2026-06-14
**Câu hỏi:** Những case WAF cho qua (allow) — nên áp rule hay train lại model AI?

---

## TL;DR — Kết luận trước

| Nhóm | Số case | Bản chất | Giải pháp |
|---|---|---|---|
| **A. Path probe sạch** (ASCII, không payload) | ~42 | Known-bad path, không có ký tự bất thường | **RULE** (mở rộng `recon.rs`). AI **mù** với loại này |
| **B. DNS-over-HTTPS tunnel** | 14 | C2/exfil qua `/dns-query?dns=<base64>` | **RULE** chuyên biệt + behavior |
| **C. Đã detect, dưới ngưỡng** | ~26 | recon đã bắt (score 25) nhưng `< block_at=80` | **KHÔNG phải miss** — sửa risk-accumulation |

**Điểm mấu chốt:** Hầu hết case miss là **recon path sạch** — model AI hiện tại (29 feature char-statistics) **về mặt nguyên lý không thể bắt được**, vì chuỗi `/owa/auth/logon.aspx` hoàn toàn bình thường về entropy/ký tự đặc biệt/SQL keyword. Đây là bài toán của **signature rule**, không phải ML.

---

## 1. Bằng chứng: AI model thấy gì?

Model ONNX (LightGBM binary) dùng **29 feature** (`detectors/ai/features.rs`), chia 2 nhóm:

- **Char-statistics** (entropy, digit_ratio, special_char_count, quote/angle/semicolon count, pct_encoded, hex_encode, double_encode) → chạy trên `url+body`
- **Attack-pattern count** (sql_keyword, xss_pattern, path_traversal, cmd_injection, scanner, ssrf, php_pattern, ssti) → chạy trên `url+body+headers`

Lấy ví dụ path bị miss `/owa/auth/logon.aspx`:

| Feature | Giá trị | Ý nghĩa |
|---|---|---|
| entropy | thấp (chuỗi ASCII thường) | giống traffic bình thường |
| special_char_count | ~2 (`/`, `.`) | bình thường |
| sql/xss/cmdi/ssti count | **0** | không có payload |
| digit_ratio, quote_count | ~0 | sạch |

→ Model dự đoán **Normal**. Không phải vì model kém, mà vì **không có gì để học** — chuỗi này về mặt thống kê y hệt một URL hợp lệ. Đây là **semantic attack** (biết path nào là nhạy cảm), không phải **syntactic attack** (payload bất thường).

**Hệ quả:** Train lại AI với các path này = nhồi danh sách path vào model → model học thuộc lòng (overfit signature). Việc đó **rule làm tốt hơn, nhanh hơn, giải thích được, không FP** — và đó chính là lý do `recon.rs` tồn tại.

---

## 2. Nhóm A — Path probe sạch → DÙNG RULE

Các case `risk_score=0` (không detector nào fire), đều là known-bad path:

```
25x  /Core/Skin/Login.aspx                         ← Sangfor/VPN appliance login probe
 2x  /ecp/Current/exporttool/...exporttool.application ← MS Exchange ProxyShell (CVE-2021-34473)
 2x  /owa/auth/logon.aspx                           ← Outlook Web Access probe
 1x  /owa/auth/x.js                                 ← OWA recon
 1x  /autodiscover/autodiscover.json?@zdi/Powershell ← Exchange ProxyLogon (CVE-2021-26855)
 2x  /webui/                                        ← router/firewall admin UI
 2x  /geoserver/web/                                ← GeoServer RCE surface (CVE-2024-36401)
 1x  /admin/config.php                              ← generic admin probe
 1x  /cdn-cgi/trace                                 ← Cloudflare-origin fingerprint
 1x  /remote/login                                  ← Fortinet SSL-VPN (CVE-2018-13379)
 1x  /RDWeb                                         ← RD Web Access
 1x  /showLogin.cc                                  ← Sangfor login
 1x  /wp-json/                                      ← WordPress REST recon
 1x  /config/database.yml                           ← Rails DB creds
 1x  /config/secrets.yml                            ← Rails secrets
 1x  /.git-credentials                              ← git creds file
 1x  /___proxy_subdomain_whm/login/                 ← cPanel/WHM probe
```

### Vì sao recon.rs hiện tại miss?

`recon.rs` có pattern cho Exchange? **Không.** Cho Fortinet/Sangfor VPN? **Không.** Cho GeoServer/cPanel? **Không.** Các pattern hiện có tập trung vào `.env/.git`, Spring actuator, Docker API, Jenkins, Kibana — thiếu hẳn **mảng appliance/webmail/VPN** mà BTC quét rất nhiều.

Ngoài ra có **gap regex** ngay trong loại đang cover:
- `r"(?i)(?:\.git(?:/|$))"` → khớp `.git/HEAD` nhưng **KHÔNG** khớp `.git-credentials` (sau `.git` là `-`, không phải `/` hay hết chuỗi).
- `/config/database.yml` không nằm trong allowlist `config.yaml|secrets|settings|credentials` (thiếu `database`).

### Đề xuất rule — thêm vào `RECON_PATHS` trong `detectors/recon.rs`

```rust
// ── Webmail / Exchange (ProxyShell / ProxyLogon) ──
r"(?i)/(?:owa|ecp)/",
r"(?i)/autodiscover/autodiscover\.(?:xml|json)",
r"(?i)/Microsoft-Server-ActiveSync\b",
// ── SSL-VPN / appliance login (Fortinet / Sangfor / RDWeb) ──
r"(?i)/(?:remote/login|remote/fgt_lang)\b",   // Fortinet CVE-2018-13379
r"(?i)(?:^|/)(?:RDWeb|showLogin\.cc|Core/Skin/Login\.aspx)\b",
r"(?i)/(?:dana-na|dana-cached)/",             // Pulse Secure
// ── Web admin surfaces ──
r"(?i)(?:^|/)(?:webui|geoserver/web|whm|cpanel)(?:$|[/?])",
r"(?i)/___proxy_subdomain",
// ── Mở rộng git/config gaps ──
r"(?i)\.git[-/]credentials\b",
r"(?i)(?:^|/)git-credentials\b",
r"(?i)(?:^|/)(?:database|application|app|master)\.ya?ml(?:$|[?#])",
```

**Score:** giữ `recon::PATH = 25` (probe tier). Không single-block — để tích lũy qua risk model (xem Nhóm C).

---

## 3. Nhóm B — DNS-over-HTTPS Tunnel → RULE chuyên biệt

```
4x  /dns-query?name=1.odns.m.dnsmeasure.top&type=A
6x  /dns-query?dns=<base64-DNS-wire-format>
4x  /query?dns=<base64>
```

Đây là **C2/exfiltration qua DoH** — `dnsmeasure.top` là domain đo lường/tunnel. Hai tín hiệu:
1. **Path** `/dns-query`, `/query?dns=` — DoH endpoint (RFC 8484). App NovaBet (betting) **không có lý do** phục vụ DoH.
2. **Param `dns=`** chứa base64 DNS wire-format — entropy cao.

AI **có thể** nhặt được phần (2) qua feature entropy, nhưng không đáng tin (base64 ngắn). Path (1) là tín hiệu chắc chắn → **rule thắng**.

### Đề xuất rule

```rust
// DNS-over-HTTPS tunneling (C2 / exfil) — không phải surface hợp lệ của app
r"(?i)(?:^|/)(?:dns-query|resolve)(?:$|\?)",
r"(?i)[?&]dns=[A-Za-z0-9_-]{16,}",   // base64url DNS wire-format trong query
```

Cân nhắc tách `tag: "dns_tunnel"` score 50 (cao hơn recon thường) vì đây là C2 rõ ràng, không chỉ recon.

---

## 4. Nhóm C — Đã Detect nhưng KHÔNG Block (vấn đề ngưỡng, KHÔNG phải miss)

Các case `risk_score=25` — recon **đã fire đúng**:

```
.env.local / .env.production / .env.example   (recon_path ✓ score 25)
.git/HEAD / .git/index / .git/logs/HEAD       (recon_path ✓ score 25)
wp-config.php / wp-config.php.bak / wp-login   (recon_path ✓ score 25)
backup.sql / openapi.yaml                      (recon_path ✓ score 25)
```

Detector hoạt động đúng. Chúng được **allow vì 25 < `block_at: 80`** (config `dev.yaml` → `risk.thresholds.block_at=80`, `challenge_at=40`).

### Phát hiện nghiêm trọng: risk KHÔNG tích lũy theo IP

IP `64.236.200.103` quét **14 request liên tiếp** (8 cái recon-positive):

```
risk=25  /.git/HEAD
risk=25  /.git/logs/HEAD
risk=25  /.env.local
risk=25  /.env.production
risk=25  /.env.local        ← vẫn 25, KHÔNG cộng dồn
risk=25  /.git/index
risk=25  /wp-config.php.bak
risk=25  /backup.sql        ← scan 8 lần vẫn chỉ 25
```

Theo `risk.weights.detector_hit=25`, `challenge_at=40`, `block_at=80`, `decay_half_life=5m` — một IP quét 8 file nhạy cảm **lẽ ra phải vượt 80 và bị block**. Nhưng score đứng yên ở 25 → **risk model không cộng dồn các recon hit cùng IP** (hoặc decay/cghi đè sai). Đây là bug đáng điều tra riêng, không liên quan rule hay AI.

### Đề xuất

1. **Điều tra risk-accumulation**: vì sao 8 recon hit cùng IP không nâng cumulative score. Kiểm tra đường `detector_hit → risk store` (Redis) — có thể recon signal không feed vào IP-risk accumulator, hoặc bị decay/overwrite mỗi request.
2. **Tùy chọn nhanh:** thêm **velocity rule** — N recon hit / cửa sổ thời gian / IP → nâng score. (Đã có `velocity_sequence.rs`, kiểm tra xem recon có nằm trong chuỗi theo dõi không.)
3. **KHÔNG** hạ `block_at` xuống 25 — sẽ FP hàng loạt (một `.env` đơn lẻ từ scanner internet là noise, block ngay quá gắt). Tích lũy mới đúng.

---

## 5. Ma trận quyết định: Rule vs AI

| Đặc điểm attack | Rule | AI | Lý do |
|---|---|---|---|
| Path nhạy cảm sạch (`/owa/`, `/remote/login`) | ✅ | ❌ | Chuỗi sạch, AI không có feature để phân biệt |
| Danh sách CVE-path hữu hạn, biết trước | ✅ | ❌ | Enumerable → signature chính xác, 0 FP |
| DoH tunnel endpoint | ✅ | ⚠️ | Path là tín hiệu mạnh; entropy chỉ phụ |
| Payload injection biến thể vô hạn (SQLi/XSS obfuscated) | ⚠️ | ✅ | Không enumerable → ML tổng quát hóa tốt |
| PHP RCE encoding lạ (`%ADd`, `%%32%65`) | ⚠️ | ✅ | AI đã bắt 668 case này (`detectors: ai`) |
| Zero-day payload chưa có signature | ❌ | ✅ | Rule mù với cái chưa biết |

**Nguyên tắc:**
- **Cái gì enumerable được (path, endpoint, tool UA) → RULE.** Nhanh, giải thích được, 0 FP, không cần retrain.
- **Cái gì biến thể vô hạn (payload nội dung) → AI.** Production log cho thấy AI **đang làm tốt** mảng này (668 block PHP/RCE).

→ Các miss hiện tại **gần như toàn bộ thuộc nhóm enumerable** → **ưu tiên RULE**, không cần retrain AI.

---

## 6. Khi nào MỚI nên retrain AI?

Chỉ retrain nếu xuất hiện **payload injection** mà model bỏ sót. Trong log 3 ngày này **không có** bằng chứng đó — các case miss đều là path-recon sạch. Nếu muốn cải thiện AI về sau:

1. **Thêm feature semantic** (không phải char-stat): "path khớp danh mục nhạy cảm" như một boolean feature — nhưng việc này trùng với rule, ROI thấp.
2. **Thu thập FN injection thực tế** (nếu có) làm training data — hiện chưa có trong log.
3. **Kết luận:** retrain AI **không giải quyết** các miss hiện tại. Để AI lo payload, để rule lo path.

---

## 7. Hành động đề xuất (ưu tiên)

| # | Việc | File | Loại | Ưu tiên |
|---|---|---|---|---|
| 1 | Thêm pattern Exchange/VPN/appliance/webadmin | `detectors/recon.rs` `RECON_PATHS` | Rule | **Cao** |
| 2 | Vá gap regex `.git-credentials`, `database.yml` | `detectors/recon.rs` | Rule | **Cao** |
| 3 | Thêm rule DoH-tunnel (`/dns-query`, `dns=`) | `detectors/recon.rs` (tag mới) | Rule | **Cao** |
| 4 | Điều tra vì sao recon hit cùng IP không cộng dồn risk | risk store / `velocity_sequence.rs` | Bug | **Cao** |
| 5 | Bổ sung test case từ chính các path trong log này | `recon.rs` tests | Test | Trung bình |
| 6 | Retrain AI | — | AI | **Không cần** (không có FN injection) |

---

## Phụ lục — Lưu ý về timestamp

`recon.rs` sửa lần cuối **2026-06-13**, log là **06-10→12**. Một số rule VULN-03 (`config.yaml`, `secrets.yml`, private key) **được thêm SAU** khi có log này — nghĩa là quá trình vá-theo-log đã bắt đầu. Phân tích này nối tiếp hướng đó với mảng appliance/VPN/DoH còn thiếu.

---

## 8. Đối chiếu với code thực tế (verify 2026-06-14) — cái gì đúng, cái gì cần sửa lại

> Kiểm tra trực tiếp source. **Nhóm A + B + lập luận Rule-vs-AI: ĐÚNG, làm được ngay.**
> **Nhóm C: chẩn đoán SAI** ("risk không cộng dồn") — code có cộng dồn; vấn đề nằm ở chỗ khác.

### 8.1 Đúng & actionable (giữ nguyên đề xuất)

- **Gap recon.rs là thật.** `RECON_PATHS` (`crates/aegis-security/src/detectors/recon.rs:10-90`) **không có** `/owa`·`/ecp`·`autodiscover` (Exchange), `/remote/login`·`Core/Skin/Login.aspx`·`dana-na` (Fortinet/Sangfor/Pulse), `geoserver/web`·`webui`·`whm`·`cpanel`·`RDWeb`, hay `/dns-query` (DoH). Xác nhận thiếu hẳn mảng appliance/webmail/VPN.
- **Gap regex là thật.** `r"(?i)(?:\.git(?:/|$))"` (dòng 13) khớp `.git/` hoặc `.git$` → **KHÔNG** khớp `.git-credentials`. Và không có pattern `database\.ya?ml` (chỉ có `database\.(sql|dump)` dòng 39). Lưu ý: `/config/secrets.yml` thì **đã** được phủ bởi `(?:^|/)(?:secrets?|settings|credentials)\.ya?ml` (dòng 65) — thêm SAU log, đúng như §7.
- **AI model = 29 feature** (`detectors/ai/features.rs:75 NUM_FEATURES=29`, test `vector_is_exactly_29_features`). Lập luận "path sạch → AI mù về nguyên lý → dùng RULE" là **đúng**. Không cần retrain.
- ⇒ Hành động #1, #2, #3, #5 trong §7 **giữ nguyên, ưu tiên Cao**. (Khi thêm regex: anchor theo segment `(?:^|/)…(?:$|[/?])` để tránh FP như các pattern admin-panel đã làm; cân nhắc `dns_tunnel` score 50.)

### 8.2 Nhóm C — chẩn đoán cần sửa lại (QUAN TRỌNG)

Report nói *"risk model không cộng dồn các recon hit cùng IP"* → **không đúng với code**:

- `RiskTracker::record_malicious_*` **cộng dồn cộng tính**: `entry.score = (entry.score + delta).min(max)` (`risk/tracker.rs:260`) + `strikes += 1`. Có test chứng minh: `interleaved_clean_does_not_reset_cumulative_for_shared_key` ("9 recon × 25 = 225, clamp 100 → gate Block").
- Data plane **gọi `record_malicious`** cho mọi recon hit với `delta = max(signal) = 25` (`data_plane.rs:919-928`), comment ghi rõ *"repeated bad requests still escalate → reach block_at in 2-3 hits"*.
- Audit field `risk_score` trên request **allow-nhưng-detected** = `post_state.score` = **cumulative** (`data_plane.rs:1092`); per-request thì nằm riêng ở `fields.request_score` (`:1100`). ⇒ Nếu cumulative tăng thì log **phải** thấy 25→50→75…, không đứng yên.
- Cumulative gate **bật** ở cả `config/dev.yaml` lẫn `config/prod.yaml` (`enabled: true`, `challenge_at:40`, `block_at:80`, `detector_hit:25`, `decay_half_life:5m`).

→ Với một **key ổn định**, 4 hit recon (25→100) **đáng lẽ phải Block**. Việc production thấy `risk_score` đứng yên ở 25 ⇒ score **thực sự không leo cho IP đó**, nhưng **nguyên nhân không phải "tracker hỏng"** mà là một trong:

1. **Risk key là COMPOSITE, không phải IP thuần.** `build_risk_key` = `{ ip, device_fp = hash(JA4 + User-Agent), session = cookie }` (`data_plane.rs:3327-3343`). Scanner đổi UA / TLS-JA4 (hoặc mỗi tool khác nhau) ⇒ `device_fp` đổi ⇒ **mỗi request rơi vào bucket khác** ⇒ mỗi key chỉ thấy 1 hit = 25. Đây là nghi phạm số 1 cho scanner Internet over-HTTPS.
2. **XFF/proxy-trust ở edge.** Nếu node sau L4 LB và không trust XFF đúng hop, **mọi** request (scanner + hàng nghìn request hợp lệ) key về cùng một hop; luồng `record_clean` của traffic sạch **decay** liên tục cái key dùng chung ⇒ tích lũy của scanner bị bào mòn. (Đúng với gotcha đã biết: dev không trust XFF → mọi thứ về 127.0.0.1.)
3. **Decay vs nhịp quét.** `decay_half_life:5m` chỉ áp khi có `record_clean` xen kẽ trên cùng key (malicious thuần thì không decay) — nên #3 thực chất là hệ quả của #2 (clean xen kẽ trên key dùng chung), hoặc khi scanner tự gửi cả request benign.

### 8.3 Hành động Nhóm C (thay cho "điều tra tracker hỏng")

| # | Việc | Cách kiểm chứng | Anchor |
|---|---|---|---|
| C1 | Xác minh **risk key** của 8 hit `64.236.200.103`: cùng `device_fp`/`session` hay đổi? | Re-key log theo `(ip, ja4, ua, session)`; nếu `device_fp` đổi mỗi request ⇒ đúng nghi phạm #1 | `data_plane.rs:3327` |
| C2 | Xác minh **edge XFF trust** trên node chạy production log | Kiểm `trusted_proxies` / hop; nếu mọi request key về 1 IP ⇒ nghi phạm #2 | `build_risk_key` peer_ip nguồn |
| C3 | (Hardening) **Velocity-based recon escalation**: N recon hit / cửa sổ / IP-thuần → nâng score, **độc lập** với composite key | Có sẵn `velocity_sequence.rs` — kiểm recon có nằm trong chuỗi theo dõi không; nếu chưa, thêm | `detectors/velocity_sequence.rs` |
| C4 | (Tùy chọn) thêm **trục IP-thuần song song** cho recon (escalate cả khi UA/TLS xoay) | cân nhắc record thêm key `from_ip(ip)` cho tín hiệu recon | `risk::RiskKey::from_ip` |

**KHÔNG** hạ `block_at` xuống 25 (FP hàng loạt) và **KHÔNG** sửa "tracker không cộng dồn" (nó cộng dồn đúng). Bài toán là **định danh attacker khi UA/TLS xoay** + **XFF ở edge**.

### 8.4 Tóm tắt verdict

| Mục report | Phán quyết | Hành động |
|---|---|---|
| Nhóm A — recon path gaps | ✅ Đúng | Thêm pattern (ưu tiên Cao) |
| Nhóm B — DoH tunnel | ✅ Đúng | Thêm rule `dns_tunnel` |
| Rule-vs-AI, 29-feature, "không retrain" | ✅ Đúng | Không retrain |
| Nhóm C — "risk không cộng dồn" | ❌ Sai (tracker cộng dồn + có test) | Điều tra **composite key + XFF**, không phải tracker |
| Gap `.git-credentials`, `database.yml` | ✅ Đúng | Vá regex |
| `/config/secrets.yml` "miss" | ⚠️ Đã phủ sau log | Không cần thêm |
