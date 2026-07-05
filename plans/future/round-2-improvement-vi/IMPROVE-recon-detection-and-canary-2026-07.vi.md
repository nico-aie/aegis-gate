> 🇻🇳 Bản dịch tiếng Việt của [IMPROVE-recon-detection-and-canary-2026-07.md](../round-2-improvement/IMPROVE-recon-detection-and-canary-2026-07.md) — bản gốc tiếng Anh là source of truth.

# IMPROVE — Tăng cường phát hiện recon (do thám) + gieo canary-path (đường dẫn bẫy)

> **Loại:** IMPROVE (từ `CURRENT-STATE-FINDINGS.md` của l-tester) · **Trạng thái:** ☐ Chưa bắt đầu — lên kế hoạch 2026-07-04
> **Tiền tố Track ID:** `RC-<1–5>` · **Tài liệu anh em:** [IMPROVE-detection-fp-tuning-2026-07.vi.md](IMPROVE-detection-fp-tuning-2026-07.vi.md)
> (dùng chung harness corpus benign/attack — xây một lần, cả hai kế hoạch cùng dùng).
> **Báo cáo nguồn:** `tests/l-tester/reports/CURRENT-STATE-FINDINGS.md` — đã kiểm chứng từng luận điểm đối chiếu
> với code 2026-07-04 (phán quyết ở §1). **Đọc §1 trước khi động vào code — phần lớn phân tích nguyên nhân gốc
> của báo cáo là sai dù kết luận tiêu đề thì đúng.**

**Mục tiêu (theo tinh thần, không theo câu chữ):** nâng khả năng chặn recon/rò rỉ bí mật trong thực tế mà không làm
phình false positive (cảnh báo sai) — bằng cách (a) sửa *đúng* nguyên nhân gốc (điểm số confidence thấp, chứ không phải
regex bị bypass), (b) bổ sung các signature (chữ ký nhận dạng) thực sự còn thiếu, và (c) gieo canary path cho các route
không bao giờ hợp lệ để chỉ một lần dò cũng chặn được, kể cả từ một IP mới toanh.

---

## 1. Kiểm chứng báo cáo — điều gì đúng, điều gì sai

**Kết luận tiêu đề dựa trên thực nghiệm của báo cáo là TRUE**: khi replay 263 recon path, mỗi path từ một IP mới, tất cả
đều trả về phản hồi từ origin (không bị chặn). Nhưng **phân tích nguyên nhân gốc (V1–V6) hầu hết là WRONG** — cái bẫy
kinh điển của l-tester ([[project_ltester_decodes_dataplane_raw]]): harness suy luận từ hành vi black-box, chứ không phải
từ code của detector.

| ID | Luận điểm của báo cáo | Phán quyết | Thực tế (bằng chứng) |
|---|---|---|---|
| — | 263 recon path được cho qua từ một IP mới | **TRUE (thực nghiệm)** | nhưng *nguyên nhân* là scoring, không phải bypass — xem hộp bên dưới |
| V1 | Bypass qua tiền tố thư mục (`/backend/.git/config` lọt qua) | **FALSE** | các regex recon là substring / neo bằng `(?:^|/)`, không neo ở gốc; `/backend/.git/config` **khớp** (`recon.rs:15-16,22`; test `env_in_subdir` `recon.rs:586`) |
| V2 | Bypass qua biến đổi hậu tố (tất cả `.bak/.old/~/.txt` đều né được) | **PARTIAL** | các rule backup+tilde đã bắt được `.bak/.old/.save/.swp/~` (`recon.rs:50,56`). **Lỗ hổng thực sự:** `/config.env`, `/aws.env`, `/wp-config.txt`, và các dạng generic `.backup/.gz/.zip` |
| V3 | Bypass qua đổi chữ hoa/thường (`/Admin/phpinfo.php` lọt qua) | **FALSE** | mọi regex đường dẫn đều mang cờ `(?i)` (`recon.rs:15-196`); chữ hoa/thường đã được xử lý |
| V4 | Cây con `/actuator/*` không được bao phủ | **FALSE** | cây con nguy hiểm được liệt kê tường minh (`recon.rs:114`) + index trần (`recon.rs:171`); `/actuator/env|heapdump|httptrace|threaddump|configprops` đều khớp (test `recon.rs:430-434`) |
| V5 | Thiếu signature (liệt kê 11 cái) | **PARTIAL (7 trong 11 là thật)** | thực sự vắng: `/id_rsa`, `/.npmrc`, `/.git-credentials`, generic `/secrets.{json,txt,…}`, `/autodiscover/*`, `/owa/auth/logon.aspx`, `/wp-json/*`. Đã có sẵn (báo cáo sai): `/.aws/credentials` (`recon.rs:78`), `/private_key.pem` (`recon.rs:109`), `/.htpasswd` (`recon.rs:21`), `/wp-login.php` (`recon.rs:34`) |
| V6 | Double-slash không được chuẩn hoá | **PARTIAL** | không có chuẩn hoá đường dẫn nào tồn tại (TRUE, lỗ hổng defense-in-depth) — nhưng `//` **không** đánh bại được neo `(?:^|/)`; `wlwmanifest.xml`/`xmlrpc.php` được trích dẫn lọt qua là vì chúng **hoàn toàn không có signature**, chứ không phải vì `//` |
| V7 | Risk-score che lấp các lỗ hổng theo từng path | **TRUE** | mô hình hai điểm (cumulative MAX+decay so với per-request SUM); một nguồn kích hoạt bất kỳ detector nào 2-3 lần sẽ đạt `block_at=70` → mọi request sau đó đều bị chặn dưới danh nghĩa `risk-score` bất kể path (`data_plane.rs:1311-1345,1619-1687`). IP mới bắt đầu từ 0 → cho qua |
| V8 | Được cho qua dù `risk_score` cao từ loopback = loopback được tin cậy | **lý thuyết FALSE, quan sát TRUE** | không có tin cậy loopback ở bất kỳ đâu. Nguyên nhân thật: dev `trusted_proxies` rỗng → XFF bị bỏ qua → mọi traffic cục bộ đều key về `127.0.0.1` (`xff.rs:18-21`, [[feedback_dev_xff_single_ip_gates]]); `risk_score` trong audit là điểm *tích luỹ* (accumulation), phán quyết dùng ngưỡng theo tier (65 = dải challenge, được cho qua khi challenge tắt) |
| V9 | Các sự kiện admin audit có trường `ip` cấp cao nhất rỗng | **TRUE** | `AdminChangeEntry::to_audit_event` hard-code `client_ip: String::new()` (`audit/mod.rs:33`); IP thật chỉ nằm ở `fields.diff.after.value` |

> ### 🔑 Nguyên nhân gốc thực sự (vì sao 263 path lọt qua từ một IP mới)
> Recon detector **có khớp** các path này — nó chỉ chấm điểm chúng là **25** (`scores.rs:117`,
> `recon::PATH = 25`), tức là *thấp hơn* `challenge_at = 30` và thấp hơn nhiều so với `block_at = 70`
> (`config.rs:4863-4873`). Nên **một** lần dò recon từ IP mới chấm 25 → **Allow** theo thiết kế
> (confidence thấp, né FP). Cần 2-3 lần recon từ *cùng một* key mới tích luỹ vượt 70 và
> chặn. Đối với một scanner thật (nhiều path, một IP) WAF chặn đúng nhờ accumulation (tích luỹ điểm rủi ro); lỗ hổng
> là **recon phân tán, low-and-slow** — mỗi path từ một IP khác nhau (log prod cho thấy các dải GCP
> `34.x/35.x`, ~29 hit mỗi cái trải trên nhiều IP), nên không key nào tích luỹ được. Đó là một lỗ hổng
> thực sự, nhưng cách sửa là **scoring + canary tripwire (dây bẫy)**, chứ không phải "sửa bypass tiền tố/chữ-hoa/cây-con" (những thứ
> không hề tồn tại).

## 2. Ba đòn bẩy (theo thứ tự ưu tiên)

1. **Confidence/scoring** (RC-2) — nguyên nhân thật. Chia recon thành các tier: các path
   *rò rỉ bí mật/RCE* không bao giờ hợp lệ thì chặn mạnh hơn; các lần dò generic vẫn giữ điểm thấp.
2. **Canary tripwire** (RC-1) — chặn tức thì ngay lần đầu (điểm 100) cho một tập không-bao-giờ-hợp-lệ được tuyển chọn,
   đánh bại kiểu né tránh recon phân tán. Chiến thắng nhanh nhất, rủi ro thấp nhất, không phải đụng đến regex.
3. **Coverage** (RC-3) — thêm 7 họ signature thực sự còn thiếu + 3 lỗ hổng V2 có thật.

Cộng thêm: RC-4 chuẩn hoá (defense-in-depth), RC-5 các bản sửa nhỏ nhưng đúng (V9) + tài liệu hoá V7/V8.

## 3. Phân đợt triển khai (Staging)

### RC-1 — gieo canary path cho các route không bao giờ hợp lệ · **S** · BẮT ĐẦU TỪ ĐÂY
Canary = điểm 100 = chặn ngay lần đầu ở mọi tier (`scores.rs:446`, canary đã kiểm chứng 2026-07-04).
Có thể chỉnh lúc runtime qua `PUT /api/risk/canary-paths` (full-replace, giới hạn 256, bền vững). **Hai điều kiện tiên quyết:**
`detectors.canary.enabled` mặc định **OFF** và `risk.canary_paths` mặc định **rỗng** — cả hai đều phải được đặt.
- Ship một `risk.canary_paths` mặc định được tuyển chọn + bật `detectors.canary.enabled: true` trong config mặc định.
- **Tập tuyển chọn (không có caller hợp lệ nào):** `/.git/config`, `/.git/HEAD`, `/.env`, `/.aws/credentials`,
  `/.git-credentials`, `/id_rsa`, `/wp-config.php`, `/terraform.tfstate`, `/actuator/heapdump`,
  `/actuator/env`, `/.ssh/id_rsa`, `/server.key`. Dùng entry chính xác; cân nhắc cây con `/.git/*`.
- **KHÔNG** đặt canary cho bất cứ thứ gì có traffic hợp lệ (`/actuator/health`, `/actuator/info`, bất kỳ route
  ứng dụng nào). Canary là một hard block — một entry sai là một sự cố (outage).
- **Giới hạn đã biết (tài liệu hoá, đừng over-engineer):** canary khớp trên đường dẫn **raw, phân biệt hoa/thường**
  (`canary.rs:97-135`) — các biến thể được mã hoá (`%2egit`) hoặc có tiền tố `//` sẽ lọt qua; điều đó ổn với một
  tripwire (recon + RC-4 hỗ trợ thêm). Quét tuyến tính, giới hạn 256 — giữ danh sách được tuyển chọn, đừng liệt kê tất cả.

### RC-2 — chấm điểm recon theo tier · **M**
Mức `25` né-FP là đúng cho các lần dò *generic* nhưng quá thấp cho những trường hợp rò rỉ bí mật rõ ràng.
- Giới thiệu một điểm `recon::SENSITIVE` (ví dụ 50–70, tinh chỉnh với corpus) cho tập con
  rò-rỉ-bí-mật/RCE: file credential, private key, `terraform.tfstate`,
  `/actuator/{heapdump,env,configprops}`, `wp-config.php`. Ở mức 50, vẫn cần hai hit; ở mức 70, một
  hit là chặn — **owner + corpus quyết định giá trị chính xác** (đây là lằn ranh dao cạo của FP).
- Giữ `recon::PATH = 25` cho các lần dò generic/mơ hồ (`/phpinfo.php`, index `/actuator`, swagger).
- Cơ chế: gắn nhãn các pattern nhạy cảm với điểm cao hơn trong bảng signature (`scores.rs` +
  metadata pattern trong `recon.rs`) — không thay đổi gate/ngưỡng, nên nó ghép hợp với accumulation hiện có.
- **Gate trên corpus** (RC dùng chung harness của FP-tuning): tier nhạy cảm không được kích hoạt trên corpus
  benign. Soak ở chế độ log-only trước khi mức điểm chặn-ngay-lần-đầu được đưa vào chạy thật.

### RC-3 — bổ sung các signature thực sự còn thiếu · **S–M**
Thêm vào `RECON_PATHS` (`recon.rs`), mỗi cái kèm một unit test trên dạng **raw**:
- Bí mật: `/id_rsa` (trần, không đuôi), `/.npmrc`, `/.git-credentials`, generic
  `(?:^|/)secrets?\.(?:json|txt|ya?ml|env|config)` (hiện chỉ có `.ya?ml`).
- Lỗ hổng V2 thật: bắt `/config.env`,`/aws.env` (`.env` trần đứng sau một từ) và `/wp-config.txt`;
  thêm `.backup|.gz|.zip` vào tập hậu tố backup. Neo chặt — không được khớp path hợp lệ `*.environment`.
- Exchange/ProxyShell: `/autodiscover/autodiscover\.json`, `/owa/auth/logon\.aspx`,
  `/Core/Skin/Login\.aspx`.
- WordPress: `/wp-json/` (ít nhất là `gravitysmtp` bị lạm dụng + `wp/v2/settings`), `wlwmanifest\.xml`,
  `/xmlrpc\.php`.
- Linh tinh từ tập 263: `/Jenkinsfile`, `jenkins.*config\.xml`, `/\.terraform/`. (`/\.DS_Store`,
  `/\.htaccess` đã có sẵn; `/\.well-known/security\.txt` là chuẩn hợp lệ — bỏ qua.)
- **Mỗi lần thêm = một unit test Rust dạng raw** ([[project_ltester_decodes_dataplane_raw]]); kiểm chứng
  đối chiếu với corpus benign để không cái nào trở thành FP kinh niên.

### RC-4 — chuẩn hoá đường dẫn để khớp (defense-in-depth) · **M** (cẩn thận — làm sau RC-1/2/3)
- Gộp `//`→`/` và giải quyết `.`/`..`, và khớp trên một bản **đã percent-decode**, *bổ sung cho*
  dạng raw — không bao giờ thay thế raw (raw là hợp đồng cho các detector khác,
  [[project_hyper_normalizes_framing]], [[project_ltester_decodes_dataplane_raw]]).
- Phạm vi: ảnh hưởng đến tất cả detector khớp đường dẫn, nên hãy đưa vào dưới dạng một helper "normalized view"
  dùng chung mà detector đọc song song với `origin_form_uri`, có guard + benchmark (hot path).
- Đây là bản sửa tổng quát cho V6 + né tránh canary được mã hoá; ưu tiên thấp hơn vì RC-1/2/3 đã bao phủ
  traffic thật quan sát được và cái này đụng đến hệ ống dùng chung.

### RC-5 — các bản sửa nhỏ đúng đắn + tài liệu · **S**
- **V9:** điền trường `ip` cấp cao nhất trong các sự kiện admin audit bằng client IP của actor — gộp vào
  AU-1 của [FEAT-audit-coverage-gaps-2026-07.vi.md](FEAT-audit-coverage-gaps-2026-07.vi.md) (làm ở đó, không
  làm hai lần); tham chiếu chéo tại đây để không bị bỏ sót.
- **V7/V8:** đang hoạt động đúng thiết kế — **tài liệu hoá**, đừng "sửa". Thêm một ghi chú ngắn vào tài liệu detection
  giải thích mô hình hai điểm và hiện tượng dev-XFF-collapse ([[feedback_dev_xff_single_ip_gates]],
  [[feedback_two_score_model]]) để báo cáo lần sau không chẩn đoán sai lại. Observability tuỳ chọn:
  một metric đếm hit detector theo từng path, độc lập với các block `risk-score`, để dashboard tổng hợp thôi
  che lấp khả năng theo từng path (một hiểu biết thực sự hữu ích duy nhất của V7).

## 4. Kiểm thử (RED-first)

- RC-1: mỗi canary path được tuyển chọn → một request duy nhất từ một **IP mới** bị chặn (403) với lý do
  `canary`; một path hợp lệ trông giống (`/actuator/health`) **không** bị chặn; toggle-off → không chặn.
- RC-2: một path thuộc tier nhạy cảm từ một IP mới đạt phán quyết mong muốn ở điểm đã chọn;
  lần dò generic vẫn được cho qua ngay lần đầu; không cái nào kích hoạt trên corpus benign.
- RC-3: unit test dạng raw cho mỗi signature mới (positive) + negative trên corpus benign (không FP).
- RC-4: các biến thể `//x`, `/./x`, mã hoá `%2e` chuẩn hoá về khớp canonical; path raw vẫn còn
  sẵn cho các detector khác; delta benchmark nằm trong ngân sách.
- Regression: các test recon hiện có (module test của `recon.rs`) vẫn xanh; workspace không cảnh báo
  ([[feedback_test_suite_green_baseline]]).
- **Corpus gate** trên mọi thay đổi scoring/signature (dùng chung với kế hoạch FP-tuning).

## 5. Rủi ro

| Mức | Rủi ro | Giảm thiểu |
|---|---|---|
| HIGH | Canary chặn nhầm (một path có traffic thật) = outage | chỉ dùng danh sách không-bao-giờ-hợp-lệ được tuyển chọn; negative test cho path trông giống; canary khớp chính xác nên bán kính ảnh hưởng đúng bằng chuỗi cụ thể; shadow log-only danh sách trước nếu chưa chắc |
| HIGH | RC-2/RC-3 làm tăng FP trên traffic benign | corpus gate + soak log-only trước các mức điểm chặn-ngay-lần-đầu; giữ tier generic ở 25 |
| MEDIUM | Regex `.env`/`secrets` của RC-3 quá rộng khớp path hợp lệ | neo chặt + negative test trên corpus benign; ưu tiên cụ thể hơn tham lam |
| MEDIUM | Hiệu năng chuẩn hoá RC-4 trên hot path | shared cached view, benchmark release-profile mỗi PR (LT-P1); làm sau cùng |
| LOW | Né tránh canary bằng mã hoá/`//` | thừa nhận giới hạn của tripwire; recon + RC-4 cung cấp chiều sâu |

## 6. Tiêu chí nghiệm thu (Acceptance)

- [ ] Ghi lại kiểm chứng §1 để chẩn đoán sai V1/V3/V4 của báo cáo không bị đem ra tranh cãi lại.
- [ ] RC-1: tập canary được tuyển chọn đã ship + bật toggle mặc định; chứng minh chặn-ngay-lần-đầu từ IP mới; không regression trên path hợp lệ.
- [ ] RC-2: scoring recon tier nhạy cảm, có corpus-gate, có bằng chứng soak.
- [ ] RC-3: thêm 7 họ còn thiếu + 3 lỗ hổng V2, test dạng raw + sạch trên corpus.
- [ ] RC-4 (tuỳ chọn/sau cùng): normalized matching view, đã benchmark.
- [ ] RC-5: V9 được xử lý trong kế hoạch audit; V7/V8 được tài liệu hoá là đúng thiết kế.
- [ ] Hướng tới hội đồng (committee): tỷ lệ chặn recon trước/sau trên bài replay 263-path từ các IP mới.
