# WAF Training Dataset — Phân tích & So sánh

> **Cập nhật:** 2026-05-18  
> **Mục đích:** Tổng hợp toàn bộ nguồn data đang có, đánh giá chất lượng, hỗ trợ lựa chọn data cho việc train model WAF.

---

## 1. Tổng quan nhanh

| # | Nguồn | Samples | Attack classes | Format | Năm | Chất lượng |
|---|-------|--------:|----------------|--------|-----|------------|
| 1 | **openappsec / Malicious** | 73,924 | 7 loại rõ ràng | JSON | 2023–2024 | ⭐⭐⭐⭐ |
| 2 | **openappsec / Legitimate** | ~1,300,000 | Normal only | JSON | 2024 | ⭐⭐⭐⭐⭐ |
| 3 | **SRBH2020 (combine)** | 594,458 | 6 loại | CSV text | 2020 | ⭐⭐⭐ |
| 4 | **SRBH2020 (transfer)** | 12,854 | 4 loại (CAPEC) | CSV text | 2020 | ⭐⭐ |
| 5 | **CSIC 2010** | 97,065 | 1 binary (Normal/Attack) | Raw HTTP | 2010 | ⭐⭐ |
| 6 | **HuggingFace ai-waf-dataset** | 11,949 | Binary → pattern-mapped | Full HTTP text | 2024 | ⭐⭐⭐ |
| 7 | **PayloadsAllTheThings / SecLists** | 1,314 raw → ~6,061 wrapped | 4 loại | Raw payloads | 2024–2025 | ⭐⭐⭐⭐ |
| 8 | **LLM Generator v1** *(mới)* | 210,000 (200K attack + 10K clean) | **21 classes** — bao gồm 8 class mới | NDJSON | 2026 | ⭐⭐⭐⭐ |

**Tổng ước tính (trước cap):** ~2,295,000 samples  
**Classes có trong dataset:** Normal, Injection, XSS, XXE, Manipulation, HTTP abusion, Log4Shell, Scanning, Fake the Source of Data, Dictionary Attack, SSTI *(cũ)* + **SSRF, LDAP Injection, NoSQL Injection, Open Redirect, HTTP Smuggling, GraphQL Abuse, RCE/Deserialization, Prototype Pollution, JWT Abuse, WebSocket Abuse, Evasion Chain, Polyglot** *(mới từ LLM Generator)*

---

## 2. Phân tích chi tiết từng nguồn

---

### Nguồn 1 — openappsec Malicious (`malicious/Malicious/`)

| File | Class | Samples | Size |
|------|-------|--------:|------|
| `sqli.json` | Injection | 916 | 268 KB |
| `cmdexe.json` | Injection | 2,468 | 720 KB |
| `shellshock.json` | Injection | 48 | 14 KB |
| `traversal.json` | Manipulation | 28,314 | 7.6 MB |
| `xss.json` | XSS | 41,888 | 12.0 MB |
| `xxe.json` | XXE | 70 | 36 KB |
| `log4shell.json` | Log4Shell | 220 | 67 KB |
| **TOTAL** | | **73,924** | **20.7 MB** |

**Format mỗi entry:**
```json
{
  "method": "GET",
  "url": "/?p=%00%27%27%20UNION%20SELECT%20...",
  "headers": { ... },
  "data": ""
}
```

**Ưu điểm:**
- Label chính xác 100% theo file name
- Payload phong phú, encode đa dạng (URL encoding, double encoding)
- Nguồn thực tế từ openappsec production WAF
- Bao gồm evasion techniques (null bytes, case variation, encoding tricks)

**Nhược điểm:**
- XSS (41,888) và Manipulation (28,314) áp đảo — SQLi chỉ có 916 samples
- Log4Shell (220) và XXE (70) rất ít — dễ bị underfit
- URL format dạng `/?p=PAYLOAD` (generic path), không phải REST API path

**Khuyến nghị khi dùng:** Dùng tất cả nhưng cần cap để tránh class imbalance. Ưu tiên giữ nguyên XXE và Log4Shell vì số lượng nhỏ.

---

### Nguồn 2 — openappsec Legitimate (`legitimate/Legitimate/`)

| Thuộc tính | Giá trị |
|------------|---------|
| Số file JSON | 692 |
| Ước tính tổng requests | ~1,300,000 |
| Tổng dung lượng | **6.9 GB** |
| HTTP methods | GET ~73%, POST ~27%, PUT/HEAD/DELETE/PATCH nhỏ |
| Label | Normal (100%) |
| Nguồn | Real browser sessions từ 185 websites khác nhau |

**Format mỗi entry:**
```json
{
  "method": "GET",
  "url": "/path/to/resource",
  "headers": { "User-Agent": "Mozilla/5.0 ...", ... },
  "data": ""
}
```

**Ưu điểm:**
- **Nguồn Normal tốt nhất** — real traffic từ browsing thực, đa dạng website
- Bao gồm cả e-commerce, blog, news, API traffic
- Có đầy đủ path patterns, query strings của ứng dụng web thực

**Nhược điểm:**
- Cực kỳ lớn (6.9 GB) — cần sampling khi dùng
- Không có annotation về domain/website type
- Phân phối lệch về GET requests

**Khuyến nghị khi dùng:** Sample tối đa 50,000–100,000 samples. Shuffle trước khi sample để đảm bảo đa dạng domain.

---

### Nguồn 3 — SRBH2020 combine (`SRBH2020/dataset_capec_combine.csv`)

| Class | Samples | % |
|-------|--------:|---|
| Injection | 261,885 | 44.1% |
| Normal | 226,509 | 38.1% |
| Fake the Source of Data | 55,982 | 9.4% |
| Manipulation | 24,519 | 4.1% |
| HTTP abusion | 23,181 | 3.9% |
| Scanning for Vulnerable Software | 2,382 | 0.4% |
| **TOTAL** | **594,458** | |

**Dung lượng:** 72.9 MB  
**Columns:** `text`, `label`, `category`  
**Format text:** `METHOD /path?query [body]` (cùng format project)

**Sample:**
```
GET /blog/index.php/2020/04/04/voluptatum-reprehenderit-maiores-ab-sequi-quaerat
POST /blog/wp-login.php action=login&log=admin&pwd=pass
```

**Ưu điểm:**
- Dataset lớn nhất, format trực tiếp dùng được
- Có class **Fake the Source of Data** (SSRF/header spoofing) không có ở nguồn khác
- Có class **Scanning** (nikto, sqlmap signatures)
- Text đã được extracted từ real WordPress app traffic

**Nhược điểm:**
- Label theo CAPEC taxonomy — một số request "Normal" về payload nhưng bị label là attack do network behavior
- **Label noise cao:** phân tích failure cases cho thấy nhiều request JS/CSS files bị label là Injection
- Injection chiếm 44% — dataset không cân bằng
- Scanning class rất ít (2,382 samples) so với tổng

**Khuyến nghị khi dùng:** Dùng nhưng apply cap 50,000/class. Cân nhắc lọc bỏ các request JS/CSS files bị label sai (xem phần Filter Guide).

---

### Nguồn 4 — SRBH2020 transfer (`SRBH2020/dataset_capec_transfer.csv`)

| Class | Samples | % |
|-------|--------:|---|
| Injection | 8,565 | 66.6% |
| Manipulation | 3,449 | 26.8% |
| HTTP abusion | 534 | 4.2% |
| 16 - Dictionary-based Password Attack | 306 | 2.4% |
| **TOTAL** | **12,854** | |

**Dung lượng:** 2.8 MB

**Ưu điểm:**
- Có class **Dictionary-based Password Attack** duy nhất trong toàn bộ dataset
- Dùng làm **test set chuẩn** (Rust benchmark dùng file này)

**Nhược điểm:**
- Không có class Normal → không thể train standalone
- Injection (66%) và Manipulation (27%) chiếm hầu hết
- Chỉ 4 classes — coverage thấp nhất

**Khuyến nghị khi dùng:** **Giữ riêng làm test set**, không mix vào training data. Đây là benchmark dataset chuẩn của project.

---

### Nguồn 5 — CSIC 2010 (`csic2010/`)

| File | Samples | Label |
|------|--------:|-------|
| `normalTrafficTraining.txt` | 36,000 | Normal |
| `normalTrafficTest.txt` | 36,000 | Normal |
| `anomalousTrafficTest.txt` | 25,065 | Attack (auto-labeled) |
| **TOTAL** | **97,065** | |

**Format:** Raw HTTP/1.1 text — được parse sang project format.  
**App target:** Tienda1 — ứng dụng e-commerce JSP của UC3M (Tây Ban Nha).

**Phân phối auto-label anomalous:**
| Auto-label | Samples | % |
|------------|--------:|---|
| HTTP abusion | 22,722 | 90.7% |
| XSS | 1,450 | 5.8% |
| Injection | 699 | 2.8% |
| XXE | 194 | 0.8% |

**Ưu điểm:**
- Dataset WAF academic nổi tiếng, nhiều paper tham khảo
- Normal traffic có đầy đủ form submission, login, browsing patterns
- Raw HTTP format chứa headers và encoding thực tế

**Nhược điểm:**
- **Quá cũ (2010)** — chỉ có form-encoded requests, không có JSON body hay REST API
- Chỉ traffic từ 1 app duy nhất (Tienda1) → Normal class bị thiếu đa dạng
- Anomalous traffic **không có label chi tiết** theo loại tấn công — phải auto-classify bằng regex
- 90.7% anomalous bị classify là "HTTP abusion" do các patterns không rõ ràng
- **Gây distribution shift:** Normal CSIC (shop requests) khác hoàn toàn Normal openappsec (browser sessions) → model nhầm CSIC Normal sang HTTP abusion

**Khuyến nghị khi dùng:**
- **Normal traffic:** Có thể dùng nhưng với tỷ lệ thấp (cap 10,000) để tránh shift
- **Anomalous traffic:** Chỉ dùng XSS (1,450) và Injection (699) — bỏ HTTP abusion vì noise cao
- Hoặc **bỏ hoàn toàn** nếu muốn dataset sạch hơn

---

### Nguồn 6 — HuggingFace `ai-waf-dataset` (`modern_payloads/ai_waf_dataset.parquet`)

| Label gốc | Samples | % |
|-----------|--------:|---|
| benign | 8,658 | 72.5% |
| malicious | 3,291 | 27.5% |
| **TOTAL** | **11,949** | |

**Phân phối malicious sau auto-classify:**
| Class | Samples |
|-------|--------:|
| HTTP abusion | 2,206 |
| Injection | 376 |
| XXE | 330 |
| XSS | 294 |
| SSTI | 47 |
| Manipulation | 38 |

**Đặc điểm malicious requests:**
- HTTP methods: POST (1,591) > GET (1,430) > PUT (194) > PATCH (62)
- **964 requests có JSON body** (REST API format)
- **1,089 requests trên `/api/` path**

**Format:** Full HTTP request với headers:
```
GET /api/v1/items?item_id=105' UNION SELECT @@VERSION, SLEEP(5) -- HTTP/1.1
Host: shop.example.com
User-Agent: Mozilla/5.0 ...
```

**Ưu điểm:**
- **Dataset hiện đại nhất (2024)** — có REST API paths, JSON body
- Normal traffic đa dạng (blog, news, e-commerce, tech sites)
- Bao gồm cả PUT, PATCH methods — không thấy ở các nguồn khác

**Nhược điểm:**
- Label **binary** (benign/malicious) — attack type phải auto-classify
- Malicious chỉ 3,291 samples — ít
- Auto-classify cho 2,206 là "HTTP abusion" — có thể không chính xác
- Dataset synthetic, không phải real production traffic

**Khuyến nghị khi dùng:** Dùng toàn bộ. Đặc biệt giá trị cho coverage **REST API / JSON body attacks** mà các nguồn cũ không có.

---

### Nguồn 7 — PayloadsAllTheThings / SecLists (`modern_payloads/*.txt, *.fuzz`)

| File | Payloads thô | Class | Nguồn |
|------|------------:|-------|-------|
| `ssti.fuzz` | 105 | SSTI | PayloadsAllTheThings |
| `ssti_engines.txt` | 10 | SSTI | SecLists |
| `nosql_mongodb.txt` | 20 | Injection | PayloadsAllTheThings |
| `nosql_generic.txt` | 26 | Injection | PayloadsAllTheThings |
| `sqli_polyglots.txt` | 2 | Injection | PayloadsAllTheThings |
| `sqli_generic.txt` | 12 | Injection | PayloadsAllTheThings |
| `xss_polyglots.txt` | 16 | XSS | PayloadsAllTheThings |
| `xss_jhaddix.txt` | 110 | XSS | PayloadsAllTheThings |
| `cmd_unix.txt` | 83 | Injection | PayloadsAllTheThings |
| `lfi_jhaddix.txt` | 930 | Manipulation | SecLists |
| **TOTAL** | **1,314** raw → **~6,061** wrapped | | |

**Wrapping template ví dụ:**
```
GET /api/v1/search?q={{4*4}}[[5*5]]          ← SSTI
POST /api/v1/render {"template":"{{7*7}}"}   ← SSTI
GET /api/v1/search?q={"$gt":""}              ← NoSQL Injection
```

**Ưu điểm:**
- **Payloads được maintain liên tục** (GitHub, cập nhật thường xuyên)
- **SSTI** — class hoàn toàn mới, không có trong bất kỳ nguồn nào khác
- **NoSQL Injection** với MongoDB `$operator` syntax
- Polyglots: 1 payload triggers nhiều loại tấn công → test model robustness

**Nhược điểm:**
- **Synthetic hoàn toàn** — payload được wrap vào template cố định, không phải real traffic
- LFI (930 payloads) áp đảo Manipulation class sau wrap
- Số lượng payload thô còn ít — SSTI chỉ 115 payloads → 920 wrapped samples

**Khuyến nghị khi dùng:** Dùng SSTI (920 samples) là quan trọng nhất — không có nguồn thay thế. LFI/Manipulation có thể giảm cap vì nguồn khác đã có Manipulation.

---

### Nguồn 8 — LLM Generator v1 (`data/llm_generator_v1/`)

> **Được tạo:** 2026-05-08 bằng LLM (`generate_v4.py`), seed=42, contract `EN_waf_interop_contract_v2.3`

#### Cấu trúc thư mục

| File | Samples | Mục đích |
|------|--------:|---------|
| `attacks_v4.ndjson` | **200,000** | Dataset attack chính (v4), NDJSON |
| `clean_baselines_v4.ndjson` | **10,000** | Legitimate traffic, phải được WAF allow |
| `attacks.json` | 57 | Test set nhỏ v1 (8 classes) |
| `attacks_v2.json` | ~100 | Test set v2 (8 classes mở rộng) |
| `attacks_v3.json` | 220 | Test set v3 (20 classes) |
| `attacks_v4.meta.json` | — | Metadata đầy đủ cho v4 |
| `contract_tests.json` | ~30 | Compliance test cases (control-plane) |

#### Phân phối class trong attacks_v4.ndjson

| Class | Samples | Tương đương class cũ | Class mới? |
|-------|--------:|----------------------|:----------:|
| recon | 22,000 | Scanning | Mở rộng |
| evasion_chain | 18,000 | — | **Mới** |
| sqli | 18,000 | Injection (subset) | Mở rộng |
| xss | 18,000 | XSS | Mở rộng |
| polyglot | 16,000 | — | **Mới** |
| path_traversal | 14,000 | Manipulation | Mở rộng |
| ssrf | 14,000 | Fake the Source of Data | Mở rộng |
| command_injection | 14,000 | Injection (subset) | Mở rộng |
| ssti | 10,000 | SSTI | Tăng 10× |
| xxe | 8,000 | XXE | Tăng 13× |
| open_redirect | 6,000 | — | **Mới** |
| ldap_injection | 6,000 | — | **Mới** |
| header_injection | 6,000 | HTTP abusion (subset) | Mở rộng |
| nosql_injection | 6,000 | Injection (subset) | Mở rộng |
| prototype_pollution | 4,000 | — | **Mới** |
| log4shell | 4,000 | Log4Shell | Tăng 18× |
| graphql_abuse | 4,000 | — | **Mới** |
| rce_deserialization | 4,000 | — | **Mới** |
| http_smuggling | 3,000 | — | **Mới** |
| jwt_abuse | 3,000 | — | **Mới** |
| websocket | 2,000 | — | **Mới** |
| **TỔNG ATTACK** | **200,000** | | |
| clean (v4) | 10,000 | Normal | — |

**8 classes hoàn toàn mới:** evasion_chain, polyglot, open_redirect, ldap_injection, prototype_pollution, graphql_abuse, rce_deserialization, http_smuggling, jwt_abuse, websocket *(10 class nếu tính hết)*

#### Format mỗi entry (attacks_v4.ndjson)

```json
{
  "id": "sqli-a4282461db",
  "class": "sqli",
  "label": "sqli · obf=urlenc",
  "method": "GET",
  "path": "/support",
  "expected_action": "block",
  "expected_rule": "sqli",
  "obf": "urlenc",
  "base_payload": "1' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
  "query": "u=1%27%20AND%20extractvalue%281%2C...",
  "headers": {
    "user-agent": "Wfuzz/3.1.0",
    "accept": "text/plain",
    "x-forwarded-for": "208.67.222.222"
  }
}
```

**Các trường đặc biệt so với dataset cũ:**
- `obf`: Kỹ thuật obfuscation được dùng (urlenc, urlenc2x, urlenc3x, hex, uniesc, case, sqlcomment, ws, tab, newline, html_dec, html_hex, none)
- `base_payload`: Raw payload TRƯỚC khi obfuscate — rất có giá trị để phân tích
- `expected_action`: WAF phải trả về action gì (block/challenge/rate_limit/allow)
- `expected_rule`: Rule detector nào phải match

**Obfuscation distribution (sample từ 5,000 entries sqli đầu):**

| Obfuscation | Count (sample) | Mô tả |
|-------------|:--------------:|-------|
| urlenc2x | 675 | Double URL encoding |
| newline | 645 | Newline injection |
| ws | 640 | Whitespace trick |
| case | 632 | Case variation |
| none | 624 | Raw payload |
| sqlcomment | 606 | SQL comment insertion |
| urlenc | 597 | Single URL encode |
| hex | 581 | Hex encoding |

**Format clean_baselines_v4.ndjson:**
```json
{
  "id": "clean-54ca09a985",
  "class": "clean",
  "label": "legitimate traffic",
  "method": "GET",
  "path": "/api/products",
  "expected_action": "allow",
  "expected_rule": null,
  "query": "page=2",
  "headers": { "user-agent": "python-requests/2.32.3", ... }
}
```

**Ưu điểm:**
- **Label 100% chính xác** — không có label noise như SRBH2020
- **8–10 classes hoàn toàn mới** không có trong bất kỳ dataset cũ nào
- **Obfuscation metadata** rõ ràng — có thể train model để nhận diện từng loại evasion riêng
- **base_payload** cho phép phân tích và augmentation thêm
- **Reproducible** — seed=42, cùng input → cùng output byte-identical
- **Scale lớn:** Log4Shell từ 220 → 4,000; SSTI từ 967 → 10,000; XXE từ 594 → 8,000
- **evasion_chain và polyglot:** Class mới cho phép train model nhận biết multi-vector attacks

**Nhược điểm:**
- **100% synthetic** — LLM-generated, không phải real traffic → có thể không cover hết các pattern thực tế
- **User-agent pool hạn chế** — headers được tạo từ pool cố định (~22 IP, ~75% legit + 25% scanner UA), không đa dạng như openappsec legitimate
- **Không có Normal traffic đa dạng** — clean_baselines chỉ 10,000 samples, rất ít so với 200K attacks (tỷ lệ 1:20)
- **Class mapping không trực tiếp:** `evasion_chain`, `polyglot`, `graphql_abuse`... không map được sang taxonomy cũ của project (11 classes), cần quyết định merge hay tách
- **Format khác:** NDJSON vs JSON/CSV cũ — cần adapter khi dùng với `build_dataset.py`
- **"ssrf" ≠ "Fake the Source of Data":** Tuy gần giống nhưng SSRF là server-side, còn SRBH2020's "Fake the Source of Data" bao gồm header spoofing rộng hơn

**Khuyến nghị khi dùng:**
- **Dùng ngay:** XXE, Log4Shell, SSTI — giải quyết class nhỏ trong dataset cũ
- **Mapping cần thiết:** `sqli` → Injection, `xss` → XSS, `path_traversal` → Manipulation, `ssrf` → Fake the Source of Data, `recon` → Scanning
- **Tách class mới:** Cân nhắc thêm `ldap_injection`, `nosql_injection`, `graphql_abuse`, `prototype_pollution`, `http_smuggling` vào taxonomy
- **Bỏ hoặc merge:** `evasion_chain` và `polyglot` — nên merge vào class chính tương ứng (theo attack vector chính của từng sample), không nên là class độc lập
- **False positive corpus:** `clean_baselines_v4.ndjson` rất có giá trị để test tỷ lệ false positive của model

---

## 3. Phân phối class tổng hợp (trước cap)

| Class | Src 1 | Src 2 | Src 3 combine | Src 3 transfer | Src 4* | Src 5 | Src 6 | **Src 8 (LLM)** | **TỔNG** |
|-------|------:|------:|--------------:|---------------:|-------:|------:|------:|----------------:|---------:|
| Normal | — | ~1,300,000 | 226,509 | — | 72,000 | 8,658 | — | 10,000 (clean) | **~1,617,167** |
| Injection (SQLi) | 3,432 | — | 261,885 | 8,565 | 699 | 376 | 775 | 18,000 | **~293,732** |
| XSS | 41,888 | — | — | — | 1,450 | 294 | 646 | 18,000 | **~62,278** |
| Manipulation/Path Traversal | 28,314 | — | 24,519 | 3,449 | 0 | 38 | 3,720 | 14,000 | **~74,040** |
| HTTP abusion | — | — | 23,181 | 534 | 22,722 | 2,206 | — | — | **~48,643** |
| Fake the Source / SSRF | — | — | 55,982 | — | — | — | — | 14,000 | **69,982** |
| Scanning / Recon | — | — | 2,382 | — | — | — | — | 22,000 | **24,382** |
| Log4Shell | 220 | — | — | — | — | — | — | 4,000 | **4,220** |
| XXE | 70 | — | — | — | 194 | 330 | — | 8,000 | **8,594** |
| Dictionary Attack | — | — | — | 306 | — | — | — | — | **306** |
| SSTI | — | — | — | — | — | 47 | 920 | 10,000 | **10,967** |
| Command Injection | *(trong Injection)* | — | — | — | — | — | — | 14,000 | **~14,000+** |
| NoSQL Injection | — | — | — | — | — | — | ~46 | 6,000 | **~6,046** |
| Header Injection | — | — | — | — | — | — | — | 6,000 | **6,000** |
| LDAP Injection | — | — | — | — | — | — | — | 6,000 | **6,000** |
| Open Redirect | — | — | — | — | — | — | — | 6,000 | **6,000** |
| Prototype Pollution | — | — | — | — | — | — | — | 4,000 | **4,000** |
| GraphQL Abuse | — | — | — | — | — | — | — | 4,000 | **4,000** |
| RCE/Deserialization | — | — | — | — | — | — | — | 4,000 | **4,000** |
| HTTP Smuggling | — | — | — | — | — | — | — | 3,000 | **3,000** |
| JWT Abuse | — | — | — | — | — | — | — | 3,000 | **3,000** |
| WebSocket Abuse | — | — | — | — | — | — | — | 2,000 | **2,000** |
| Evasion Chain | — | — | — | — | — | — | — | 18,000 | **18,000** |
| Polyglot | — | — | — | — | — | — | — | 16,000 | **16,000** |

> *Source 4 (CSIC 2010) anomalous labels là auto-classified bằng regex, không phải label gốc.  
> Src 8 = `attacks_v4.ndjson` (200K) + `clean_baselines_v4.ndjson` (10K).

**Cải thiện sau khi thêm LLM Generator v1:**
- Log4Shell: 220 → **4,220** (+18×)
- SSTI: 967 → **10,967** (+11×)
- XXE: 594 → **8,594** (+13×)
- Scanning/Recon: 2,382 → **24,382** (+10×)
- **10 classes mới** hoàn toàn không có trong dataset cũ

**Vấn đề imbalance còn lại:**
- Dictionary Attack (306) vẫn cực kỳ thiếu — chưa có nguồn bổ sung
- Normal (~1.6M) vẫn áp đảo, nhưng đây là tự nhiên cho WAF traffic
- `evasion_chain` (18K) và `polyglot` (16K) cần quyết định merge hay giữ làm class riêng

---

## 4. So sánh LLM Generator v1 vs các dataset cũ

### 4a. Đặc điểm kỹ thuật so sánh

| Thuộc tính | Dataset cũ (tổng hợp) | LLM Generator v1 |
|------------|:---------------------:|:----------------:|
| Nguồn gốc | Real traffic + academic | LLM-generated synthetic |
| Format | JSON / CSV / Raw HTTP | NDJSON (streaming-friendly) |
| Label quality | Từ tốt (openappsec) đến noise (SRBH2020) | 100% chính xác (programmatic) |
| Obfuscation info | Không có | Có (`obf` field + `base_payload`) |
| Expected action | Không có | Có (`block/challenge/rate_limit/allow`) |
| Class taxonomy | CAPEC-based (11 classes) | Attack-type based (21 classes) |
| Coverage | 11 classes | **21 classes** (10 mới) |
| Evasion diversity | Hạn chế (encoding chủ yếu) | 13 kỹ thuật obfuscation documented |
| Reproducibility | Không (real traffic) | Có (seed=42 → byte-identical) |
| False positive corpus | Không riêng biệt | Có (`clean_baselines_v4.ndjson`, 10K) |

### 4b. Class mapping giữa 2 hệ taxonomy

| Class cũ (project) | Class tương đương trong LLM v4 | Ghi chú |
|--------------------|-------------------------------|---------|
| Injection | sqli + command_injection + ldap_injection + nosql_injection | LLM tách chi tiết hơn |
| XSS | xss | Giống nhau |
| XXE | xxe | Giống nhau |
| Manipulation | path_traversal | path_traversal = LFI/directory traversal |
| HTTP abusion | header_injection + http_smuggling + websocket | LLM tách thêm 2 loại mới |
| Fake the Source of Data | ssrf | SSRF ≈ FSOD nhưng hẹp hơn |
| Scanning | recon | recon = Scanning mở rộng |
| Log4Shell | log4shell | Giống nhau |
| SSTI | ssti | Giống nhau |
| Dictionary Attack | jwt_abuse *(gần nhất)* | Không có class tương đương chính xác |
| *(không có)* | open_redirect | Class hoàn toàn mới |
| *(không có)* | prototype_pollution | Class hoàn toàn mới |
| *(không có)* | graphql_abuse | Class hoàn toàn mới |
| *(không có)* | rce_deserialization | Class hoàn toàn mới |
| *(không có)* | evasion_chain | Multi-class evasion — nên merge theo vector chính |
| *(không có)* | polyglot | Multi-class — nên merge theo vector chính |

### 4c. Tác động lên class nhỏ (vấn đề cũ)

Bảng dưới so sánh trước/sau khi thêm LLM Generator v1:

| Class | Trước (cũ) | Sau (+LLM v4) | Đánh giá |
|-------|----------:|-------------:|----------|
| Log4Shell | 220 | 4,220 | Giải quyết hoàn toàn — không còn underfitting |
| SSTI | 967 | 10,967 | Giải quyết hoàn toàn |
| XXE | 594 | 8,594 | Giải quyết hoàn toàn |
| Scanning | 2,382 | 24,382 | Giải quyết hoàn toàn |
| Dictionary Attack | 306 | 306 | **Vẫn còn vấn đề** — không có class tương đương trong LLM v4 |

### 4d. Rủi ro khi mix LLM synthetic với real traffic

1. **Distribution mismatch:** LLM tạo ra headers từ pool hạn chế (~22 IP, UA pool cố định). Real traffic có phân phối tự nhiên đa dạng hơn nhiều. Model có thể học shortcut từ LLM headers thay vì payload.

2. **Payload repetition risk:** Với seed cố định và template có hạn, LLM có thể tạo ra nhiều biến thể của cùng một pattern. Cần check n-gram similarity trước khi mix vào train set.

3. **evasion_chain và polyglot không map được:** 34,000 samples (18K + 16K) cần được xử lý riêng — không thể label là class đơn. Options:
   - Phân tích từng sample và assign class theo vector attack chính
   - Tạo class mới "Evasion" và "Polyglot" trong taxonomy
   - Bỏ ra khỏi training, chỉ dùng để test robustness

4. **`clean_baselines_v4.ndjson` là FP corpus, không phải Normal training data:** 10,000 samples này được thiết kế để test WAF không block nhầm, nhưng chúng synthetic. Không nên replace openappsec legitimate làm Normal training data.

---

## 5. So sánh format & compatibility

| Thuộc tính | openappsec JSON | SRBH2020 CSV | CSIC 2010 Raw | HuggingFace | PayloadsATT | **LLM Gen v1** |
|------------|:--------------:|:-----------:|:-------------:|:-----------:|:-----------:|:--------------:|
| Format gốc | JSON object | CSV text | Raw HTTP/1.1 | Full HTTP text | Raw string | **NDJSON** |
| Có HTTP headers | Có | Không | Có | Có | Không | **Có** |
| Có body (POST) | Có | Có | Có | Có | Không | **Có (JSON)** |
| JSON body support | Không | Không | Không | Một phần | Synthetic | **Có** |
| REST /api/ paths | Không | Một phần | Không | Có | Synthetic | **Có** |
| Label chi tiết | Có (file-based) | Có | Không | Binary only | Không | **Có (21 classes)** |
| Obfuscation info | Không | Không | Không | Không | Không | **Có (13 types)** |
| Real traffic | Có | Có | Có | Có | Không | **Không (synthetic)** |
| Năm thu thập | 2023–2024 | 2020 | 2010 | 2024 | 2024–2025 | **2026** |
| Dùng được trực tiếp | Có | Có | Cần parse | Cần parse | Cần wrap | **Cần NDJSON adapter** |

---

## 6. Đánh giá chất lượng & vấn đề đã phát hiện (dataset cũ)

### 5.1 Label noise (SRBH2020)

Phân tích failure cases (3,355 samples bị predict sai) phát hiện **label noise nghiêm trọng**:

```
TRUE=Injection  →  PRED=Normal  (249 cases)
```

Các request bị predict sai bao gồm:
```
GET /blog/wp-includes/js/media-editor.min.js?ver=4.9.5     ← Label: Injection ??
GET /blog/wp-includes/js/jquery/ui/sortable.min.js?ver=1.11.4
```

Đây là WordPress JS files hoàn toàn bình thường — model predict đúng là Normal nhưng SRBH2020 label là Injection do network-level behavior, không phải payload content. Điều này giải thích tại sao accuracy trên SRBH2020 test set (85.79%) thấp hơn nhiều so với unified test set (94.3%).

**Quy tắc lọc đề xuất:**
```python
# Loại bỏ request JS/CSS/image files bị label là attack
STATIC_EXTENSIONS = r'\.(js|css|png|jpg|gif|ico|woff|woff2|ttf|svg|min\.js|min\.css)(\?|$)'
# Nếu path match static extension VÀ category == "Injection" → bỏ
```

### 5.2 Distribution shift (CSIC 2010 Normal)

CSIC 2010 Normal traffic (tienda1 shop) có pattern khác hẳn openappsec Normal (browser sessions):

```
# CSIC 2010 Normal
GET /tienda1/publico/registro.jsp?password=B%C1l%21tEo&login=horatio
TRACE /blog/wp-includes/css/dashicons.min.css?ver=4.9.5

# openappsec Normal  
GET /blog/technology/ai-innovations-in-2024
POST /checkout/payment payment_method=credit_card
```

Model nhầm CSIC Normal sang HTTP abusion do unusual methods (TRACE), Spanish characters, và tienda1 URL patterns.

### 5.3 Class rất nhỏ

| Class | Total samples | Rủi ro |
|-------|-------------:|--------|
| Log4Shell | 220 | Underfitting, recall thấp |
| Dictionary Attack | 306 | Underfitting |
| XXE | 594 | Có thể OK với current features |
| SSTI (mới) | 967 | Borderline |

---

## 7. Filter & Selection Guide

### 6.1 Cấu hình recommended (balanced, high-quality)

```python
# build_dataset.py settings
DEFAULT_CAP = 50_000   # per class

# Giữ nguyên (không cần filter):
# - openappsec malicious: label tốt, payload đa dạng
# - openappsec legitimate: Normal tốt nhất
# - SRBH2020 combine: lớn, có Fake the Source of Data và Scanning
# - HuggingFace: modern REST/JSON format
# - PayloadsAllTheThings SSTI: class mới quan trọng

# Cân nhắc giảm:
# - CSIC 2010 Normal: giảm cap xuống 10,000 để tránh distribution shift
# - CSIC 2010 anomalous HTTP abusion: loại bỏ hoặc giảm nhiều
```

### 6.2 Scenarios lựa chọn data

#### Scenario A: Model cân bằng, đa dạng (hiện tại — recommended)
| Nguồn | Dùng | Cap/class |
|-------|:----:|--------:|
| openappsec malicious | Tất cả | 50,000 |
| openappsec legitimate | Dùng | 50,000 |
| SRBH2020 combine | Dùng | 50,000 |
| SRBH2020 transfer | **Test set only** | — |
| CSIC 2010 Normal | Giảm | **10,000** |
| CSIC 2010 anomalous | Chỉ XSS + Injection | **5,000** |
| HuggingFace | Dùng | 50,000 |
| PayloadsATT | Dùng | 50,000 |

#### Scenario B: Model sạch label (loại bỏ noise)
- Bỏ hoàn toàn CSIC 2010
- Filter SRBH2020: loại request `.js/.css` bị label attack
- Chỉ dùng openappsec + HuggingFace + PayloadsATT

#### Scenario C: Modern attack focus (REST/JSON/API)
- Ưu tiên HuggingFace + PayloadsAllTheThings
- Tăng cap cho SSTI, NoSQL
- Giảm cap CSIC 2010 và SRBH2020

#### Scenario D: Maximum data (no cap)
```bash
python build_dataset.py --no-cap
```
Cảnh báo: Normal class sẽ gấp 1,600× Log4Shell → model bias nặng về Normal.

### 6.3 Classes nên ưu tiên augment thêm

| Class | Current | Priority | Hành động |
|-------|--------:|:--------:|-----------|
| Log4Shell | 220 | 🔴 Cao | Tải thêm từ PayloadsATT CVE-2021-44228 |
| Dictionary Attack | 306 | 🔴 Cao | Tìm thêm brute-force wordlists |
| SSTI | 967 | 🟡 Trung bình | Đã có cơ bản, có thể thêm Jinja2/Twig specific |
| Scanning | 2,382 | 🟡 Trung bình | Thêm Nuclei template signatures |
| XXE | 594 | 🟢 Thấp | Đủ dùng |

---

## 8. Thư mục & cấu trúc file

```
ml_waf/
├── malicious/Malicious/          # Source 1 — openappsec attack payloads
│   ├── sqli.json          (916 samples)
│   ├── cmdexe.json        (2,468 samples)
│   ├── shellshock.json    (48 samples)
│   ├── traversal.json     (28,314 samples)
│   ├── xss.json           (41,888 samples)
│   ├── xxe.json           (70 samples)
│   └── log4shell.json     (220 samples)
│
├── legitimate/Legitimate/        # Source 2 — openappsec real browser sessions
│   └── browsing_2024_*.json     (692 files, ~1.3M requests, 6.9 GB)
│
├── SRBH2020/                     # Source 3 & 4
│   ├── dataset_capec_combine.csv  (594,458 samples, 6 classes)  ← Training
│   └── dataset_capec_transfer.csv (12,854 samples, 4 classes)   ← Test set
│
├── csic2010/                     # Source 5 — CSIC 2010 HTTP dataset
│   ├── normalTrafficTraining.txt  (36,000 Normal)
│   ├── normalTrafficTest.txt      (36,000 Normal)
│   └── anomalousTrafficTest.txt   (25,065 Attack)
│
├── modern_payloads/              # Source 6 & 7
│   ├── ai_waf_dataset.parquet    (11,949 samples — HuggingFace)
│   ├── ssti.fuzz                 (105 SSTI payloads)
│   ├── ssti_engines.txt          (10 SSTI payloads)
│   ├── nosql_mongodb.txt         (20 NoSQL payloads)
│   ├── nosql_generic.txt         (26 NoSQL payloads)
│   ├── sqli_polyglots.txt        (2 SQLi polyglots)
│   ├── sqli_generic.txt          (12 SQLi payloads)
│   ├── xss_polyglots.txt         (16 XSS polyglots)
│   ├── xss_jhaddix.txt           (110 XSS payloads)
│   ├── cmd_unix.txt              (83 CMD injection payloads)
│   └── lfi_jhaddix.txt           (930 LFI/traversal payloads)
│
├── data/llm_generator_v1/        # Source 8 — LLM-generated synthetic dataset
│   ├── attacks_v4.ndjson         (200,000 attacks, 21 classes, seed=42) ← MAIN
│   ├── clean_baselines_v4.ndjson (10,000 legitimate FP corpus)
│   ├── attacks_v4.meta.json      (metadata: class counts, obfuscations)
│   ├── attacks_v3.json           (220 samples, 20 classes — smaller test set)
│   ├── attacks_v2.json           (v2 intermediate)
│   ├── attacks.json              (57 samples, 8 classes — v1 test set)
│   ├── contract_tests.json       (compliance tests: control-plane + headers)
│   └── README.md                 (contract EN_waf_interop_contract_v2.3)
│
├── dataset_unified.csv           # Output tổng hợp (build_dataset.py)
├── build_dataset.py              # Merge & sample pipeline
├── train.py                      # Training script
├── features.py                   # Feature extraction (26 features)
└── waf_model.onnx                # Trained model (36.8 MB)
```

---

## 9. Kết quả model hiện tại (tham khảo)

### Multi-class (11 classes)

| Class | Precision | Recall | F1 | Support |
|-------|----------:|-------:|---:|--------:|
| XXE | 1.000 | 1.000 | 1.000 | 53 |
| XSS | 1.000 | 0.997 | 0.998 | 8,668 |
| Log4Shell | 0.957 | 1.000 | 0.978 | 44 |
| HTTP abusion | 0.952 | 0.989 | 0.970 | 9,288 |
| Injection | 0.972 | 0.956 | 0.964 | 10,000 |
| Fake the Source of Data | 0.959 | 0.922 | 0.940 | 10,000 |
| Manipulation | 0.927 | 0.924 | 0.926 | 10,000 |
| Normal | 0.862 | 0.886 | 0.873 | 10,000 |
| Scanning | 0.843 | 0.798 | 0.820 | 476 |
| **Overall accuracy** | | | **0.943** | 58,590 |

### Binary (Normal vs Attack) — Rust benchmark trên SRBH2020 transfer
- **Accuracy:** 85.79% trên dataset_capec_transfer.csv
- Accuracy thấp hơn do label noise trong SRBH2020 (xem mục 5.1)

### Inference performance

| | Python | Rust |
|---|-------:|-----:|
| batch=1 (real-time WAF) | 732 req/s | **4,600 req/s** |
| batch=10,000 (bulk) | 7,424 req/s | **13,860 req/s** |
| Latency p99 (batch=1) | 3.9ms | **0.5ms** |

---

## 10. Checklist trước khi train

- [ ] Chạy `python build_dataset.py` để rebuild `dataset_unified.csv`
- [ ] Kiểm tra class distribution trong output (tránh class < 500 samples)
- [ ] Verify `dataset_capec_transfer.csv` **không** bị mix vào training data
- [ ] Nếu thêm SSTI class: update `waf_infer/src/features.rs` và rebuild Rust
- [ ] Sau train: chạy binary evaluation (Normal vs Attack) song song với multi-class
- [ ] Benchmark Rust inference sau khi export ONNX mới

**Checklist bổ sung khi integrate LLM Generator v1:**
- [ ] Viết adapter chuyển `attacks_v4.ndjson` (NDJSON) → format CSV của `build_dataset.py`
- [ ] Quyết định taxonomy: giữ nguyên 11 class hay thêm class mới (ldap_injection, nosql_injection, graphql_abuse, etc.)
- [ ] Xử lý `evasion_chain` và `polyglot` — merge vào class theo vector chính hay tạo class riêng
- [ ] Kiểm tra n-gram similarity giữa LLM-generated payloads và test set để tránh data leakage
- [ ] Dùng `clean_baselines_v4.ndjson` như FP test corpus (không mix vào Normal training)
- [ ] Nếu thêm class mới: update taxonomy trong `features.py` và rebuild label encoder

---

*Report được cập nhật thủ công sau khi phân tích dữ liệu thực tế và so sánh với nguồn mới. Cập nhật lại sau mỗi lần thêm nguồn data.*
