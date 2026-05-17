# WAF Training Dataset — Phân tích & So sánh

> **Cập nhật:** 2026-04-30  
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

**Tổng ước tính (trước cap):** ~2,085,000 samples  
**Classes có trong dataset:** Normal, Injection, XSS, XXE, Manipulation, HTTP abusion, Log4Shell, Scanning, Fake the Source of Data, Dictionary Attack, SSTI *(mới)*

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

## 3. Phân phối class tổng hợp (trước cap)

| Class | Source 1 | Source 2 | Source 3 combine | Source 3 transfer | Source 4* | Source 5 | Source 6 | **TỔNG** |
|-------|--------:|--------:|-----------------:|------------------:|----------:|---------:|---------:|---------:|
| Normal | — | ~1,300,000 | 226,509 | — | 72,000 | 8,658 | — | **~1,607,167** |
| Injection | 3,432 | — | 261,885 | 8,565 | 699 | 376 | 775 | **~275,732** |
| XSS | 41,888 | — | — | — | 1,450 | 294 | 646 | **~44,278** |
| Manipulation | 28,314 | — | 24,519 | 3,449 | 0 | 38 | 3,720 | **~60,040** |
| HTTP abusion | — | — | 23,181 | 534 | 22,722 | 2,206 | — | **~48,643** |
| Fake the Source of Data | — | — | 55,982 | — | — | — | — | **55,982** |
| Scanning | — | — | 2,382 | — | — | — | — | **2,382** |
| Log4Shell | 220 | — | — | — | — | — | — | **220** |
| XXE | 70 | — | — | — | 194 | 330 | — | **594** |
| Dictionary Attack | — | — | — | 306 | — | — | — | **306** |
| SSTI | — | — | — | — | — | 47 | 920 | **967** |

> *Source 4 (CSIC 2010) anomalous labels là auto-classified bằng regex, không phải label gốc.

**Vấn đề imbalance rõ ràng:**
- Normal (~1.6M) gấp ~5,800× Log4Shell (220)
- Dictionary Attack (306) và SSTI (967) cực kỳ thiếu data
- Cần cap 50,000/class và augmentation riêng cho các class nhỏ

---

## 4. So sánh format & compatibility

| Thuộc tính | openappsec JSON | SRBH2020 CSV | CSIC 2010 Raw | HuggingFace | PayloadsATT |
|------------|:--------------:|:-----------:|:-------------:|:-----------:|:-----------:|
| Format gốc | JSON object | CSV text | Raw HTTP/1.1 | Full HTTP text | Raw string |
| Có HTTP headers | Có | Không | Có | Có | Không |
| Có body (POST) | Có | Có | Có | Có | Không (payload only) |
| JSON body support | Không | Không | Không | Một phần | Synthetic |
| REST /api/ paths | Không | Một phần | Không | Có | Synthetic |
| Label chi tiết | Có (file-based) | Có | Không | Binary only | Không |
| Năm thu thập | 2023–2024 | 2020 | 2010 | 2024 | 2024–2025 |
| Dùng được trực tiếp | Có | Có | Cần parse | Cần parse | Cần wrap |

---

## 5. Đánh giá chất lượng & vấn đề đã phát hiện

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

## 6. Filter & Selection Guide

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

## 7. Thư mục & cấu trúc file

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
├── dataset_unified.csv           # Output tổng hợp (build_dataset.py)
├── build_dataset.py              # Merge & sample pipeline
├── train.py                      # Training script
├── features.py                   # Feature extraction (26 features)
└── waf_model.onnx                # Trained model (36.8 MB)
```

---

## 8. Kết quả model hiện tại (tham khảo)

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

## 9. Checklist trước khi train

- [ ] Chạy `python build_dataset.py` để rebuild `dataset_unified.csv`
- [ ] Kiểm tra class distribution trong output (tránh class < 500 samples)
- [ ] Verify `dataset_capec_transfer.csv` **không** bị mix vào training data
- [ ] Nếu thêm SSTI class: update `waf_infer/src/features.rs` và rebuild Rust
- [ ] Sau train: chạy binary evaluation (Normal vs Attack) song song với multi-class
- [ ] Benchmark Rust inference sau khi export ONNX mới

---

*Report này được tự động sinh từ phân tích dữ liệu thực tế. Cập nhật lại sau mỗi lần thêm nguồn data mới.*
