# ML-WAF — Machine Learning Web Application Firewall

Hệ thống phân loại HTTP request thời gian thực sử dụng **LightGBM** (Python training) + **ONNX Runtime** (Rust inference). Model nhận vào một HTTP request dạng text, trích xuất 26 engineered features và phân loại vào 11 class tấn công / bình thường.

```
HTTP Request
     │
     ▼
Feature Extraction (26 features)
     │
     ▼
LightGBM Classifier (ONNX)
     │
     ▼
Label: Normal / Injection / XSS / SSTI / ...
```

---

## Mục lục

1. [Kiến trúc tổng quan](#1-kiến-trúc-tổng-quan)
2. [Yêu cầu hệ thống](#2-yêu-cầu-hệ-thống)
3. [Cài đặt môi trường](#3-cài-đặt-môi-trường)
4. [Chuẩn bị dữ liệu](#4-chuẩn-bị-dữ-liệu)
5. [Training model](#5-training-model)
6. [Rust inference & benchmark](#6-rust-inference--benchmark)
7. [Cấu trúc project](#7-cấu-trúc-project)
8. [Classes & nhãn](#8-classes--nhãn)
9. [Feature extraction](#9-feature-extraction)
10. [Thêm dữ liệu mới](#10-thêm-dữ-liệu-mới)
11. [Troubleshooting](#11-troubleshooting)
12. [Kết quả benchmark](#12-kết-quả-benchmark)

---

## 1. Kiến trúc tổng quan

Project được chia làm 2 phần tách biệt:

| Phần | Công nghệ | Mục đích |
|------|-----------|---------|
| **Training pipeline** | Python 3.11, LightGBM, scikit-learn | Merge data → extract features → train → export ONNX |
| **Inference engine** | Rust, ONNX Runtime (ORT 2.x) | Load ONNX model → classify request → benchmark latency |

Lý do tách: Python tiện cho training/experimentation, Rust cho production với latency sub-millisecond và throughput cao (~14K req/s ở batch lớn).

**Luồng đầy đủ:**

```
[Data sources]          [Python]                [Rust]
  JSON / CSV   →   build_dataset.py   →   dataset_unified.csv
                          │
                       train.py
                          │
                   waf_model.onnx  ──────►  waf_infer/
                   label_map.json  ──────►  (cargo run --release)
```

---

## 2. Yêu cầu hệ thống

- **OS:** Windows 10/11 (đã test), Linux/macOS tương thích
- **Python:** 3.11+ (qua Conda/Miniconda)
- **Rust:** 1.75+ (cài qua rustup)
- **RAM:** tối thiểu 8 GB (16 GB recommended khi build dataset đầy đủ)
- **Disk:** ~15 GB tổng (bao gồm legitimate dataset ~7 GB)

---

## 3. Cài đặt môi trường

### 3.1 Python — Conda environment

```bash
# Tạo conda environment tên "waf" với Python 3.11
conda create -n waf python=3.11 -y
conda activate waf

# Cài đặt dependencies
pip install -r requirements.txt
```

**requirements.txt** bao gồm:
```
lightgbm>=4.3.0
scikit-learn>=1.4.0
pandas>=2.1.0
numpy>=1.26.0
onnxmltools>=1.16.0
onnxruntime>=1.17.0
```

> **Lưu ý:** Nếu đọc file `.parquet` (HuggingFace dataset) cần thêm:
> ```bash
> pip install pyarrow
> ```

### 3.2 Rust — Cài đặt rustup

Tải và cài rustup từ [https://rustup.rs](https://rustup.rs).  
Sau khi cài, Rust và Cargo sẽ được đặt tại `~/.cargo/bin/`.

#### Thêm Cargo vào PATH (Windows PowerShell)

**Cho session hiện tại** (dùng ngay sau khi cài, không cần restart terminal):

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
```

**Vĩnh viễn** (áp dụng cho tất cả terminal mới về sau):

```powershell
[Environment]::SetEnvironmentVariable(
    "PATH",
    "$env:USERPROFILE\.cargo\bin;" + [Environment]::GetEnvironmentVariable("PATH", "User"),
    "User"
)
```

> **Quan trọng:** Lệnh `SetEnvironmentVariable` chỉ có hiệu lực ở terminal **mới** sau đó. Terminal hiện tại vẫn cần chạy lệnh `$env:PATH = ...` ở trên.

Kiểm tra cài đặt thành công:

```powershell
cargo --version
# cargo 1.75.0 (...)
rustc --version
# rustc 1.75.0 (...)
```

---

## 4. Chuẩn bị dữ liệu

### 4.1 Cấu trúc thư mục data

```
ml_waf/
├── malicious/Malicious/       ← openappsec attack payloads (JSON)
├── legitimate/Legitimate/     ← real browser sessions (JSON, ~7 GB)
├── SRBH2020/                  ← academic dataset (CSV)
├── csic2010/                  ← CSIC 2010 HTTP dataset (raw text)
└── modern_payloads/           ← HuggingFace + PayloadsAllTheThings
```

### 4.2 Nguồn dữ liệu

Project tổng hợp từ **7 nguồn**:

| # | Thư mục / File | Samples | Mô tả |
|---|---------------|--------:|-------|
| 1 | `malicious/Malicious/*.json` | 73,924 | openappsec: SQLi, XSS, XXE, traversal, log4shell |
| 2 | `legitimate/Legitimate/*.json` | ~1,300,000 | openappsec: real browser traffic từ 185 websites |
| 3 | `SRBH2020/dataset_capec_combine.csv` | 594,458 | SRBH2020: Injection, Normal, Fake Source, Manipulation... |
| 4 | `SRBH2020/dataset_capec_transfer.csv` | 12,854 | **Test set** — không dùng cho training |
| 5 | `csic2010/*.txt` | 97,065 | CSIC 2010: raw HTTP requests (2010, hơi cũ) |
| 6 | `modern_payloads/ai_waf_dataset.parquet` | 11,949 | HuggingFace: modern REST API attacks với JSON body |
| 7 | `modern_payloads/*.txt / *.fuzz` | ~6,061 | PayloadsAllTheThings: SSTI, NoSQL, polyglots |

> **Chi tiết đầy đủ:** xem [WAF_DATASET_REPORT.md](WAF_DATASET_REPORT.md)

### 4.3 Tải dataset bổ sung (nếu chưa có)

**CSIC 2010** (nếu chưa có thư mục `csic2010/`):

```powershell
New-Item -ItemType Directory -Path csic2010 -Force

$base = "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010"
Invoke-WebRequest "$base/normalTrafficTraining.txt" -OutFile csic2010/normalTrafficTraining.txt
Invoke-WebRequest "$base/normalTrafficTest.txt"     -OutFile csic2010/normalTrafficTest.txt
Invoke-WebRequest "$base/anomalousTrafficTest.txt"  -OutFile csic2010/anomalousTrafficTest.txt
```

**HuggingFace ai-waf-dataset** (nếu chưa có `modern_payloads/ai_waf_dataset.parquet`):

```powershell
New-Item -ItemType Directory -Path modern_payloads -Force

Invoke-WebRequest `
  "https://huggingface.co/datasets/notesbymuneeb/ai-waf-dataset/resolve/main/data/train-00000-of-00001.parquet" `
  -OutFile modern_payloads/ai_waf_dataset.parquet
```

**PayloadsAllTheThings** (nếu chưa có các file `.txt`, `.fuzz`):

```powershell
$patt = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"
$sec  = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
$dest = "modern_payloads"

$files = @{
    "ssti.fuzz"          = "$patt/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz"
    "ssti_engines.txt"   = "$sec/Fuzzing/template-engines-expression.txt"
    "nosql_mongodb.txt"  = "$patt/NoSQL%20Injection/Intruder/MongoDB.txt"
    "nosql_generic.txt"  = "$patt/NoSQL%20Injection/Intruder/NoSQL.txt"
    "sqli_polyglots.txt" = "$patt/SQL%20Injection/Intruder/SQLi_Polyglots.txt"
    "sqli_generic.txt"   = "$patt/SQL%20Injection/Intruder/Generic_Fuzz.txt"
    "xss_polyglots.txt"  = "$patt/XSS%20Injection/Intruders/XSS_Polyglots.txt"
    "xss_jhaddix.txt"    = "$patt/XSS%20Injection/Intruders/JHADDIX_XSS.txt"
    "cmd_unix.txt"       = "$patt/Command%20Injection/Intruder/command-execution-unix.txt"
    "lfi_jhaddix.txt"    = "$sec/Fuzzing/LFI/LFI-Jhaddix.txt"
}
foreach ($fname in $files.Keys) {
    Invoke-WebRequest $files[$fname] -OutFile "$dest\$fname" -UseBasicParsing
    Write-Host "Downloaded: $fname"
}
```

### 4.4 Build unified dataset

Sau khi có đủ data, chạy:

```bash
conda activate waf
python build_dataset.py
```

Các tùy chọn:

```bash
python build_dataset.py               # mặc định: cap 50,000 samples/class
python build_dataset.py --cap 30000   # giảm cap để train nhanh hơn
python build_dataset.py --no-cap      # không giới hạn (cảnh báo: imbalanced)
```

Output: `dataset_unified.csv` (~47 MB với cap mặc định).

---

## 5. Training model

```bash
conda activate waf
python train.py
```

Script sẽ thực hiện theo thứ tự:

1. Load `dataset_unified.csv`
2. Extract 26 features cho từng request
3. Split 70% train / 10% validation / 20% test (stratified)
4. Train LightGBM với early stopping
5. Đánh giá accuracy trên test set — **multi-class** và **binary (Normal vs Attack)**
6. Export sang `waf_model.onnx`
7. Chạy Python inference benchmark

Các file được tạo ra:

| File | Mô tả |
|------|-------|
| `waf_model.txt` | LightGBM native model (~70 MB) |
| `waf_model.onnx` | ONNX model dùng cho Rust inference (~50 MB) |
| `label_map.json` | Mapping từ class index → tên class |

> **Nếu chỉ muốn re-export ONNX** mà không retrain:
> ```bash
> python train.py --export-only
> ```

**Thời gian ước tính:**
- Feature extraction: ~2–5 phút (tùy số lượng sample)
- Training: ~5–15 phút (tùy `num_boost_round` và early stopping)

---

## 6. Rust inference & benchmark

### 6.1 Chuẩn bị

Đảm bảo Cargo đã có trong PATH (xem [mục 3.2](#32-rust--cài-đặt-rustup)):

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
```

Đảm bảo đã có `waf_model.onnx` và `label_map.json` ở thư mục gốc (sau bước train).

### 6.2 Chạy

```powershell
cd waf_infer
cargo run --release
```

Lần đầu build sẽ mất **5–15 phút** do:
- Download ORT (ONNX Runtime) binary tự động (~100 MB)
- Compile Rust source

Các lần sau build rất nhanh (~vài giây) nếu không có thay đổi code.

### 6.3 Output

```
Loading ONNX model: ../waf_model.onnx
Labels: [(0, "16 - Dictionary-based Password Attack"), (1, "Fake the Source of Data"), ...]
Loaded 12854 samples from ../SRBH2020/dataset_capec_transfer.csv

Running evaluation on test set (12854 samples)...
  Accuracy : 0.8579 (11028/12854)

================================================================================
Rust inference benchmark  (latency = per-request, amortised)
================================================================================
   batch       req/s       mean        p50        p95        p99        max
  ─────────────────────────────────────────────────────────────────────────
       1        4600    0.217ms    0.200ms    0.294ms    0.505ms    2.340ms
     100        9377    0.107ms    0.097ms    0.132ms    0.250ms    0.275ms
    1000       11750    0.085ms    0.084ms    0.102ms    0.116ms    0.128ms
   10000       13860    0.072ms    0.070ms    0.085ms    0.088ms    0.088ms
```

### 6.4 Sử dụng inference trong code Rust

Xem `waf_infer/src/main.rs` để biết cách:
- Load ONNX session: `Session::builder().commit_from_file("waf_model.onnx")`
- Build feature matrix từ request strings: `build_feature_matrix(&requests)`
- Predict: `predict(&mut session, &requests)` → `Vec<i64>` (class indices)
- Map index → tên class: `label_map.get(&pred_id)`

---

## 7. Cấu trúc project

```
ml_waf/
│
├── 📄 README.md                    ← File này
├── 📄 WAF_DATASET_REPORT.md        ← Phân tích chi tiết các nguồn data
│
│── 🐍 build_dataset.py             ← Merge tất cả data sources → dataset_unified.csv
├── 🐍 train.py                     ← Training + evaluation + ONNX export
├── 🐍 features.py                  ← Feature extraction (26 features)
├── 📄 requirements.txt             ← Python dependencies
│
├── 📄 dataset_unified.csv          ← [generated] Merged training data
├── 📄 waf_model.txt                ← [generated] LightGBM native model
├── 📄 waf_model.onnx               ← [generated] ONNX model cho Rust
├── 📄 label_map.json               ← [generated] Class index → tên
├── 📄 fail_cases.csv               ← [generated] Samples bị predict sai (debug)
│
├── 📁 malicious/Malicious/         ← Data nguồn 1: openappsec attack payloads
│   ├── sqli.json        (916)
│   ├── cmdexe.json      (2,468)
│   ├── shellshock.json  (48)
│   ├── traversal.json   (28,314)
│   ├── xss.json         (41,888)
│   ├── xxe.json         (70)
│   └── log4shell.json   (220)
│
├── 📁 legitimate/Legitimate/       ← Data nguồn 2: real browser sessions (~7 GB)
│   └── browsing_2024_*.json       (692 files, ~1.3M requests)
│
├── 📁 SRBH2020/                    ← Data nguồn 3 & 4: SRBH2020 academic
│   ├── dataset_capec_combine.csv  (594,458 samples) ← Training
│   └── dataset_capec_transfer.csv (12,854 samples)  ← Test set chuẩn
│
├── 📁 csic2010/                    ← Data nguồn 5: CSIC 2010
│   ├── normalTrafficTraining.txt  (36,000 Normal)
│   ├── normalTrafficTest.txt      (36,000 Normal)
│   └── anomalousTrafficTest.txt   (25,065 Attack)
│
├── 📁 modern_payloads/             ← Data nguồn 6 & 7: modern attacks
│   ├── ai_waf_dataset.parquet     (11,949 samples — HuggingFace 2024)
│   ├── ssti.fuzz                  (105 SSTI payloads)
│   ├── nosql_mongodb.txt          (20 NoSQL payloads)
│   ├── lfi_jhaddix.txt            (930 LFI/traversal payloads)
│   └── ...                        (các file payload khác)
│
└── 📁 waf_infer/                   ← Rust inference engine
    ├── Cargo.toml
    └── src/
        ├── main.rs                 ← Entry point, benchmark, evaluation
        └── features.rs             ← Feature extraction (port từ features.py)
```

---

## 8. Classes & nhãn

Model phân loại HTTP request vào **11 classes**:

| Index | Class | Mô tả |
|------:|-------|-------|
| 0 | `16 - Dictionary-based Password Attack` | Brute-force mật khẩu theo wordlist |
| 1 | `Fake the Source of Data` | SSRF, header spoofing, IP giả mạo |
| 2 | `HTTP abusion` | Dùng HTTP sai mục đích: method lạ, malformed request, scanner |
| 3 | `Injection` | SQLi, command injection, NoSQL injection, Shellshock |
| 4 | `Log4Shell` | CVE-2021-44228: `${jndi:ldap://...}` trong headers/params |
| 5 | `Manipulation` | Path traversal (`../`), LFI, file disclosure |
| 6 | `Normal` | HTTP request hợp lệ |
| 7 | `SSTI` | Server-Side Template Injection: `{{7*7}}`, `${7*7}` |
| 8 | `Scanning for Vulnerable Software` | Nikto, sqlmap, nmap user-agent signatures |
| 9 | `XSS` | Cross-Site Scripting: `<script>`, `onerror=`, `javascript:` |
| 10 | `XXE` | XML External Entity: `<!ENTITY`, `SYSTEM "file://..."` |

**Label map** lưu tại `label_map.json`:

```json
{
  "0": "16 - Dictionary-based Password Attack",
  "1": "Fake the Source of Data",
  "2": "HTTP abusion",
  "3": "Injection",
  "4": "Log4Shell",
  "5": "Manipulation",
  "6": "Normal",
  "7": "SSTI",
  "8": "Scanning for Vulnerable Software",
  "9": "XSS",
  "10": "XXE"
}
```

---

## 9. Feature extraction

Model dùng **26 engineered features** được extract từ chuỗi text `"METHOD /path?query [body]"`. Logic trích xuất giống nhau ở cả Python (`features.py`) và Rust (`waf_infer/src/features.rs`).

| # | Feature | Mô tả |
|--:|---------|-------|
| 0 | `request_len` | Tổng độ dài request |
| 1 | `method_id` | GET=0, POST=1, PUT=2, DELETE=3, PATCH=4, HEAD=5, OPTIONS=6, other=7 |
| 2 | `path_len` | Độ dài URL path |
| 3 | `query_len` | Độ dài query string |
| 4 | `body_len` | Độ dài body |
| 5 | `num_params` | Số lượng key=value params (query + body) |
| 6 | `entropy` | Shannon entropy của url+body — cao nếu có encoding |
| 7 | `digit_ratio` | Tỷ lệ ký tự số |
| 8 | `upper_ratio` | Tỷ lệ chữ hoa |
| 9 | `special_char_count` | Đếm `' " < > ; = % & +` |
| 10 | `single_quote_count` | Đếm `'` — indicator SQLi |
| 11 | `double_quote_count` | Đếm `"` |
| 12 | `angle_bracket_count` | Đếm `<` + `>` — indicator XSS |
| 13 | `semicolon_count` | Đếm `;` — indicator command injection |
| 14 | `pct_encoded_count` | Số lượng `%XX` sequences |
| 15 | `sql_keyword_count` | Đếm SQL keywords (SELECT, UNION, DROP...) sau decode |
| 16 | `xss_pattern_count` | Đếm XSS patterns (`<script`, `onerror=`...) |
| 17 | `path_traversal_count` | Đếm `../` sau decode |
| 18 | `cmd_injection_count` | Đếm `;`, `|`, `&&`, `$(...)`... |
| 19 | `scanner_count` | Đếm scanner signatures (nikto, sqlmap, nmap...) |
| 20 | `ssrf_count` | Đếm SSRF patterns (`127.0.0.1`, `file://`, `169.254.`...) |
| 21 | `php_pattern_count` | Đếm PHP patterns (`eval(`, `.php`, `$_GET`...) |
| 22 | `null_byte_count` | Đếm `%00`, `\x00`, ` ` |
| 23 | `hex_encode_count` | Đếm `0x[hex]{4+}` |
| 24 | `crlf_inject_count` | Đếm `%0a`, `%0d`, `\r\n` |
| 25 | `double_encode_count` | Đếm `%25XX` (double URL encoding) |

> **Lưu ý:** Features 15–21 được tính trên chuỗi đã **URL-decode** để bắt các payload bị encode.

---

## 10. Thêm dữ liệu mới

### 10.1 Thêm file JSON (cùng format openappsec)

Tạo file JSON với format:

```json
[
  {
    "method": "POST",
    "url": "/api/v1/login",
    "headers": {},
    "data": "{\"username\": \"admin' OR '1'='1\", \"password\": \"x\"}"
  }
]
```

Đặt vào `malicious/Malicious/ten_loai_tan_cong.json`, sau đó thêm mapping vào `build_dataset.py`:

```python
MALICIOUS_CATEGORY = {
    ...
    "ten_loai_tan_cong": "TenClass",  # thêm dòng này
}
```

### 10.2 Thêm payload file (raw strings)

Thêm file `.txt` vào `modern_payloads/`, rồi thêm vào `payload_files` trong `load_modern_payloads()` của `build_dataset.py`:

```python
("ten_file.txt", "TenClass", _REST_TEMPLATES[:6]),
```

### 10.3 Thêm class mới

Nếu thêm class mới (ví dụ: `"NoSQLi"`):

1. Thêm samples với label mới vào data
2. Chạy lại `python build_dataset.py`
3. Chạy lại `python train.py` — `label_map.json` sẽ được cập nhật tự động
4. Rebuild Rust: `cargo build --release` (trong `waf_infer/`)

> **Không cần sửa Rust code** khi thêm class mới — model và label map được load động.

### 10.4 Rebuild pipeline hoàn chỉnh

```bash
# 1. Rebuild dataset
python build_dataset.py

# 2. Retrain + export ONNX
python train.py

# 3. Rebuild và chạy Rust benchmark
cd waf_infer
cargo run --release
```

---

## 11. Troubleshooting

### `cargo` không nhận dạng được

```
cargo : The term 'cargo' is not recognized...
```

**Nguyên nhân:** Rust đã cài nhưng `~/.cargo/bin` chưa có trong PATH của session hiện tại.

**Fix ngay** (session hiện tại):

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
```

**Fix vĩnh viễn** (tất cả terminal mới):

```powershell
[Environment]::SetEnvironmentVariable(
    "PATH",
    "$env:USERPROFILE\.cargo\bin;" + [Environment]::GetEnvironmentVariable("PATH", "User"),
    "User"
)
```

Sau đó mở terminal mới, `cargo --version` sẽ hoạt động.

---

### `python` không nhận dạng được

```powershell
# Activate conda env trước
conda activate waf

# Hoặc dùng đường dẫn đầy đủ
& "$env:USERPROFILE\miniconda3\envs\waf\python.exe" train.py
```

---

### Build Rust lỗi: `failed to load ONNX model`

```
failed to load ONNX model — run train.py first
```

**Nguyên nhân:** Chưa có file `waf_model.onnx` ở thư mục gốc.

**Fix:**

```bash
conda activate waf
python train.py        # hoặc python train.py --export-only nếu đã có waf_model.txt
```

---

### Rust build lần đầu rất chậm

Bình thường. ORT (ONNX Runtime) tự động download ~100 MB binary trong lần build đầu. Cần kết nối internet. Sau đó được cache, các lần sau nhanh hơn nhiều.

---

### Lỗi import `pyarrow` khi chạy `build_dataset.py`

```
ImportError: Unable to find a usable engine; tried using: 'pyarrow', 'fastparquet'
```

**Fix:**

```bash
pip install pyarrow
```

---

### Model accuracy thấp trên SRBH2020 transfer (~85%)

**Đây là bình thường.** `dataset_capec_transfer.csv` được dùng làm benchmark độc lập với label theo CAPEC taxonomy (network behavior), trong khi model được train trên payload-based features. Accuracy thực tế trên unified test set là ~94%.

---

## 12. Kết quả benchmark

### Accuracy (unified test set, 20% held-out)

| Class | Precision | Recall | F1 |
|-------|----------:|-------:|---:|
| XXE | 1.000 | 1.000 | 1.000 |
| XSS | 1.000 | 0.997 | 0.998 |
| Log4Shell | 0.957 | 1.000 | 0.978 |
| HTTP abusion | 0.952 | 0.989 | 0.970 |
| Injection | 0.972 | 0.956 | 0.964 |
| Fake the Source of Data | 0.959 | 0.922 | 0.940 |
| Manipulation | 0.927 | 0.924 | 0.926 |
| Normal | 0.862 | 0.886 | 0.873 |
| Scanning | 0.843 | 0.798 | 0.820 |
| **Overall accuracy** | | | **0.943** |

### Inference latency — Python vs Rust

| Batch | Python req/s | Python p99 | Rust req/s | Rust p99 | Rust nhanh hơn |
|------:|------------:|-----------:|-----------:|---------:|:--------------:|
| 1 | 732 | 3.9ms | 4,600 | 0.5ms | **6.3×** |
| 100 | 6,332 | 0.3ms | 9,377 | 0.3ms | 1.5× |
| 1,000 | 7,227 | 0.2ms | 11,750 | 0.1ms | 1.6× |
| 10,000 | 7,424 | 0.2ms | 13,860 | 0.1ms | 1.9× |

> Với WAF production (batch=1, classify từng request): **Rust nhanh hơn 6.3× so với Python**.

---

*Được phát triển với LightGBM + ONNX Runtime + Rust. Dataset tổng hợp từ openappsec, SRBH2020, CSIC 2010, HuggingFace, và PayloadsAllTheThings.*
