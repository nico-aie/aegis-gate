# Aegis-Gate WAF — Legitimate Traffic FP Report

**Ngày chạy:** 2026-07-07 13:44:02  
**Endpoint:** `https://18.140.47.62`  
**Dataset:** `/Users/admin/Documents/workspace/remote/dataset/Legitimate`  
**Script:** `eval_waf_legitimate_dataset.py`

---

## Tổng quan

| Chỉ số | Giá trị |
|--------|---------|
| Files dataset | 692 |
| Files loaded | 692 |
| Files lỗi parse | 0 |
| Tổng records gửi | 1,040,242 |
| Network errors | 308 (0.0%) |
| Effective records | 1,039,934 |
| Thời gian chạy | 8.1 phút |
| Throughput | 2,143 rq/s |

### WAF Overhead Latency (`x-waf-overhead-latency`)

> Header đo từ lúc request vào WAF đến lúc trả response.
> **Blocked** = WAF processing only (không proxy upstream) → số liệu chính xác nhất cho WAF overhead.
> **Passed** = WAF + upstream proxy time → bị ảnh hưởng bởi backend latency.

Coverage: 1,039,933 / 1,039,934 requests (100.0%)

**🔒 Blocked requests (5,392) — WAF-only cost**

| Metric | Value |
|--------|------:|
| Count | 5,392 |
| Mean | 230.619 ms |
| P50 | 9.734 ms |
| P90 | 534.827 ms |
| P95 | 1404.846 ms |
| P99 | 3843.279 ms |
| P99.9 | 5979.021 ms |
| Max | 7386.235 ms |

**✅ Passed requests (1,034,542) — WAF + upstream**

| Metric | Value |
|--------|------:|
| Count | 1,034,541 |
| Mean | 55.261 ms |
| P50 | 7.914 ms |
| P90 | 155.2 ms |
| P95 | 286.673 ms |
| P99 | 616.491 ms |
| P99.9 | 1786.82 ms |
| Max | 8412.078 ms |

**📊 All combined**

| Metric | Value |
|--------|------:|
| Count | 1,039,933 |
| Mean | 56.171 ms |
| P50 | 7.92 ms |
| P90 | 156.054 ms |
| P95 | 288.331 ms |
| P99 | 625.937 ms |
| P99.9 | 1968.977 ms |
| Max | 8412.078 ms |

> **SLA (WAF-only, blocked requests):** ❌ High — WAF P99 ≥ 10ms, investigate bottleneck

### WAF action distribution

> % trên 1,039,934 effective (request có response). 308 network errors không có action, xem mục Tổng quan.

| Action | Count | % |
|--------|------:|--:|
| `allow` | 1,034,536 | 99.5% |
| `block` | 5,392 | 0.5% |
| `circuit_breaker` | 5 | 0.0% |
| `no_header` | 1 | 0.0% |
| **Tổng** | **1,039,934** | **100.0%** |

---

## False Positive Rate (detector eval)

> Traffic hợp lệ — lý tưởng detector KHÔNG bắt.
> **FP = request bị detector bắt = `x-waf-rule-id` ≠ `none`** (có rule fire). Không dùng risk-score để xác định FP.

| Metric | Giá trị |
|--------|---------|
| **FP — Detector bắt nhầm (rule-id ≠ none)** | **0.56% ✅** |
| Số request bị bắt | 5,858 / 1,039,934 |

### Rule fire theo `x-waf-rule-id`

| rule_id (header) | Fires | % of effective |
|------------------|------:|---------------:|
| `mass-assignment` | 1,318 | 0.13% ✅ |
| `sqli` | 1,182 | 0.11% ✅ |
| `command-injection` | 1,100 | 0.11% ✅ |
| `xss` | 497 | 0.05% ✅ |
| `template-injection` | 409 | 0.04% ✅ |
| `ai` | 284 | 0.03% ✅ |
| `ssrf` | 281 | 0.03% ✅ |
| `jwt-alg-none` | 208 | 0.02% ✅ |
| `jwt-time-forged` | 152 | 0.01% ✅ |
| `path-traversal` | 109 | 0.01% ✅ |
| `recon-path` | 103 | 0.01% ✅ |
| `header-injection` | 66 | 0.01% ✅ |
| `css-injection` | 40 | 0.00% ✅ |
| `open-redirect` | 35 | 0.00% ✅ |
| `method-override-bypass` | 25 | 0.00% ✅ |
| `nosql-injection` | 20 | 0.00% ✅ |
| `body-deep-nesting` | 15 | 0.00% ✅ |
| `body-too-large` | 9 | 0.00% ✅ |
| `upstream-error` | 5 | 0.00% ✅ |

---

## Rule fire theo HTTP method

| Method | Total | Fired (rule-id ≠ none) | Fire % |
|--------|------:|-----------------------:|-------:|
| `DELETE` | 457 | 0 | 0.00% |
| `GET` | 741,100 | 1,376 | 0.19% |
| `HEAD` | 1,311 | 0 | 0.00% |
| `PATCH` | 56 | 0 | 0.00% |
| `POST` | 295,129 | 4,219 | 1.43% |
| `PUT` | 1,881 | 263 | 13.98% |

---

## Top sites có rule fire (top 20)

| Site | Total | Fired | Fire % | Rule (header) |
|------|------:|------:|-------:|---------------|
| onedrive_al | 1,924 | 262 | 13.6% | `template-injection`×177, `sqli`×84, `command-injection`×1 |
| target | 1,829 | 224 | 12.2% | `jwt-alg-none`×208, `xss`×14, `sqli`×2 |
| browsing_office_powerpoint_and_clipchamp | 2,979 | 205 | 6.9% | `mass-assignment`×196, `path-traversal`×3, `command-injection`×3, `ai`×2, `sqli`×1 |
| ulta | 1,806 | 161 | 8.9% | `jwt-time-forged`×152, `sqli`×7, `template-injection`×2 |
| browsing_semrush | 1,227 | 158 | 12.9% | `mass-assignment`×156, `sqli`×1, `command-injection`×1 |
| virginatlantic_ni | 1,852 | 149 | 8.0% | `sqli`×85, `xss`×62, `command-injection`×2 |
| nike | 1,677 | 142 | 8.5% | `command-injection`×74, `mass-assignment`×52, `sqli`×9, `template-injection`×7 |
| sephora_hl | 2,151 | 127 | 5.9% | `mass-assignment`×117, `xss`×9, `sqli`×1 |
| wetransfer_mu | 1,272 | 107 | 8.4% | `mass-assignment`×107 |
| lowe_s | 2,412 | 106 | 4.4% | `sqli`×51, `command-injection`×49, `template-injection`×6 |
| roughtrade_mu | 1,600 | 98 | 6.1% | `mass-assignment`×98 |
| kohl_s | 4,226 | 93 | 2.2% | `command-injection`×68, `template-injection`×15, `sqli`×9, `open-redirect`×1 |
| pureformulas_mu | 3,777 | 92 | 2.4% | `recon-path`×91, `nosql-injection`×1 |
| canva | 1,397 | 91 | 6.5% | `sqli`×90, `mass-assignment`×1 |
| browsing_instagram | 716 | 90 | 12.6% | `mass-assignment`×64, `sqli`×26 |
| skyscanner | 1,776 | 84 | 4.7% | `command-injection`×48, `sqli`×25, `xss`×6, `template-injection`×4, `mass-assignment`×1 |
| browsing_nike | 1,609 | 80 | 5.0% | `command-injection`×57, `sqli`×15, `template-injection`×7, `mass-assignment`×1 |
| alibaba_hl | 4,552 | 78 | 1.7% | `xss`×73, `mass-assignment`×5 |
| delta | 1,282 | 74 | 5.8% | `sqli`×27, `command-injection`×15, `xss`×13, `css-injection`×12, `template-injection`×4, `ai`×3 |
| crocs | 3,087 | 69 | 2.2% | `ssrf`×58, `sqli`×5, `mass-assignment`×4, `command-injection`×2 |

---

## Top paths có rule fire (top 20)

| Named fires | Path |
|-----------:|------|
| 216 | `/collect` |
| 214 | `/` |
| 193 | `/dlhome/shared/components/TealeafTarget.jsp` |
| 153 | `/dpa/rpc` |
| 130 | `/pods/podedit.svc/jsonAnonymous/GetUpdates` |
| 128 | `/rup/b933a76e0e591dbb/eyJSZXNvdXJjZUlEIjoiQjkzM0E3NkUwRTU5MURCQiExODUiLCJSZWxhdG` |
| 128 | `/rup/b933a76e0e591dbb/eyJSZXNvdXJjZUlEIjoiQjkzM0E3NkUwRTU5MURCQiE0MzkiLCJSZWxhdG` |
| 124 | `/2/httpapi` |
| 121 | `/_ajax/ae/createBatch` |
| 98 | `/graphql/` |
| 93 | `/v2/public/yql` |
| 91 | `/content/published/api/v1.1/swagger.json` |
| 87 | `/api/v3/data/` |
| 84 | `/0JXkApkPmZ3MW/6M/6pVXyl1uI4wQ/DYh7fr0t7Daw/BwtUPgE/Lg/YlbiMvFXE` |
| 81 | `/ajax/bnzai` |
| 78 | `/v2/recording` |
| 73 | `/h5/mtop.alibaba.icbu.im.login.token.get/1.0/` |
| 68 | `/v1/sot/evt` |
| 61 | `/api/graphql` |
| 60 | `/VBtAK7G-qmgq/7p/z_3gut9M7K/7G3QbtYY3OOp/KSsCAQ/Tm0pEx/IMbWw` |

---

## Phân tích & Kết luận

**FP tổng (rule-id ≠ none): 0.56%** (5,858/1,039,934). Rule fire theo header:

### ✅ Mọi rule đều < 2% legit

Cao nhất: `mass-assignment` 0.13%, `sqli` 0.11%, `command-injection` 0.11%, `xss` 0.05%, `template-injection` 0.04%.

---

## Files output

| File | Mô tả |
|------|-------|
| `20260707_133556_legitimate_results.csv` | Per-record results với tất cả WAF header fields |
| `20260707_133556_legitimate_summary.json` | Stats tổng hợp |
| `20260707_133556_legitimate_report.md` | File này |
| `20260707_133556_network_errors.txt` | Request lỗi mạng (input + exception) — soi nguyên nhân |
| `20260707_133556_fp_logs/ai.txt` | Các request có rule `ai` (theo header) |
| `20260707_133556_fp_logs/body-deep-nesting.txt` | Các request có rule `body-deep-nesting` (theo header) |
| `20260707_133556_fp_logs/body-too-large.txt` | Các request có rule `body-too-large` (theo header) |
| `20260707_133556_fp_logs/command-injection.txt` | Các request có rule `command-injection` (theo header) |
| `20260707_133556_fp_logs/css-injection.txt` | Các request có rule `css-injection` (theo header) |
| `20260707_133556_fp_logs/header-injection.txt` | Các request có rule `header-injection` (theo header) |
| `20260707_133556_fp_logs/jwt-alg-none.txt` | Các request có rule `jwt-alg-none` (theo header) |
| `20260707_133556_fp_logs/jwt-time-forged.txt` | Các request có rule `jwt-time-forged` (theo header) |
| `20260707_133556_fp_logs/mass-assignment.txt` | Các request có rule `mass-assignment` (theo header) |
| `20260707_133556_fp_logs/method-override-bypass.txt` | Các request có rule `method-override-bypass` (theo header) |
| `20260707_133556_fp_logs/nosql-injection.txt` | Các request có rule `nosql-injection` (theo header) |
| `20260707_133556_fp_logs/open-redirect.txt` | Các request có rule `open-redirect` (theo header) |
| `20260707_133556_fp_logs/path-traversal.txt` | Các request có rule `path-traversal` (theo header) |
| `20260707_133556_fp_logs/recon-path.txt` | Các request có rule `recon-path` (theo header) |
| `20260707_133556_fp_logs/sqli.txt` | Các request có rule `sqli` (theo header) |
| `20260707_133556_fp_logs/ssrf.txt` | Các request có rule `ssrf` (theo header) |
| `20260707_133556_fp_logs/template-injection.txt` | Các request có rule `template-injection` (theo header) |
| `20260707_133556_fp_logs/upstream-error.txt` | Các request có rule `upstream-error` (theo header) |
| `20260707_133556_fp_logs/xss.txt` | Các request có rule `xss` (theo header) |

---

*Generated by `eval_waf_legitimate_dataset.py`*