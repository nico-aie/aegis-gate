> 🇻🇳 Bản dịch tiếng Việt của [IMPROVE-detection-fp-tuning-2026-07.md](../round-2-improvement/IMPROVE-detection-fp-tuning-2026-07.md) — bản gốc tiếng Anh là source of truth.

# IMPROVE — Độ chính xác phát hiện: tinh chỉnh FP & tốt nghiệp lên default-ON

> **Type:** IMPROVE (committee round-2 🟡1) · **Status:** ☐ Chưa bắt đầu — lập kế hoạch 2026-07-04
> **Track ID prefix:** `FP-<1–3>` · Chính thức hóa đầu việc lỏng lẻo chưa được theo dõi trước đây
> từ track attack-coverage: `enumeration` + `behavior_analyzer` đã ship ở trạng thái **default-OFF
> chờ tinh chỉnh FP** (FEAT-attack-coverage-wiring, đã lưu trữ 2026-07-04).

**Mục tiêu (tinh thần, không phải câu chữ):** nâng cao precision (độ chính xác) thực tế trên nền
tảng phát hiện hiện có — ít false positive (cảnh báo sai) hơn trên lưu lượng lành tính, không thoái
lui trên true positive — và cho hai detector đang ngủ đông tốt nghiệp lên default-ON bằng bằng chứng
đo lường được, không phải theo cảm tính.

---

## 1. Hiện trạng

- Nền tảng phát hiện đã trưởng thành: quét body có gate theo content-type và gating exec-sink cho XSS
  đã ship như các đợt giảm FP (`[[feedback_test_suite_green_baseline]]` — các test phát hiện cũ
  trở nên lỗi thời sau các commit giảm FP là một khuôn mẫu đã biết và *có chủ đích*).
- `enumeration` (gate theo 404, off-chain) và `behavior_analyzer` đã được đấu nối nhưng
  **default-OFF** chờ bằng chứng về FP.
- Hai cái bẫy đo lường cần tôn trọng:
  - `[[project_ltester_decodes_dataplane_raw]]` — harness l-tester decode URI hai lần; data plane
    thật đưa cho các detector các dạng **percent-encoded thô**. Xác thực bằng unit test Rust trên
    các dạng thô, không bao giờ chỉ dựa vào báo cáo recon bằng Python.
  - `[[project_hyper_normalizes_framing]]` — các rule ở tầng framing không thể được kích hoạt qua
    các client có chuẩn hóa.

## 2. Phân giai đoạn

### FP-1 — harness đo lường + corpus lành tính · **M** · BẮT ĐẦU TỪ ĐÂY
- Xây dựng một **corpus lưu lượng lành tính** có phiên bản (check vào `tests/` hoặc fixture được
  tải về): các phiên trình duyệt thực tế, API client, đường dẫn static-asset, truy vấn tìm kiếm
  chứa payload lành tính kiểu SQL/HTML, các tham số redirect percent-encoded (lớp artifact l-tester
  đã biết), body của webhook (JSON/XML), file upload.
- Corpus tấn công: tái sử dụng các vector của l-tester, phát lại ở dạng **thô** qua đường Rust
  (dựng `EvalContext` ở mức unit, không phải harness Python).
- Sản phẩm bàn giao: báo cáo precision/recall (độ chính xác/độ phủ) chạy được bằng `cargo test`
  cho từng detector (tỷ lệ FP trên corpus lành tính, tỷ lệ TP trên corpus tấn công), kèm một
  snapshot baseline được commit để có thể diff được độ trôi dạt.

### FP-2 — tinh chỉnh các detector ồn ào nhất · **M**
- Xếp hạng các detector theo mức đóng góp FP trên corpus; tinh chỉnh những kẻ vi phạm hàng đầu
  (ngưỡng, gating, yêu cầu về ngữ cảnh) mỗi detector một PR, mỗi PR trình bày số liệu corpus
  trước/sau.
- Các ứng viên đã biết từ lịch sử: các encoding của tham số redirect, các rule từ khóa chung chung
  trên query string lành tính. **Không** thử lại việc hợp nhất RegexSet
  (`[[project_regexset_slower_than_vec]]`).
- Ràng buộc bảo vệ: mọi PR tinh chỉnh giữ tỷ lệ TP trên corpus tấn công không đổi hoặc tốt hơn;
  tôn trọng ngân sách hiệu năng (bench trước/sau trên release profile).

### FP-3 — cho `enumeration` + `behavior_analyzer` tốt nghiệp lên default-ON · **S–M**
- Tiêu chí đầu vào: tỷ lệ FP trên corpus dưới một ngân sách đã thống nhất (owner quyết định;
  đề xuất <0.1% request lành tính bị chấm điểm, 0 block ở các ngưỡng mặc định) + một đợt soak
  ở chế độ log-only trên stack dev/bench.
- Lật các giá trị mặc định + ghi release-note cho thay đổi; giữ kill switch cho từng detector.

## 3. Kiểm thử / bằng chứng

- Bản thân báo cáo FP-1 chính là artifact kiểm thử; các baseline đã commit làm cho các thoái lui
  chuyển RED.
- Các unit test của detector được cập nhật song song với việc tinh chỉnh (khuôn mẫu test-lỗi-thời
  là điều được kỳ vọng — xác nhận đó là giảm FP có chủ đích trước khi "sửa" một detector để làm
  hài lòng một test cũ).
- Bằng chứng soak log-only được đính kèm trước khi lật mặc định ở FP-3.

## 4. Rủi ro

| Sev | Rủi ro | Giảm thiểu |
|---|---|---|
| MEDIUM | Việc tinh chỉnh âm thầm làm rơi các TP thật | gate corpus tấn công trong mọi PR; soak log-only trước khi lật mặc định |
| MEDIUM | Corpus không mang tính đại diện → tự tin sai lầm | gieo mầm từ lưu lượng bench thực + các báo cáo FP đã biết; đánh phiên bản và nuôi lớn nó |
| LOW | Thoái lui hiệu năng do gating bổ sung | bench trên release profile cho từng PR (profile LT-P1) |

## 5. Tiêu chí nghiệm thu

- [ ] Harness precision/recall tái lập được trong `cargo test`, baseline đã commit.
- [ ] Top-N detector ồn ào được tinh chỉnh kèm số liệu trước/sau.
- [ ] `enumeration` + `behavior_analyzer` default-ON (hoặc một quyết định không làm, có bằng chứng hậu thuẫn).
- [ ] Bản tóm tắt hướng tới committee: mức giảm FP đo lường được, nền tảng không thay đổi.
