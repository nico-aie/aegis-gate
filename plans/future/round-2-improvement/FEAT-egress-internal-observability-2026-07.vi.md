> 🇻🇳 Bản dịch tiếng Việt của [FEAT-egress-internal-observability-2026-07.md](FEAT-egress-internal-observability-2026-07.md) — bản gốc tiếng Anh là source of truth.

# FEAT — Khả năng quan sát egress (lưu lượng đi ra) & lưu lượng nội bộ (thiết kế trước)

> **Loại:** FEAT (committee round-2 🟡4) · **Trạng thái:** ☐ Chưa bắt đầu — lên kế hoạch 2026-07-04, **thiết kế trước (design-first)**
> **Tiền tố Track ID:** `EG-<1–3>` · Hạng mục round-2 lớn nhất và ít được định nghĩa rõ nhất — làm cuối cùng; EG-1 là
> một tài liệu thiết kế, không phải code.

**Mục tiêu (theo tinh thần, không theo câu chữ):** phát hiện hoạt động đáng ngờ *rời khỏi* môi trường, chứ không chỉ
các cuộc tấn công đi vào — và làm cho lưu lượng giữa các thành phần hệ thống trở nên quan sát được.

---

## 1. Phạm vi trung thực (những gì một reverse proxy có thể và không thể thấy)

Aegis nằm inline trên **lưu lượng inbound ở edge + các response của nó**. Nó *không* thấy:
- các kết nối outbound do origin khởi tạo (exfil — rò rỉ dữ liệu — qua socket trực tiếp, DNS tunneling từ origin);
- lưu lượng giữa các backend service không đi qua WAF.

Tuyên bố có "egress inspection" (kiểm tra lưu lượng đi ra) vượt ra ngoài đường response sẽ chính là cái bẫy
câu-chữ-thay-vì-tinh-thần (round-2 🟡6). Cách phân rã trung thực:

| Tầng | Khả năng quan sát hiện tại | Cơ hội |
|---|---|---|
| **Đường response** (origin → client đi qua WAF) | Kênh response-outcome đã ship (track AC); bộ lọc response bằng AI đã tồn tại (`response_filter_put`, `admin_mutate.rs:5726`); response-header strip | **EG-2: kiểm tra response/exfil** — thắng lợi thực sự, nằm trong đường đi |
| **Các luồng nội bộ của chính WAF** (fleet channel, Redis, etcd, các kết nối dial tới upstream) | Health signals, các SLO producer, định danh upstream của zero_trust | **EG-3: khả năng quan sát nội bộ** — chủ yếu là đấu nối các tín hiệu sẵn có vào một bề mặt duy nhất |
| **Egress do origin khởi tạo** | Không có (nằm ngoài đường đi) | Ngoài phạm vi; ghi lại ranh giới + điểm tích hợp (ví dụ: export sang một NDR/egress proxy) — không xây dựng |

## 2. Phân giai đoạn

### EG-1 — tài liệu thiết kế + thiết lập kỳ vọng với committee · **S** · BẮT ĐẦU TỪ ĐÂY
- Một tài liệu thiết kế duy nhất: threat model (mô hình mối đe dọa — exfil qua đường response trông như thế nào), ranh giới
  trung thực nêu trên, ngân sách hiệu năng (kiểm tra trên đường response là hot-path — chi phí quét body phải được
  giới hạn/lấy mẫu), và câu chuyện dự định trình bày với committee. Owner review trước khi viết bất kỳ dòng code nào.

### EG-2 — phát hiện exfil/bất thường trên đường response · **L**
Các detector ứng viên (tập cuối cùng theo EG-1; tất cả đều được gate theo content-type, giới hạn kích thước, log-only trước):
- **Các mẫu dữ liệu nhạy cảm trong response**: số thẻ PAN (kiểm tra Luhn), dấu hiệu private-key/secret,
  các hình dạng PII hàng loạt — lấy mẫu, không bao giờ quét toàn bộ body trên các stream lớn.
- **Bất thường về kích thước/tốc độ response theo từng client**: các đợt truyền lớn đột ngột tới một IP có rủi ro cao (nạp vào
  mô hình rủi ro per-IP sẵn có — một tín hiệu *response* được chấm điểm rủi ro, phản chiếu cách
  `behavior_analyzer` chấm điểm request).
- **Rò rỉ thông tin qua trang lỗi**: stack trace / debug banner rời khỏi origin (rẻ,
  giá trị cao với committee).
- Hành động: ban đầu chỉ log/chấm điểm; chặn một response giữa stream có các bẫy về UX + tính đúng đắn —
  việc enforce là một quyết định muộn hơn, được đưa ra tường minh.
- Tái sử dụng: hệ thống ống dẫn của kênh response-outcome (công việc AC-P2) là điểm gắn kết tự nhiên.

### EG-3 — bề mặt quan sát nội bộ · **M**
- Một trang dashboard ("Internal Flows"): tình trạng/độ trễ của fleet channel, round-trip Redis/etcd +
  tỷ lệ lỗi, kết quả dial tới upstream theo zone (dữ liệu đã có — zone-aware LB + passive health),
  trạng thái định danh zero_trust cho mTLS upstream, độ trễ lan truyền của config-plane.
- Chủ yếu là tổng hợp các tín hiệu sẵn có (SLO producer, passive-health, `/api/upstreams`,
  telemetry) — khoảng trống nằm ở khâu trình bày, không phải khâu thu thập.
- Các alert hook gắn vào hệ thống multi-burn alerting hiện có thay vì một hệ thống mới.

## 3. Rủi ro

| Mức | Rủi ro | Giảm thiểu |
|---|---|---|
| HIGH | Quét response-body phá hỏng hiệu năng hot-path | gate theo content-type + giới hạn kích thước + lấy mẫu; bench gate ở release-profile cho mỗi PR (profile LT-P1); mặc định log-only |
| MEDIUM | Hứa quá lời về "egress" với committee | EG-1 nêu rõ ranh giới một cách tường minh; ship phần tập con trung thực |
| MEDIUM | Các mẫu PII dễ gây false positive (Luhn trên các chữ số ngẫu nhiên) | các validator (Luhn, entropy), chấm-điểm-không-chặn, corpus từ harness FP-tuning |
| LOW | Trang dashboard EG-3 bị phình phạm vi | chỉ tổng hợp các tín hiệu sẵn có; không có collector mới trong v1 |

## 4. Tiêu chí nghiệm thu

- [ ] Tài liệu thiết kế EG-1 được owner review; thống nhất cách trình bày với committee.
- [ ] EG-2: các detector trên đường response chạy ở chế độ log-only với bằng chứng bench; tích hợp với mô hình rủi ro.
- [ ] EG-3: trang internal-flows hoạt động từ các tín hiệu sẵn có.
- [ ] Ranh giới được ghi lại thành văn: egress do origin khởi tạo được tuyên bố rõ là ngoài phạm vi kèm hướng dẫn tích hợp.
