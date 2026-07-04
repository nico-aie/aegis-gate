> 🇻🇳 Bản dịch tiếng Việt của [FEAT-audit-coverage-gaps-2026-07.md](FEAT-audit-coverage-gaps-2026-07.md) — bản gốc tiếng Anh là source of truth.

# FEAT — Các lỗ hổng độ phủ audit-logging + các lưu ý về risk-decay

> **Type:** FEAT (committee round-2 🟡3) · **Status:** ☐ Chưa bắt đầu — lập kế hoạch 2026-07-04
> **Track ID prefix:** `AU-<1–4>` · Đã xác minh 2026-07-04 trên cả hai đường audit (hash-chain +
> interop contract log) và risk tracker.

**Mục tiêu (tinh thần, không phải câu chữ):** mọi hành động liên quan đến bảo mật đều để lại dấu vết mà
điều tra viên có thể tin cậy; câu chuyện risk decay (suy giảm điểm rủi ro theo thời gian) chứng minh được
với committee bằng bằng chứng, và các điểm sắc cạnh của nó hoặc được sửa hoặc được ghi nhận là thiết kế
có chủ đích.

---

## 1. Hiện trạng đã xác minh

### Những gì đã vững (trả lời committee bằng bằng chứng, đừng xây lại)
- Hash chain SHA-256 chống giả mạo (tamper-evident) trên các mutation của admin: `AuditedMutate::apply`
  bao bọc **~40 điểm gọi mutation** — config activate/rollback, rules CRUD/toggle, mode/loadmode, risk
  resets/thresholds, chỉnh sửa white/blacklist, gates, zero-trust, các route AI (`mutation.rs:187-278`,
  các điểm gọi rải khắp `admin_mutate.rs`). Chain trên đĩa xoay vòng theo ngày sẽ re-seed `prev_hash`
  (`sinks/jsonl.rs:380-471`); đã có xác minh offline (`audit/verify.rs`); 9 định dạng SIEM sink.
- **Risk decay đã được triển khai đầy đủ**: phục hồi trust tuyến tính, mặc định **30 pts/hr**
  (`config.rs:4744-4759`), điều chỉnh nóng được; decay-on-read qua `decayed_slot` trên mọi quyết định
  gate, API view, và write rebase (`tracker.rs:591-599, 694-752, 1054-1076`); strikes cố tình
  không bao giờ decay; tùy chọn Redis durability lưu bền các slot bị strike kèm tuổi theo wall-clock.
  Câu hỏi của committee "decay đã được triển khai chưa?" → **có**, đóng gói bằng chứng (AU-4).

### Các lỗ hổng thực sự (cần sửa)

| # | Lỗ hổng | Anchor |
|---|---|---|
| 1 | **Đăng nhập thành công / thất bại / đăng xuất KHÔNG phát ra audit event nào** — `authenticate()`/`logout()` không có bất kỳ tham chiếu `AuditBus` nào | `login.rs` (toàn bộ file), `admin_login.rs:99-199` |
| 2 | **`reset_state` của control-plane xóa sạch toàn bộ risk/state mà không có audit event** — hủy hoại dữ liệu, không để lại dấu vết | `admin_dispatch.rs:1230-1260` |
| 3 | **Không có event chuyên biệt cho thay đổi credential** — việc xoay vòng password/TOTP chỉ hiện diện dưới dạng diff `config_activate` của toàn bộ config | `login.rs:34-126` |
| 4 | **Việc giao nhận là best-effort**: `emit()` âm thầm loại bỏ khi buffer đầy/không có subscriber (`audit.rs:337-339`); broadcast lag = drop có ghi log (`jsonl.rs:551-556`); fsync chỉ chạy khi xoay vòng theo ngày + graceful shutdown → crash làm mất phần đuôi chưa sync | `audit.rs`, `jsonl.rs:388-390,438-448,574-585` |
| 5 | Thiếu witness/external anchoring (mới chỉ có schema) | `witness.rs:1-8` — do plan placeholder-cleanup xử lý; anchoring thực sự vẫn thuộc tương lai |

### Các lưu ý về risk-decay (quyết định: sửa hay ghi nhận là thiết kế có chủ đích)

| # | Lưu ý | Anchor |
|---|---|---|
| A | **Idle eviction xóa mất strikes**: slot bị gỡ sau `IDLE_TTL = 3600s` không hoạt động → strikes "trọn đời" bị reset đối với kẻ tấn công im lặng 1 giờ (trừ khi bật Redis durability + còn dưới cap) | `tracker.rs:55-105, 473-492` |
| B | **Cardinality cap âm thầm dừng tích lũy** tại `MAX_TRACKED_KEYS = 1_000_000` — các key mới vẫn được chấm điểm theo từng request nhưng không bao giờ tích lũy; hành xử như Allow | `tracker.rs:68, 614-618, 662-665` |
| C | `trust_per_hour: 0` vô hiệu hóa hoàn toàn decay (điểm số bị dính cứng) — có thể đạt tới qua API | `tracker.rs:1070` |

## 2. Phân giai đoạn

### AU-1 — audit event cho auth + hành động hủy hoại dữ liệu · **S** · BẮT ĐẦU TỪ ĐÂY
- Phát các event `AuditClass::Access` từ đường đăng nhập: `login_success`, `login_failure`
  (lý do được gom nhóm: bad-password / bad-totp / locked-out — **không bao giờ** ghi giá trị được
  gửi lên), `logout`. Gộp/giới hạn tốc độ các event thất bại theo IP theo từng cửa sổ thời gian
  để một trận lụt credential-stuffing (nhồi thông tin đăng nhập) không thể đánh sập audit bus
  (tận dụng lại các bộ đếm `login_rate_limiter` sẵn có).
- `reset_state`: phát một event lớp `Admin` **trước khi** xóa (actor = control-plane secret
  principal, source ip), để chính việc xóa không thể xóa dấu vết của nó.
- Các event TOTP enroll/disable + đổi password — sẽ hạ cánh cùng `FEAT-2fa-enforcement` TF-2 và
  AA-P1a/b (các PR đó bổ sung endpoint; plan này sở hữu taxonomy của event).

### AU-2 — trung thực về giao nhận + nút vặn durability · **S–M**
- Metrics: `waf_audit_events_dropped_total` (phía emit + phía lag) và các bộ đếm giao nhận
  theo từng sink (chia sẻ công việc với placeholder-cleanup #5 `/api/cold-tier`).
- Config: `audit.fsync_interval` (mặc định: hành vi hiện tại chỉ rotate/shutdown) dành cho operator
  muốn một cửa sổ mất mát có giới hạn; ghi nhận mô hình durability một cách trung thực trong `docs/`.
- **Không** hứa hẹn giao nhận đảm bảo — theo lập trường `[[project_health_signals_reported_not_gating]]`:
  báo cáo suy giảm, không bao giờ chặn data plane vì audit I/O.

### AU-3 — các lưu ý risk-decay · **S–M**
- **A (strike eviction):** quyết định của owner — nếu "strikes trọn đời" là hợp đồng, miễn trừ
  các slot bị strike khỏi idle eviction (có giới hạn: số lượng slot bị strike là nhỏ) hoặc yêu cầu
  Redis durability cho strike gate; nếu không, sửa tài liệu để nói "strikes tồn tại qua 1 giờ idle".
- **B (cap):** phát `waf_risk_tracker_saturated_total` + cảnh báo trên dashboard khi cap chặn
  việc tích lũy — việc fail-open âm thầm mới là phần committee quan tâm.
- **C:** đặt sàn validation hoặc cảnh báo tường minh khi `trust_per_hour: 0` được đặt qua API/config.

### AU-4 — gói bằng chứng cho committee · **S**
- Một tài liệu ngắn (hoặc một mục trong bản trả lời round-2) gồm công thức decay, các giá trị mặc
  định, các anchor file:line, và một transcript kiểm thử tái lập được (chấm điểm một key, tua đồng
  hồ, cho thấy giá trị đọc đã decay + strike vẫn tồn tại). Tương tự cho độ phủ audit: bản liệt kê
  các điểm gọi mutation.

## 3. Kiểm thử (RED-first)

- Đăng nhập thành công/thất bại/đăng xuất mỗi loại tạo ra đúng một event trong chain; lụt thất bại
  tạo ra các event đã gộp, không phải mỗi lần thử một event; không có tài liệu bí mật trong bất kỳ
  event nào.
- Event `reset_state` hiện diện trong chain *sau* một lần xóa state (thứ tự được chứng minh).
- Các bộ đếm drop tăng lên khi ép broadcast lag; nút vặn fsync giới hạn mất mát trong một kill-test.
- Hành vi strike-eviction theo quyết định của owner (miễn trừ hoặc được ghi nhận); metric saturation
  kích hoạt khi chạm cap.
- Bộ kiểm thử xác minh chain vẫn giữ trạng thái xanh (`audit/verify.rs`).

## 4. Rủi ro

| Sev | Rủi ro | Giảm thiểu |
|---|---|---|
| MEDIUM | Lụt audit-event từ các lần đăng nhập thất bại (DoS lên bus) | cửa sổ gộp theo IP; giới hạn cardinality của lý do |
| LOW | Nút vặn fsync làm hại độ trễ hot-path | đường audit vốn đã nằm ngoài đường request (broadcast + writer task); nút vặn chỉ ảnh hưởng writer task |
| LOW | Việc sửa strike-eviction làm phình bộ nhớ | chỉ các slot bị strike; giới hạn tập được miễn trừ |

## 5. Tiêu chí nghiệm thu

- [ ] Login/logout/đăng-nhập-thất-bại/reset_state/thay-đổi-credential đều để lại audit event trong chain.
- [ ] Các metric drop/giao nhận được phơi bày; mô hình durability được ghi nhận trung thực.
- [ ] Các lưu ý decay A–C được định đoạt (sửa hoặc ghi nhận là thiết kế có chủ đích).
- [ ] Gói bằng chứng được bàn giao cho committee (decay = đã được triển khai sẵn).
