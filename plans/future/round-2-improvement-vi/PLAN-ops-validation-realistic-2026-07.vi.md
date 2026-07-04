> 🇻🇳 Bản dịch tiếng Việt của [PLAN-ops-validation-realistic-2026-07.md](../round-2-improvement/PLAN-ops-validation-realistic-2026-07.md) — bản gốc tiếng Anh là source of truth.

# PLAN — Kiểm chứng dưới điều kiện vận hành thực tế

> **Loại:** PLAN (committee round-2 🟡5) · **Trạng thái:** ☐ Chưa bắt đầu — lên kế hoạch 2026-07-04
> **Tiền tố Track ID:** `OV-<1–3>` · Sản phẩm bàn giao là **bằng chứng** (runbook + transcript các drill — bài diễn tập),
> không phải tính năng. Lên lịch trước round 3.

**Mục tiêu (theo tinh thần, không theo câu chữ):** chứng minh hệ thống trụ vững bên ngoài các bài test chức năng cô lập —
tải giống production, các quy trình admin thực tế, và tình huống lỗi/phục hồi — với các drill script có thể tái lập
và bằng chứng được ghi lại.

---

## 1. Nợ kỹ thuật đã biết mà kế hoạch này trả

- **Bài manual smoke cho SLO/alerting chưa bao giờ được chạy** — đường enforcement-excluded chưa từng được
  kiểm tra end-to-end; đợt tấn công thật đầu tiên sẽ là lần test đầu tiên. Đây là drill quan trọng nhất.
- Đường watcher/deploy chỉ mới được sửa gần đây (hot-reload theo atomic-rename) — đáng để làm một drill chứng minh trên
  một fleet đang chạy, không chỉ qua unit test.
- Các footgun (cạm bẫy tự hại) của bench harness đã được ghi lại nhưng nằm rải rác: biến env `WAF_CONFIG` giết boot một cách âm thầm
  (`[[project_waf_config_env_footgun]]`), SIGTERM drain giữ port ~5s, các client Redis exec
  bị bỏ mồ côi (`[[feedback_e2e_docker_cleanup]]`), hiện tượng đầu độc rủi ro single-IP do XFF ở môi trường dev
  (`[[feedback_dev_xff_single_ip_gates]]`). Runbook sẽ hợp nhất những mục này.

## 2. Phân giai đoạn

### OV-1 — kiểm chứng tải & hỗn hợp tấn công · **M** · BẮT ĐẦU TỪ ĐÂY
- Fleet ở release-profile (LT-P1) (≥2 node + Redis) dưới hỗn hợp lưu lượng giống production duy trì liên tục:
  baseline lành tính + các đợt tấn công (các vector của l-tester, replay ở dạng raw), DDoS spike (kiểm tra
  cơ chế tổng hợp fleet-RPS), enumeration kiểu nhỏ giọt chậm (slow-drip).
- Ghi lại: độ trễ p50/p99, tỷ lệ lỗi, lấy mẫu tính đúng đắn của block/allow, độ ổn định memory/fd
  qua soak test (kiểm thử chạy bền) ≥1 giờ, hành vi SLO burn trong khung thời gian tấn công (bài smoke chưa-từng-chạy — xác minh
  phân loại blocks≠outage, origin-5xx=bad vẫn đúng khi chạy thật).
- Các ngưỡng đạt/rớt được viết ra *trước* khi chạy.

### OV-2 — các quy trình quản trị thực tế · **S–M**
Các drill vận hành được script hóa chạy trên fleet thật (mỗi drill = các bước + quan sát kỳ vọng):
1. Triage tấn công: live feed → điều tra IP → reset rủi ro → xác minh allow sạch.
2. Vòng đời rule: tạo (simulator) → enforce → quan sát attribution header → rollback.
3. Chuyển mode dry-run↔enforce → xác minh hội tụ **toàn fleet** (bản sửa publish của `/api/mode`).
4. Deploy config qua atomic rename → quan sát hot-reload trên tất cả các node (bản sửa watcher).
5. Ack/resolve incident xuyên node (hội tụ overlay của federation).
6. Xoay vòng credential + (khi đã ship) đăng ký TOTP / thay chứng chỉ mTLS.
- Mỗi drill đồng thời đóng vai trò là kịch bản demo cho round 3.

### OV-3 — các drill về lỗi & phục hồi · **M**
- **Redis outage** (mất Redis) giữa lúc có traffic: tư thế degraded-not-fail-closed vẫn giữ vững
  (`[[project_health_signals_reported_not_gating]]`); hành vi risk/session trong lúc + sau sự cố;
  watchdog TelemetryAbsent kích hoạt.
- **Origin failure** (origin gặp sự cố): kill các upstream member → passive health đánh dấu down → phục hồi half-open;
  failover theo zone với locality gate.
- **Kill/restart node**: SIGKILL một node WAF → tính liên tục của các peer, rebind hot-bind, session sống sót
  (lưu trong Redis), hành vi resurrection của incident.
- **Rollback config dưới áp lực**: push config hỏng → rollback → fleet hội tụ.
- **Cert hết hạn** (zero_trust): định danh upstream hết hạn → alert kích hoạt, trạng thái degraded trung thực.
- Ghi lại các quan sát về thời gian phục hồi đối chiếu với kỳ vọng SLO.

## 3. Sản phẩm bàn giao

- [ ] `docs/ops/validation-runbook.md` — các drill script hợp nhất + các footgun của môi trường.
- [ ] Gói bằng chứng cho mỗi drill (transcript, ảnh chụp metrics, ảnh chụp panel SLO) đặt dưới
      `plans/future/` hoặc `docs/ops/evidence/` — dành cho committee.
- [ ] Danh sách defect từ các drill được triage thành issue (đầu ra thực sự — hãy kỳ vọng sẽ tìm thấy vài cái).
- [ ] Các ngưỡng của OV-1 được đáp ứng hoặc regression được ghi nhận thành issue.

## 4. Rủi ro

| Mức | Rủi ro | Giảm thiểu |
|---|---|---|
| MEDIUM | Các drill phát hiện bug thật vào thời điểm muộn | đó chính là mục đích — chừa buffer lịch trước round 3 |
| LOW | Các footgun của môi trường bench làm tốn thời gian drill | runbook hợp nhất chúng ngay từ đầu (§1) |
| LOW | Giới hạn của một máy đơn (1 Redis, fleet cục bộ) | ghi lại môi trường một cách trung thực trong gói bằng chứng |
