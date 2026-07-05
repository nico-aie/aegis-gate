> 🇻🇳 Bản dịch tiếng Việt của [COMMITTEE-ROUND2-response-2026-07-04.md](../round-2-improvement/COMMITTEE-ROUND2-response-2026-07-04.md) — bản gốc tiếng Anh là source of truth.

# Hội đồng Vòng 2 — phản hồi đã kiểm chứng & danh mục kế hoạch

> **Trạng thái:** Soạn thảo ngày 2026-07-04 từ đợt rà soát nội bộ vòng 2. Mọi nhận định của hội đồng
> bên dưới đều đã được kiểm chứng lại trực tiếp trên codebase trước khi lập kế hoạch (bằng chứng
> dạng file:line trong các kế hoạch được liên kết).
> Chưa có hạng mục nào trong bộ này được triển khai — mỗi kế hoạch liên kết đều chờ chủ dự án phê duyệt.
> **Phân công nhóm & lộ trình:** [TEAM-PLAN-round2-3-members-2026-07.vi.md](TEAM-PLAN-round2-3-members-2026-07.vi.md).

---

## 1. Kết luận kiểm chứng (từng nhận định một)

| # | Nhận định của hội đồng | Kết luận | Bằng chứng (tóm tắt) | Kế hoạch |
|---|---|---|---|---|
| 🔴1 | mTLS (xác thực chứng chỉ hai chiều) đã được triển khai nhưng mặc định bị tắt cho admin | **XÁC NHẬN — thực tế còn tệ hơn mô tả** | `zero_trust.downstream.apply_to` *mặc định* là `[Admin]` (`config.rs:4299-4300`) nhưng scope Admin **không bao giờ được tiêu thụ** — chỉ có `Data` được nối dây (`run.rs:1195-1210`). TLS acceptor của admin được dựng bằng `with_no_client_auth()` (`run.rs:2177-2185`). Vì vậy ngay cả operator đã cấu hình admin mTLS hôm nay cũng không hề có bước kiểm tra client cert. | [FEAT-admin-mtls-default-2026-07.vi.md](FEAT-admin-mtls-default-2026-07.vi.md) |
| 🔴2 | 2FA (xác thực hai yếu tố) chưa được bật / chưa được bắt buộc | **XÁC NHẬN** | `totp_enabled` mặc định `false` (`config.rs:6131`); không tồn tại cờ `require_totp`; đăng nhập chỉ bằng mật khẩu được hỗ trợ đầy đủ (`login.rs:215`, test `login_with_totp_disabled_ignores_totp_code`). Recovery code (mã khôi phục) được in ra khi đăng ký nhưng **không thể xác minh khi đăng nhập** (không có trường lưu trữ, không có nơi nào gọi `verify_recovery_code`). Tài liệu mô tả một lệnh `waf admin disable-totp` không hề tồn tại. | [FEAT-2fa-enforcement-2026-07.vi.md](FEAT-2fa-enforcement-2026-07.vi.md) |
| 🔴3 | Các endpoint placeholder (có auth nhưng không có business logic) | **XÁC NHẬN — 7 endpoint cụ thể** | `/api/threat-intel/feeds` (hardcode, không có config phía sau), `/api/gitops/status` (module đã bị xóa), `/api/analytics/query` (vỏ rỗng trả 503/empty), `/api/audit/witness` (chỉ còn schema, phần ký đã bị xóa), `/api/cold-tier` (hardcode `delivery:"unknown"`), `render_cert_renew` (đã cài đặt nhưng không được gắn route = code chết), `/api/geoip/status` (hardcode `indicator_count:0`). | [FEAT-placeholder-endpoints-cleanup-2026-07.vi.md](FEAT-placeholder-endpoints-cleanup-2026-07.vi.md) |
| 🟡1 | Cải thiện độ chính xác phát hiện / giảm FP | **HỢP LỆ — trùng với vấn đề còn dang dở đã biết** | `enumeration` + `behavior_analyzer` được phát hành ở trạng thái mặc định TẮT trong khi chờ tinh chỉnh false positive (cảnh báo sai) (trước giờ chưa được theo dõi chính thức). Đã phân tích độ phủ recon/lộ-bí-mật từ báo cáo l-tester: kết luận "263 đường dẫn lọt qua" là có thật, nhưng nguyên nhân là điểm tin cậy thấp (recon=25 < block=70), KHÔNG phải các bypass regex mà báo cáo tuyên bố (V1/V3/V4 SAI) — khắc phục bằng seed canary + chấm điểm phân tầng + 7 signature thực sự còn thiếu. | [IMPROVE-detection-fp-tuning-2026-07.vi.md](IMPROVE-detection-fp-tuning-2026-07.vi.md) · [IMPROVE-recon-detection-and-canary-2026-07.vi.md](IMPROVE-recon-detection-and-canary-2026-07.vi.md) |
| 🟡2 | Tính khả dụng của dashboard | **CHUNG CHUNG — cần chi tiết cụ thể** | Nhiều đợt cải thiện UX lớn đã được phát hành (scope badges, node selector, timeseries widget, risk-key pivot, trang SLO health). Xem §3 bên dưới. | §3 của tài liệu này |
| 🟡3 | Xác minh audit logging + risk decay | **KẾT LUẬN TÁCH ĐÔI** | Risk decay (suy giảm điểm rủi ro theo thời gian): **đã triển khai đầy đủ** (khôi phục độ tin cậy tuyến tính, mặc định 30 điểm/giờ, decay-on-read, `tracker.rs:1054-1076`) — phản hồi hội đồng kèm bằng chứng. Audit logging (ghi nhật ký kiểm toán): **có lỗ hổng thật** — login/logout/đăng nhập thất bại và `reset_state` của control plane **không** phát ra sự kiện audit nào; việc ghi nhận chỉ ở mức best-effort (chỉ fsync khi xoay vòng file/tắt máy). | [FEAT-audit-coverage-gaps-2026-07.vi.md](FEAT-audit-coverage-gaps-2026-07.vi.md) |
| 🟡4 | Quan sát egress + luồng nội bộ | **HỢP LỆ — phần lớn phải xây mới** | Việc kiểm tra chiều response đã tồn tại một phần (response-outcome channel, AI response filter); giám sát egress/luồng nội bộ thực sự thì chưa có. | [FEAT-egress-internal-observability-2026-07.vi.md](FEAT-egress-internal-observability-2026-07.vi.md) |
| 🟡5 | Kiểm chứng dưới điều kiện vận hành thực tế | **HỢP LỆ** | Bài smoke test thủ công cho SLO/alerting chưa bao giờ được chạy; các đợt diễn tập sự cố/khôi phục còn mang tính tùy hứng. | [PLAN-ops-validation-realistic-2026-07.vi.md](PLAN-ops-validation-realistic-2026-07.vi.md) |
| 🟡6 | Tập trung vào ý định của yêu cầu | **GHI CHÚ QUY TRÌNH** | Xem §4. | — |

## 2. Các điểm cần chủ dự án quyết định (chặn tiến độ, quyết trước khi triển khai)

1. **Mâu thuẫn về transport giữa vòng 1 và vòng 2.** Vòng 1 yêu cầu admin phục vụ qua plain-HTTP
   công khai (được ghi nhận là hợp đồng cứng trong `plans/future/admin-accounts-rbac-sso.md` và
   phần guardrail của `plans/issues/FEAT-admin-accounts-p1-self-service-hardening.md`). Vòng 2 nay
   lại yêu cầu **mTLS mặc định trên admin** — điều này đòi hỏi TLS trên admin listener. Hai yêu cầu
   này không thể cùng đúng.
   **Khuyến nghị:** coi vòng 2 thay thế vòng 1; cập nhật ghi chú guardrail trong cả hai kế hoạch
   hiện có và memory `project_admin_public_http_contract` khi kế hoạch mTLS bắt đầu.
2. **Ngữ nghĩa "mặc định bật" cho admin mTLS.** Bật mặc định thực sự khi chưa có chứng chỉ nào sẽ
   làm hỏng lần khởi động đầu tiên. Kế hoạch mTLS khuyến nghị lộ trình theo giai đoạn (nối dây →
   công cụ bootstrap → đảo giá trị mặc định kèm đường cấp phát chứng chỉ). Cần chọn trạng thái
   cuối: mặc định fail-closed (đóng an toàn khi lỗi) hay bắt-buộc-khi-đã-cấu-hình-CA.
3. **Endpoint placeholder: hoàn thiện hay gỡ bỏ.** Khuyến nghị cho từng endpoint nằm trong kế hoạch
   dọn dẹp; hai endpoint (`analytics/query`, `cold-tier delivery`) có đường "hoàn thiện" với chi phí
   thấp, số còn lại nên gỡ bỏ.

## 3. 🟡2 Tính khả dụng của dashboard (giữ lại ở đây — cần chi tiết từ hội đồng)

Nhận xét này còn chung chung và nhiều thứ đã được phát hành (fleet-scope badges, degraded banners,
node selector, window chips trung thực, TimeseriesChart, investigation pivot, trang Health có khả
năng giải thích). Thay vì đoán mò, hãy chạy một đợt rà soát có cấu trúc và rút ra backlog cụ thể:

- **Click-path audit (kiểm tra đường dẫn thao tác)** cho 6 tác vụ operator hàng đầu (xử lý một cuộc
  tấn công, chuyển mode, sửa rule, điều tra một IP, kiểm tra sức khỏe fleet, xuất báo cáo) — đếm số
  bước/ngõ cụt.
- **Rà soát tính nhất quán**: cách đặt tên (allow/bypass/whitelist), nội dung empty-state, error
  toast, mẫu xác nhận cho các hành động phá hủy.
- Sửa các ô UI dựa trên placeholder (threat-intel, gitops, witness) như một phần của 🔴3 — các
  panel "coming soon" cũ kỹ tự thân đã là một phát hiện về tính khả dụng.
- Khung thời gian: 1 ngày audit → backlog gồm các PR nhỏ. Không tạo file kế hoạch riêng cho đến khi
  đợt audit sinh ra được một backlog.

## 4. 🟡6 Ý định của yêu cầu (ghi chú quy trình)

Áp dụng cho mọi hạng mục hội đồng/hợp đồng còn lại: nêu rõ **mục tiêu an ninh** (chứ không phải câu
chữ nguyên văn) ở đầu mỗi kế hoạch, và thêm một dòng nghiệm thu "đạt mục tiêu, không chỉ đúng câu
chữ" — ví dụ: mục tiêu của mTLS là *các bên chưa xác thực hoàn toàn không thể chạm tới kênh admin*,
nên kế hoạch cũng phải xử lý cả đường fallback plain-HTTP và `AEGIS_INSECURE_COOKIES`, chứ không
chỉ gắn thêm một verifier lên TLS.

## 5. Trình tự đề xuất

1. **FEAT-2fa-enforcement** (nhỏ; mở rộng AA-P1 đã được lên kế hoạch trong `plans/issues/`) — thắng lợi 🔴 nhanh nhất.
2. **FEAT-admin-mtls-default** P1 (nối dây scope Admin — từ chối các kết nối không có chứng chỉ khi đã cấu hình).
3. **FEAT-placeholder-endpoints-cleanup** (các PR nhỏ, rủi ro thấp, hội đồng nhìn thấy được).
4. **FEAT-audit-coverage-gaps** (sự kiện login/reset_state có chi phí thấp; làm cùng với #1).
5. mTLS P2/P3 (công cụ bootstrap, đảo giá trị mặc định) + **IMPROVE-detection-fp-tuning**.
6. **PLAN-ops-validation** trước vòng 3.
7. **FEAT-egress-internal-observability** — thiết kế trước, lớn nhất, làm cuối cùng.
