> 🇻🇳 Bản dịch tiếng Việt của [FEAT-2fa-enforcement-2026-07.md](../round-2-improvement/FEAT-2fa-enforcement-2026-07.md) — bản gốc tiếng Anh là source of truth.

# FEAT — Bắt buộc 2FA (xác thực hai yếu tố) cho mọi truy cập admin

> **Loại:** FEAT (committee round-2 🔴2) · **Trạng thái:** ☐ Chưa bắt đầu — lập kế hoạch 2026-07-04
> **Tiền tố Track ID:** `TF-<1–3>` · **Mở rộng từ:** `plans/issues/FEAT-admin-accounts-p1-self-service-hardening.md`
> (AA-P1b web enrollment + đăng nhập bằng recovery, AA-P1d setup token) — kế hoạch này bổ sung lớp *enforcement*
> (thực thi bắt buộc) mà các giai đoạn đó đã chủ ý để lại. **Không** lặp lại phạm vi của chúng ở đây.

**Mục tiêu (theo tinh thần, không theo câu chữ):** chỉ mật khẩu đơn thuần không bao giờ được cấp quyền truy cập admin. Mọi
đăng nhập admin tương tác đều yêu cầu yếu tố thứ hai; các lối thoát khẩn cấp (recovery code (mã khôi phục), break-glass
(cơ chế truy cập khẩn cấp)) bản thân chúng cũng phải được xác thực và ghi audit.

---

## 1. Hiện trạng đã xác minh (2026-07-04)

| Sự kiện | Vị trí tham chiếu |
| --- | --- |
| Phần hiện thực TOTP đã vững: RFC 6238 SHA1, so sánh constant-time, chống replay | `admin_auth/totp.rs:18-175` |
| `totp_enabled` mặc định là **false**; `#[serde(default)]` → config bỏ trống = tắt | `config.rs:6050-6051, 6131` |
| Không tồn tại `require_totp` / cờ MFA toàn cục ở bất kỳ đâu | (grep: không có) |
| Đăng nhập chỉ bằng mật khẩu được hỗ trợ đầy đủ khi cờ tắt | `login.rs:215`, test `login.rs:766-777` |
| Enrollment (đăng ký TOTP) chỉ qua CLI→dán vào YAML (`waf admin enroll-totp`); chưa có web enrollment | `main.rs:650-695`, `config.rs:6058` |
| Recovery code được sinh ra + in ra nhưng **không dùng được khi đăng nhập** — không có trường lưu trữ, `verify_recovery_code` không có caller nào | `totp.rs:191-209`, `main.rs:683` |
| Docs nói quá thực tế: khẳng định recovery code được lưu bằng argon2 + có lệnh `waf admin disable-totp`; cả hai đều không tồn tại | `dashboard-auth.md:55,230,260` (lại là `[[project_docs_overstate_impl]]`) |
| Bearer token của service-account là một đường không tương tác riêng biệt (không có TOTP) | `config.rs:6144`, `main.rs:726` |
| Đường dựng identity thứ cấp bỏ qua các trường TOTP (`..AdminIdentity::default()`) | `aegis-proxy/src/lib.rs:400-403` |

## 2. Phân giai đoạn

### TF-1 — cờ enforcement `require_totp` · **S** · BẮT ĐẦU TỪ ĐÂY
- Thêm `admin.dashboard_auth.require_totp: bool` — **mặc định `true`**.
- Ngữ nghĩa khi đăng nhập (`authenticate`, `login.rs:144`):
  - `require_totp && !totp_enabled` → đăng nhập trả về một trạng thái `enrollment_required` riêng biệt,
    cho phép session chỉ vào được bề mặt **chỉ-để-enroll-TOTP** (không mở khóa gì khác) — ghép cặp
    với `POST /api/admin/totp/enroll|confirm` của AA-P1b. Cho tới khi AA-P1b hoàn thành, phương án dự phòng: từ chối
    đăng nhập kèm thông báo lỗi có thể hành động được "hãy chạy `waf admin enroll-totp`" (vẫn được enforce, UX kém hơn).
  - `require_totp && totp_enabled` → đường strict giữ nguyên không đổi.
  - `require_totp: false` → hành vi như hiện nay (opt-out tường minh, nhìn thấy được, dành cho dev).
- Cảnh báo validation lúc boot (cảnh báo, không phải lỗi) khi `require_totp: false` trong một profile không phải dev.
- Audit đường dựng identity thứ cấp (`lib.rs:400-403`) để enforcement không thể bị lách,
  bất kể đường boot nào đã dựng ra identity.
- Dev/CI/bench: đặt `require_totp: false` một cách tường minh trong `config/dev.yaml` v.v. — enforcement là
  *mặc định*, dev phải opt-out một cách rõ ràng.

### TF-2 — bịt các kẽ hở ở lối thoát khẩn cấp · **M**
- **Đăng nhập bằng recovery code**: AA-P1b chịu trách nhiệm phần wiring (tiêu thụ một lần, lưu bền trong doc). Kế hoạch này bổ sung:
  đăng nhập bằng recovery *được tính là 2FA* (được phép dưới `require_totp`), phát ra một audit event riêng biệt,
  và khi số mã còn lại xuống thấp thì đẩy dần tới việc buộc re-enrollment (đăng ký lại).
- **CLI `waf admin disable-totp`**: có trong docs nhưng không có trong code — hoặc hiện thực nó (yêu cầu mật khẩu hiện tại
  + một recovery/TOTP code; phát audit event) hoặc gỡ nó khỏi docs. Khuyến nghị:
  hiện thực; việc sửa YAML để tắt vẫn khả thi nhưng khi đó nó là một thay đổi config có audit.
- **Service accounts**: giữ nguyên (không tương tác), nhưng ghi rõ trong tài liệu rằng `require_totp` không
  áp dụng cho bearer token, và scope của chúng chính là biện pháp giảm thiểu.

### TF-3 — chỉnh docs cho đúng thực tế + bằng chứng cho committee · **S**
- Sửa `docs/control-plane/dashboard-auth.md` cho khớp với thực tế sau TF-1/2 (lưu trữ recovery,
  lệnh disable, các mặc định về enforcement).
- Artifact xác minh cho committee: transcript test cho thấy đăng nhập chỉ bằng mật khẩu bị từ chối
  trên một config mặc định.

## 3. Tests (RED-first)

- Config mặc định (`require_totp` không đặt) + `totp_enabled: false` → đăng nhập chỉ bằng mật khẩu **thất bại** /
  được chuyển sang trạng thái chỉ-enrollment; không truy cập được gì khác trong trạng thái đó.
- `require_totp: false` tường minh → hành vi cũ được giữ nguyên (regression guard — chốt chặn hồi quy).
- Đăng nhập bằng recovery code thỏa mãn enforcement, tiêu thụ mã đúng một lần, và audit event được phát ra.
- `disable-totp` yêu cầu yếu tố thứ hai; sau một lần disable thì lần đăng nhập kế tiếp bị buộc re-enrollment
  (vì `require_totp` vẫn là true).
- Cả hai đường dựng identity (accept.rs + lib.rs) enforce giống hệt nhau.
- Giữ các bộ test RFC 6238 / argon2 / rate-limit vẫn xanh.

## 4. Rủi ro

| Mức | Rủi ro | Giảm thiểu |
|---|---|---|
| MEDIUM | Lockout (tự khóa chính mình): enforcement lên trước UX enrollment (AA-P1b) | xếp lịch sau AA-P1b, hoặc chấp nhận khoảng thời gian dùng fallback lỗi CLI; loopback + sửa YAML vẫn là break-glass |
| MEDIUM | Các flow dev/CI/bench hỏng vì mặc định true | opt-out tường minh trong các config dev ngay trong cùng PR |
| LOW | Bề mặt session chỉ-enrollment rò rỉ các API khác | giới hạn phạm vi bằng middleware gate hiện có (`admin_auth_middleware.rs:81-200`), viết test liệt kê toàn bộ route table đối chiếu với nó |

## 5. Tiêu chí nghiệm thu

- [ ] Bản cài đặt mặc định mới: không có session admin nào nếu thiếu yếu tố thứ hai — đúng nguyên văn yêu cầu của committee.
- [ ] Flow enrollment-required dùng được end-to-end (cùng với AA-P1b) hoặc fallback CLI được ghi trong tài liệu.
- [ ] Các đường recovery + disable được hiện thực, có audit, và khớp với docs.
- [ ] Dev/CI/bench xanh với các opt-out tường minh.
