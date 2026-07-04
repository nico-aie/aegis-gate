> 🇻🇳 Bản dịch tiếng Việt của [FEAT-admin-mtls-default-2026-07.md](FEAT-admin-mtls-default-2026-07.md) — bản gốc tiếng Anh là source of truth.

# FEAT — mTLS cho kênh admin: nối dây trước, rồi biến thành mặc định

> **Loại:** FEAT (hội đồng vòng 2 🔴1) · **Trạng thái:** ☐ Chưa bắt đầu — lập kế hoạch 2026-07-04
> **Tiền tố Track ID:** `MT-A<1–3>` · **Bối cảnh thiết kế:** phản hồi hội đồng vòng 2
> ([COMMITTEE-ROUND2-response-2026-07-04.vi.md](COMMITTEE-ROUND2-response-2026-07-04.vi.md))
>
> ⚠️ **Thay thế một hợp đồng từ vòng 1.** `[[project_admin_public_http_contract]]` và các ghi chú
> guardrail trong `admin-accounts-rbac-sso.md` / `FEAT-admin-accounts-p1-self-service-hardening.md`
> ghi nhận yêu cầu bắt buộc của vòng 1: admin phục vụ qua plain-HTTP công khai. Vòng 2 yêu cầu rõ
> ràng admin mTLS (xác thực chứng chỉ hai chiều) theo mặc định. Sau khi chủ dự án xác nhận, cập
> nhật các guardrail đó + memory trước khi bắt đầu.

**Mục tiêu (theo ý định, không theo câu chữ):** một bên chưa xác thực không được phép *chạm tới*
kênh admin — bắt buộc phải có client certificate hợp lệ trước khi bất kỳ HTTP nào được trao đổi.
Xác thực mật khẩu/TOTP/session vẫn là lớp chốt chặn thứ hai ở tầng ứng dụng (defense in depth —
phòng thủ nhiều lớp).

---

## 1. Hiện trạng đã kiểm chứng (2026-07-04)

| Sự kiện | Vị trí |
| --- | --- |
| Admin listener bind theo `cfg.listeners.admin.bind`, mặc định `127.0.0.1:9443` | `run.rs:2116`, `config.rs:6007-6009` |
| Đã tồn tại **TLS phía server** tùy chọn: `admin.tls: Option<TlsConfig>` (mặc định `None` = plain HTTP) | `config.rs:5994-5995`, `run.rs:2145-2199` |
| Acceptor của admin được dựng **không có client auth** (`build_hardened_server_config`) | `run.rs:2177-2185` |
| `zero_trust.downstream.apply_to` **mặc định là `[Admin]`** trong schema… | `config.rs:4299-4300, 4325-4336` |
| …nhưng chỉ scope `Data` được tiêu thụ; `Admin` **không được match ở bất kỳ đâu** | `run.rs:1195-1210` |
| Builder cho client-cert verifier đã tồn tại (data plane đang dùng): `build_hardened_server_config_with_client_auth` (WebPkiClientVerifier, Optional/Required) | `listener/tls_policy.rs:89-148` |
| `ClientTrustStore` hot-swap (thay nóng) **đã được truyền vào vòng lặp accept của admin** — nhưng chỉ phục vụ các API đọc `/api/mtls/*`, không phục vụ acceptor | `run.rs:2245, 2283`, `accept.rs:383,1096` |
| HTTP server của admin: hyper `http1` + tokio-rustls; ALPN ghim `http/1.1` | `accept.rs:26,1645-1657,1730-1744`, `run.rs:2188` |

**Tóm lại:** đây là một kế hoạch *nối dây*. Không cần crate mới, không cần crypto mới — verifier,
trust store và cơ chế acceptor đều đã có sẵn trong bản phát hành hiện tại; chỉ là đường admin chưa
bao giờ gọi đến chúng. Hiện trạng còn tệ hơn những gì hội đồng nêu: cấu hình `zero_trust.downstream`
với scope `Admin` (vốn là mặc định!) âm thầm không có tác dụng gì trên admin listener.

## 2. Phân giai đoạn

### MT-A1 — tiêu thụ scope `Admin` (làm cho mTLS đã cấu hình có hiệu lực thật) · **S–M** · BẮT ĐẦU TỪ ĐÂY
- Trong phần dựng acceptor của admin (`run.rs:2153-2193`): khi `zero_trust.downstream` tồn tại,
  `mode != Disabled`, và `apply_to` chứa `DownstreamMtlsScope::Admin`, dựng bằng
  `build_hardened_server_config_with_client_auth(resolver, min_version, &admin_client_trust, mode)`
  thay cho builder không có client auth. Trust store đã sẵn trong scope (`run.rs:2245`).
- `Required` → handshake không có client cert hợp lệ sẽ **thất bại**; `Optional` → cert được xác
  minh khi được trình ra (chế độ chuyển tiếp).
- Tôn trọng `allowed_sans` trên đường admin theo đúng cách data plane đang làm.
- **Kiểm tra hợp lệ cấu hình:** `zero_trust.downstream` có `Admin` trong `apply_to` nhưng
  `admin.tls` không được đặt → lỗi validation lúc khởi động (mTLS trên plain HTTP là phi logic).
  Điều này đóng lại cái bẫy no-op âm thầm hiện nay.
- Structural guard test (kiểm thử bảo vệ cấu trúc): khẳng định `DownstreamMtlsScope::Admin` có nơi
  tiêu thụ (mô phỏng mẫu guard của `apply_and_swap`, `[[project_apply_and_swap_helper_guard]]`).

### MT-A2 — cấp phát chứng chỉ & khả năng vận hành · **M**
- CLI `waf admin mtls bootstrap`: sinh một admin CA cục bộ + một client cert cho operator
  (xuất PKCS#12/PEM), in hướng dẫn cài đặt. Không có công cụ này, "mặc định bật" là một cỗ máy
  khóa cửa nhốt operator.
- Hot-swap trust-store đã tồn tại qua `/api/mtls/*` — xác minh acceptor của admin nhận được các
  anchor đã hoán đổi mà không cần khởi động lại (về lý thuyết là có, `ClientTrustStore` là live);
  viết test cho điều này.
- Dashboard: hiển thị trạng thái mTLS của kênh admin (mode, CA fingerprint, danh sách SAN được
  phép) trên trang Zero-Trust; banner kiểu degraded khi kênh admin đang phục vụ mà không có mTLS.
- Tài liệu: runbook đăng ký chứng chỉ, bao gồm cài client-cert trên trình duyệt; break-glass (lối
  thoát khẩn cấp) = loopback/SSH-tunnel (mẫu `[[project_control_plane_loopback_only]]`) với chế độ
  `Optional`, tuyệt đối không dùng cờ bypass.

### MT-A3 — đảo giá trị mặc định · **M** (bước cần thận trọng — làm CUỐI CÙNG)
- Phát hành cấu hình mặc định với `admin.tls` đã được điền (server cert tự ký do bootstrap sinh ra)
  và `zero_trust.downstream.mode: required` + `apply_to: [Admin]`.
- Luồng khởi động lần đầu: nếu chưa có CA/cert nào, quá trình boot sẽ tự sinh (hoặc từ chối khởi
  động kèm một dòng hướng dẫn chạy `waf admin mtls bootstrap` — điểm quyết định #2 của chủ dự án
  trong tài liệu phản hồi).
- Loại bỏ `AEGIS_INSECURE_COOKIES` khỏi đường mặc định (cookie Secure một khi admin đã chạy HTTPS).
- Hệ quả cho dev/CI/bench: Makefile `run-dev`, QUICKSTART, harness e2e/bench nhận một profile
  dev-mode tường minh (`mode: disabled` được ghi chú rõ ràng) — cùng mẫu với cách tách test-hash
  của AA-P1d.

## 3. Kiểm thử (RED-first — viết test thất bại trước)

- Handshake không có client cert → bị từ chối ở chế độ `Required`, được chấp nhận ở
  `Optional`/`Disabled` (dùng raw TLS client, không dùng HTTP client có chuẩn hóa — bài học
  `[[project_hyper_normalizes_framing]]`).
- Cert từ một CA không được tin cậy → bị từ chối; CA hợp lệ nhưng SAN không nằm trong
  `allowed_sans` → bị từ chối.
- Hot-swap trust-anchor có hiệu lực ở handshake kế tiếp mà không cần khởi động lại.
- Validation lúc boot: scope `Admin` + không có `admin.tls` → lỗi cấu hình với thông báo hướng dẫn
  hành động rõ ràng.
- Đường dev plain-HTTP hiện có vẫn khởi động được khi zero_trust vắng mặt (cho đến khi MT-A3 đảo
  giá trị mặc định).
- Guard test cho việc tiêu thụ scope (MT-A1).

## 4. Rủi ro

| Mức | Rủi ro | Giảm thiểu |
|---|---|---|
| HIGH | **Operator bị khóa ngoài** khi đảo mặc định (chưa cài cert) | MT-A3 làm cuối; CLI bootstrap làm trước; break-glass qua loopback có tài liệu; chế độ chuyển tiếp `Optional` |
| MEDIUM | Xung đột hợp đồng vòng 1 — hội đồng có thể đảo ngược lại | Chủ dự án xác nhận việc thay thế trước MT-A1; giữ đường plain-HTTP sau cấu hình tường minh, không xóa hẳn |
| MEDIUM | Hỏng dev/CI/bench khi đảo mặc định | profile dev tường minh trong cùng PR (mô phỏng cách tiếp cận AA-P1d) |
| LOW | MT-A1 gây hồi quy trên admin TLS hiện có | thay đổi acceptor là nhánh bổ sung (additive); các đường plain + server-TLS giữ nguyên bộ test riêng |

## 5. Nghiệm thu

- [ ] MT-A1: kết nối không có cert tới admin listener ở chế độ `Required` thất bại ngay tại handshake (đúng yêu cầu kiểm chứng nguyên văn của hội đồng).
- [ ] MT-A1: đóng no-op âm thầm — scope `Admin` hoặc hoạt động, hoặc thất bại validation một cách rõ ràng.
- [ ] MT-A2: CLI bootstrap + hot-swap đã xác minh + hiển thị trên dashboard + runbook.
- [ ] MT-A3: bản cài đặt mặc định mới chỉ phục vụ admin qua mTLS; dev/CI/bench đều xanh.
- [ ] Ghi chú guardrail vòng 1 + memory `project_admin_public_http_contract` đã được cập nhật.
