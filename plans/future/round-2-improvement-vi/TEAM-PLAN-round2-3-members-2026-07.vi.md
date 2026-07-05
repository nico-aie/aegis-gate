# KẾ HOẠCH TRIỂN KHAI ROUND 2 — Nhóm 3 người

> **Ngày lập:** 2026-07-04 · **Trạng thái:** ☐ Chờ kick-off
> **Phạm vi:** toàn bộ feedback round-2 của committee, đã được verify từng mục so với code
> (xem [COMMITTEE-ROUND2-response-2026-07-04.vi.md](COMMITTEE-ROUND2-response-2026-07-04.vi.md)).
> Bản gốc tiếng Anh của từng plan là source of truth; bản `.vi.md` để đọc cho nhanh.

---

## 1. Phân công

| Ai | Track | Plan chi tiết | Bao gồm |
|---|---|---|---|
| **Member 1** | 🔴 mTLS cho admin channel (`MT-A1 → MT-A3`) | [FEAT-admin-mtls-default-2026-07.vi.md](FEAT-admin-mtls-default-2026-07.vi.md) | Code + unit test + **regression test suite** |
| **Member 2** | 🔴 Bắt buộc 2FA (`TF-1 → TF-3`) + phần enrollment tiền đề (AA-P1b) | [FEAT-2fa-enforcement-2026-07.vi.md](FEAT-2fa-enforcement-2026-07.vi.md) + `plans/issues/FEAT-admin-accounts-p1-self-service-hardening.md` (stage P1b) | Code + unit test + **regression test suite** |
| **Member 3 (Nico)** | Toàn bộ phần còn lại + review/merge + quyết định | Placeholder cleanup (`PE`) · Audit gaps (`AU`) · FP tuning (`FP`) · Ops validation (`OV`) · Egress design doc (`EG-1`) | Code + test + điều phối |

**Lý do chia như vậy:** hai track 🔴 (mTLS, 2FA) độc lập với nhau về mặt code (một bên là tầng
TLS acceptor `run.rs`/`accept.rs`/`tls_policy.rs`, một bên là tầng login `login.rs`/`totp.rs`),
nên 2 người làm song song được. Phần còn lại nhiều mảng nhỏ, rải rác, cần người nắm toàn cảnh
repo — hợp với Member 3.

## 2. Điểm phối hợp bắt buộc (đọc kỹ — đây là chỗ dễ giẫm chân nhau)

| # | Xung đột | Cách xử lý |
|---|---|---|
| C1 | **`login.rs` bị đụng bởi cả M2 (TF-1/TF-2) và M3 (AU-1: audit event cho login/logout)** | M2 merge TF-1 trước, M3 rebase AU-1 lên sau. Thống nhất trước "event taxonomy" (tên event, field) để M2 chừa sẵn chỗ gọi hook. |
| C2 | **`accept.rs` bị đụng bởi M1 (acceptor) và M2 (đường dựng identity `accept.rs:527-535`)** | Vùng khác nhau trong file — PR nhỏ, merge sớm, ai rebase sau thì tự resolve. Báo nhau trên channel khi động vào file này. |
| C3 | **Mâu thuẫn round-1 vs round-2** (round 1 yêu cầu admin plain-HTTP; round 2 yêu cầu mTLS mặc định) | Nico chốt với committee **trước khi M1 làm MT-A3** (flip default). MT-A1/MT-A2 **không** bị chặn — chỉ làm cho config đã bật hoạt động thật, không đổi default. |
| C4 | **TF-1 (bắt buộc 2FA) cần luồng enrollment trên web (AA-P1b)** để không khoá người dùng | M2 làm AA-P1b trước TF-1. Nếu kẹt thời gian: TF-1 dùng fallback báo lỗi hướng dẫn chạy `waf admin enroll-totp` (vẫn enforce được, UX kém hơn). |
| C5 | **Dev/CI/bench sẽ vỡ khi flip default** (cả mTLS lẫn 2FA) | Mỗi PR flip default phải sửa `config/dev.yaml`, Makefile, QUICKSTART, bench/e2e **trong cùng PR**. |
| C6 | Per-sink delivery counter dùng chung bởi PE-2 (`/api/cold-tier`) và AU-2 (metrics) | M3 làm cả hai — tự thống nhất, làm counter một lần dùng hai chỗ. |

## 3. Lộ trình đề xuất (3 tuần + 1 tuần validation chung)

### Tuần 1 — nền móng, không chờ nhau
- **M1:** `MT-A1` — wire `DownstreamMtlsScope::Admin` vào admin acceptor; boot-validation cho
  config sai; guard test. *(Bắt đầu được ngay, không phụ thuộc C3.)*
- **M2:** `AA-P1b` — TOTP enroll/confirm qua web + recovery-code login (consume-once).
- **M3 (Nico):** `PE-1` + `PE-2` (dọn 7 placeholder endpoints); chốt C3 với committee;
  review PR của M1/M2.

### Tuần 2 — enforcement
- **M1:** `MT-A2` — CLI `waf admin mtls bootstrap`, hot-swap trust store, hiển thị trên
  dashboard, runbook + **regression suite đầy đủ (xem §4)**.
- **M2:** `TF-1` (flag `require_totp`, default true, luồng enrollment-required) + `TF-2`
  (CLI `disable-totp`, recovery = 2FA hợp lệ) + **regression suite (xem §4)**.
- **M3:** `AU-1` (audit event cho login/logout/failed-login/`reset_state` — rebase sau TF-1)
  + `AU-2` (drop metrics, fsync knob) + `PE-3` (guard CI).

### Tuần 3 — flip default + đo đạc
- **M1:** `MT-A3` — flip default (sau khi C3 đã chốt); sửa dev/CI/bench cùng PR.
- **M2:** `TF-3` — sửa docs cho đúng thực tế + gói bằng chứng cho committee (transcript login
  bị từ chối khi thiếu 2FA trên config mặc định).
- **M3:** `AU-3`/`AU-4` (chốt các caveat của risk decay + evidence pack) + `FP-1`
  (corpus + harness đo FP) + `EG-1` (design doc egress).

### Tuần 4 — validation chung (cả 3 người)
- Chạy [PLAN-ops-validation-realistic-2026-07.vi.md](PLAN-ops-validation-realistic-2026-07.vi.md):
  - **OV-1** (load + attack mix): M3 dựng, cả nhóm quan sát.
  - **OV-2** (admin workflows): M1 drive drill mTLS/cert-swap, M2 drive drill login/TOTP/rotation,
    M3 drive drill rule/mode/config.
  - **OV-3** (failure/recovery): cả nhóm, mỗi người ghi evidence cho drill mình phụ trách.
- Bug tìm được trong tuần này = issue mới, triage chung, ưu tiên trước round 3.

## 4. Yêu cầu testing (bắt buộc, RED-first theo TDD)

### Chung cho mọi PR (Definition of Done)
- [ ] Test viết trước, fail trước, xanh sau (RED → GREEN).
- [ ] `cargo test --workspace` xanh toàn bộ + **không có warning mới** (baseline hiện tại là
      zero-warning — warning mới = regression).
- [ ] Cross-review: PR của M1 do M2 review và ngược lại; Nico review + merge cuối.
- [ ] Tick checkbox tương ứng trong file plan khi xong.

### Regression suite — Member 1 (mTLS)
- Handshake **không có** client cert → bị từ chối ở mode `Required`; được chấp nhận ở
  `Optional`/`Disabled`. (Test bằng raw TLS client, không dùng HTTP client tự normalize.)
- Cert từ CA lạ → từ chối; đúng CA nhưng SAN ngoài `allowed_sans` → từ chối.
- Hot-swap trust anchor có hiệu lực ở handshake kế tiếp, không cần restart.
- **Đường cũ không vỡ:** admin plain-HTTP (khi chưa bật) và admin server-TLS-only giữ nguyên
  hành vi — test riêng cho từng đường.
- Boot validation: scope `Admin` + thiếu `admin.tls` → lỗi config rõ ràng.
- Guard test: `DownstreamMtlsScope::Admin` phải có consumer (chống tái diễn "silent no-op").

### Regression suite — Member 2 (2FA)
- Config mặc định → login chỉ có password **bị chặn** / rơi vào trạng thái enrollment-required.
- `require_totp: false` (opt-out tường minh) → hành vi cũ giữ nguyên (guard chống vỡ dev).
- Session ở trạng thái enrollment-required **không gọi được** API nào khác (enumerate route table).
- Recovery code: dùng được đúng 1 lần, lần 2 fail; được tính là 2FA hợp lệ.
- Cả **hai** đường dựng identity (`accept.rs:527` và `lib.rs:400`) enforce giống nhau.
- Suite RFC 6238 / argon2 / rate-limit / session hiện có giữ xanh.

### Member 3
- `PE-3`: guard CI chống placeholder endpoint mới.
- `AU`: event nghiệm thu theo chain (login flood → event gộp, không phải 1-event-1-request;
  `reset_state` có event **trước** khi wipe).
- `FP-1`: harness precision/recall chạy bằng `cargo test`, baseline commit vào repo.
- Lưu ý khi test detector: data plane nhận URI **raw percent-encoded** — viết unit test trên
  raw form, đừng tin report của harness Python.

## 5. Quy ước làm việc

- **Branch:** `feat/mtls-admin-*` (M1), `feat/2fa-enforce-*` (M2), M3 theo prefix từng track.
  Base: `develop`. PR nhỏ, mỗi stage một PR.
- **Commit message:** conventional commits (`feat:`, `fix:`, `test:`, `chore:`).
- **Không `git add -A`** — stage từng file tường minh (đã có tiền lệ quét nhầm file lạ vào commit).
- **Sync:** stand-up ngắn đầu tuần + báo ngay trên channel khi đụng `login.rs`/`accept.rs`/`run.rs`
  (các file chung — xem §2).
- **Escalation:** vướng quyết định về hướng (default posture, break-glass, disposition endpoint)
  → hỏi Nico, đừng tự chọn rồi code tiếp.

## 6. Mốc nghiệm thu trước round 3

- [ ] 🔴1: kết nối không có client cert bị từ chối trên admin listener (demo được cho committee).
- [ ] 🔴2: cài đặt mặc định không thể đăng nhập admin nếu thiếu yếu tố thứ hai (kèm transcript).
- [ ] 🔴3: 7 placeholder endpoints đã "complete hoặc remove", có guard CI.
- [ ] 🟡3: evidence pack — risk decay đã có sẵn (chứng minh bằng test), audit gaps đã vá.
- [ ] 🟡1: báo cáo FP trước/sau + quyết định default-ON có số liệu.
- [ ] 🟡5: runbook + evidence các drill tuần 4.
- [ ] 🟡4: design doc egress được duyệt (chưa cần code).
