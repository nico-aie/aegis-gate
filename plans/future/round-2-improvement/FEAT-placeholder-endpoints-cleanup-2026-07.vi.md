> 🇻🇳 Bản dịch tiếng Việt của [FEAT-placeholder-endpoints-cleanup-2026-07.md](FEAT-placeholder-endpoints-cleanup-2026-07.md) — bản gốc tiếng Anh là source of truth.

# FEAT — Placeholder endpoint (endpoint giữ chỗ, chưa có logic thật): hoàn thiện hoặc gỡ bỏ

> **Loại:** FEAT/chore (committee round-2 🔴3) · **Trạng thái:** ☐ Chưa bắt đầu — lập kế hoạch 2026-07-04
> **Tiền tố Track ID:** `PE-<1–3>` · Đã rà soát và xác minh 2026-07-04 trên toàn bộ route table admin
> (`admin_dispatch.rs:59-617`, `admin_get.rs:111-1443`) + control plane (`interop/control.rs`).

**Mục tiêu (theo tinh thần, không theo câu chữ):** mọi endpoint nằm sau auth-gate hoặc làm việc thật sự hoặc không
tồn tại. Không có JSON "coming soon" phía sau màn đăng nhập, không có route đã đăng ký nhưng chết, không có trường dữ liệu nói dối.

---

## 1. Danh sách kiểm kê đã xác minh (danh sách đầy đủ — không còn mục nào khác đủ điều kiện)

| # | Endpoint | Hiện tại | Hướng xử lý (đề xuất) |
|---|---|---|---|
| 1 | `GET /api/threat-intel/feeds` (`admin_get.rs:620-627`) | Hardcode `{"feeds":[],"configured_in_yaml":false,...}`; comment nói rằng nó đọc `cfg.threat_intel` — **trường config đó không hề tồn tại** | **GỠ BỎ** endpoint + tile tương ứng trên dashboard. Chỉ thêm lại khi một tính năng threat-intel thật sự được ship. |
| 2 | `GET /api/gitops/status` (`admin_get.rs:1218` → `tracking.rs:535-541`) | Luôn trả `GitopsStatusResponse::placeholder()`; module gitops đã bị xóa | **GỠ BỎ** endpoint, bỏ phần gộp (fold-in) gitops khỏi `/api/tracking/snapshot` (`tracking.rs:594`), bỏ UI. |
| 3 | `GET /api/analytics/query` (`admin_get.rs:702-711` → `analytics.rs:140-186`) | 503 khi chưa cấu hình; **trả vỏ rỗng ngay cả khi đã đặt `admin.prometheus_url`** ("upstream-proxy call lands in a follow-up") | **HOÀN THIỆN** — hiện thực lời gọi proxy tới Prometheus (nhỏ, phần plumbing + các kiểu response đã có sẵn). Phục vụ cho track `security-analytics-and-reporting.md`. Nếu từ chối làm: trả 501 trung thực + ẩn UI. |
| 4 | `GET /api/audit/witness` (`admin_get.rs:679-681`) | Chỉ còn schema; phần HMAC sign/verify đã bị xóa (`witness.rs:1-22`); không có gì gọi `WitnessState::update` | **GỠ BỎ** endpoint + UI. Witness/anchoring thật sự là một follow-up thuộc `security-analytics` / audit-durability, không phải một stub. |
| 5 | `GET /api/cold-tier` (`admin_get.rs:984-988` → `logging.rs:60-90`) | Danh sách sink là thật; `delivery:"unknown"` hardcode cho từng sink | **HOÀN THIỆN** — nối các bộ đếm delivery theo từng sink (ok/error/last-success lấy từ các sink task). Rẻ và là tín hiệu vận hành thực sự hữu ích. Fallback: bỏ trường này. |
| 6 | `render_cert_renew` (`tracking.rs:623-631`) | Luôn trả `405`; **không được đăng ký trên route nào** — dead code (code chết) | **XÓA** hàm + unit test của nó. |
| 7 | `GET /api/geoip/status` (`admin_get.rs:634-660`) | Thật, trừ `indicator_count: 0` bị hardcode (dòng 651) | **HOÀN THIỆN** (nối số đếm thật) hoặc bỏ trường. Cả hai hướng đều chỉ một dòng code. |

**Đã xác minh KHÔNG phải placeholder (để yên):** các endpoint copilot (thật, trả 503 trung thực khi thiếu
feature `llm`), các fallback `::placeholder()` có điều kiện cho `/api/slo|cluster|certs|alerts`
(dữ liệu live khi đã được nối; chỉ rỗng trong bundle single-node/test), `/api/analytics/latency*`
`/route-activity` `/routes` (chỉ rỗng khi window chưa được cài đặt), toàn bộ `/__waf_control/*`
(thật). Đừng "sửa" những mục này.

## 2. Phân giai đoạn

### PE-1 — các mục gỡ bỏ (#1, #2, #4, #6) · **S**
Một PR duy nhất. Với từng mục, xử lý cùng nhau: endpoint + đăng ký route + tile/panel dashboard (`[[project_dashboard_js_hook_safety]]`:
phải rebuild binary mới thấy thay đổi JSX; chạy acorn hooks guard). Ghi chú các mục gỡ bỏ trong tài liệu phản hồi
gửi committee ("đã gỡ bỏ bề mặt chưa hoàn thiện" là một cách giải quyết chấp nhận được — và trung thực).

### PE-2 — các mục hoàn thiện (#3, #5, #7) · **S–M**
- #3 analytics/query: hiện thực lời gọi HTTP tới Prometheus (tôn trọng `admin.prometheus_url`,
  có timeout, lỗi → envelope 502/503 trung thực). Hỗ trợ cả range query lẫn instant query.
- #5 cold-tier: trạng thái delivery theo từng sink lấy từ state của sink task (bộ đếm delivered/error + timestamp
  lần thành công gần nhất). Làm nổi bật câu chuyện audit-durability từ `FEAT-audit-coverage-gaps-2026-07.vi.md`.
- #7 geoip: nối `indicator_count` từ DB/country list đã được nạp.

### PE-3 — regression guard (chốt chặn hồi quy) · **S**
- Sweep trong CI/test: duyệt route table để khẳng định mọi handler đã đăng ký đều truy cập được từ
  dashboard hoặc từ bề mặt API có tài liệu, và grep-guard chống các giá trị trả về `"coming soon"`/`placeholder()`
  trên các route auth-gated mới thêm. Tránh để round-3 lại phát hiện thêm một loạt mới.

## 3. Rủi ro

| Mức | Rủi ro | Giảm thiểu |
|---|---|---|
| MEDIUM | Các consumer bám wire-format (script bên ngoài) gọi vào endpoint đã bị gỡ | các endpoint đều được gate bằng admin session + không được tài liệu hóa ra bên ngoài; ghi chú trong CHANGELOG; 404 là đúng cho endpoint đã gỡ |
| LOW | Dashboard trắng trang do sửa JSX | rebuild binary + guard `lint-hooks.mjs` + smoke thủ công từng trang bị đụng tới |
| LOW | #3 phình phạm vi thành tier analytics đầy đủ | chỉ làm lời gọi proxy; store Tier-2 vẫn nằm ở `security-analytics-and-reporting.md` |

## 4. Tiêu chí nghiệm thu

- [ ] 7 mục được xử lý dứt điểm (gỡ bỏ hoặc hoạt động thật sự) — không mục nào còn trả dữ liệu tĩnh/nói dối.
- [ ] Dashboard không còn tile nào dựa trên endpoint đã bị gỡ.
- [ ] Guard của PE-3 đã nằm trong CI.
- [ ] Cập nhật ghi chú về độ cũ (staleness) trong `plans/archive/unwired-stubs-catalog.md` để tham chiếu tới đợt rà soát này.
