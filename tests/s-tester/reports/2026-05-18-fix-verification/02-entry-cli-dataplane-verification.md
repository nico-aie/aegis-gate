---
folder: 2026-05-17-entry-cli-dataplane-audit/
agent: Agent B (verification)
date: 2026-05-18T00:00Z
status: 4 FIXED / 0 PARTIAL / 0 NOT_FIXED (4 total) — ✅ HOÀN HẢO
---

# entry-cli-dataplane fix verification — chi tiết

**Tất cả 4 CRITICAL đã fix đúng**. Không có gì cần fix tiếp trong folder này.

## Status table

| ID | Title | Status | Evidence |
|---|---|---|---|
| F-CRITICAL-001 | `/__waf_control/*` thiếu 6 §5 headers | **FIXED** | `aegis-proxy/src/accept.rs:1193-1217` — response qua `stamp_interop_response(...)` với `DecisionTag::allow()` trước khi return. Comment lines 1193-1206 explicit cite F-CRITICAL-001. |
| F-CRITICAL-002 | log_only bypass cho rate-limit/strike/blacklist/risk | **FIXED** | 4 block branches đều consult `mode_for_rule`: blacklist `data_plane.rs:271-288`, strike `:315-332`, rate-limit `:486-508`, risk-score `:870-899`. LogOnly path fall-through to upstream qua `log_only_intent` carrier. |
| F-CRITICAL-003 | Audit sink fail-silent at boot | **FIXED** | `aegis-proxy/src/run.rs:1767-1794` — open failure trigger `mkdir_p` retry, sau đó `panic!` với operator-actionable message. Không còn silent `None`. (Note: dùng `panic!` thay vì `Err(WafError::Config)` — vẫn fail-loud, semantic đúng) |
| F-CRITICAL-004 | `MAX_BODY_BYTES = 1 MiB` hard-coded | **FIXED** | Const removed. `data_plane.rs:186` đọc `upstream_ctx.max_body_bytes`. `proxy.rs:125,194` expose field. `aegis-core/src/config.rs:343-355` định nghĩa `cfg.proxy.max_body_bytes` với default 10 MiB. |

## Đánh giá

Folder này **100% đạt** — không cần fix gì thêm.

Note nhỏ:
- F-CRITICAL-003: Dùng `panic!` thay `Err(...)` — semantic OK (fail-loud), nhưng nếu muốn graceful boot error logging, có thể chuyển sang Err sau.
- F-CRITICAL-004: Default 10 MiB (suggested ≥16 MiB) — vẫn là **config-driven** nên đạt spec; operator có thể tune.

Không có vấn đề gì cần escalate.
