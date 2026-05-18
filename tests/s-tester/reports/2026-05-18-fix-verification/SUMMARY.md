---
id: 2026-05-18-fix-verification
date: 2026-05-18T00:00Z
test_mode: source-review (verify-fixes)
scope:
  - Verify lại 60 CRITICAL findings từ 5 audit folder ngày 2026-05-17
  - User claim "tất cả bug đã fix" → đối chiếu với code hiện tại
  - 5 agent verification song song, mỗi agent đọc lại file:line gốc + code mới
tester: Claude (5 parallel general-purpose verification agents)
---

# Re-audit verification — 5 audit folder · 60 CRITICAL

## Cấu hình verification

Mỗi agent đọc lại CRITICAL report gốc → check code hiện tại tại đúng
file:line → đối chiếu với spec Hackathon → kết luận FIXED / PARTIAL /
NOT_FIXED kèm bằng chứng code-anchored.

| Agent | Phạm vi | Số CRITICAL kiểm tra |
|---|---|---:|
| A | aegis-core (audit/decision/config schema) | 13 |
| B | entry-cli-dataplane (4 hot-path) | 4 |
| C | proxy-full-audit (H3, admin, dead code, etc.) | 10 |
| D | aegis-control (rule rebuild, healthz, audit search, etc.) | 18 |
| E | aegis-security (detectors, risk, velocity, behavior) | 15 |

---

## Kết quả tổng

| Crate | FIXED | PARTIAL | NOT_FIXED | Tỷ lệ FIXED |
|---|---:|---:|---:|---:|
| entry-cli-dataplane | **4** | 0 | 0 | **100%** ✅ |
| aegis-control | **16** | 1 | 1 | **89%** |
| proxy-full-audit | 7 | 2 | 1 | **70%** |
| aegis-core | 6 | 5 | 2 | **46%** (chỉ 6/13 fully fixed) |
| aegis-security | **3** | 1 | **11** | **20%** ⚠️ |
| **TỔNG** | **36** | **9** | **15** | **60%** |

→ **60% CRITICAL được fix đúng**. 25% chưa fix (15 items). 15% partial (9 items).

---

## ⚠️ Đánh giá tổng

**Tuyên bố "tất cả bug đã fix" KHÔNG đúng**. Cụ thể:

### 🚨 Crate có vấn đề nhất — `aegis-security` (3/15 = 20% FIXED)

Đây là crate **chứa logic phát hiện tấn công** — chiếm phần lớn điểm
Security Effectiveness rubric (40/120). 11/15 CRITICAL **chưa fix**:

| ID | Title | Tác động |
|---|---|---|
| F-CRITICAL-001 | RiskTracker keyed by IpAddr only (vẫn không có device_fp / session) | §5.5 violation |
| F-CRITICAL-002 | Rate limit per-IP only (không có per-user-session) | §5.2 #02 violation |
| F-CRITICAL-003 | velocity.rs không có Login→OTP→Deposit sequence engine | §5.2 #10 + Attack Battle 06 |
| F-CRITICAL-004 | Behavior chỉ có 1/4 signal (thiếu zero-depth, missing Referer, <50ms) | §5.2 #09 |
| F-CRITICAL-007 | Canary không call `auto_block` — chỉ set max score, IP không bị chặn | §5.5 |
| F-CRITICAL-008 | Pipeline::inbound vẫn chỉ chạy rule engine — bypass detector/risk/canary | Architecture rubric |
| F-CRITICAL-010 | Không có device→IP reverse map → không detect được same-device-different-IP | §5.2 #08 + Attack Battle 04 |
| F-CRITICAL-011 | JA4 vẫn `sort_unstable` + không strip GREASE → Chrome unstable device ID | §5.2 #08 |
| F-CRITICAL-013 | response_filter vẫn chỉ strip 2 header (server + x-powered-by) | §5.7 violation |
| F-CRITICAL-014 | brute_force vẫn per-IP POST-only, không có per-user / per-device | §5.3 OWASP |
| F-CRITICAL-015 | bots.rs vẫn không đọc `ja4_fingerprint` field; không có ASN | §5.2 #05 + #08 |

### 🟠 Crate có vấn đề thứ hai — `aegis-core` (6/13 = 46% FIXED)

Schema-side source của nhiều bug cross-crate. Kết quả mixed:

✅ Đã fix tốt: F-CRITICAL-007 (thresholds 30/70), F-CRITICAL-008
(DdosConfig tier_overrides), F-CRITICAL-009 (RlScope 6 variants),
F-CRITICAL-010 (fail_mode_by_tier), F-CRITICAL-011 (per-tier mask),
F-CRITICAL-012 (canary_paths).

❌ Vẫn còn vấn đề:
- **F-CRITICAL-003 / 004 (NOT_FIXED)**: AuditEvent struct vẫn thiếu
  `method`, `path`, `mode` fields; `action: String` chưa thành enum.
  Author tự ghi trong docstring "Still outstanding: filed for
  follow-up commit" — admin tự nhận chưa fix. §6 contract violation
  trên EVERY audit event.
- F-CRITICAL-001 / 002 / 005 / 006 / 013 (PARTIAL): wire-shape đã
  đúng (qua serde rename / serialize_with) nhưng Rust type chưa
  refactor.

### 🔴 H3 bypass (proxy-full-audit F-CRITICAL-001) vẫn chưa fix

`listener/http3.rs:290` vẫn gọi `crate::proxy::handle_request` (bare
router) → **mọi request QUIC bypass toàn bộ security pipeline**.
§5 / §6 / §10 contract fail trên QUIC surface.

### 🟡 Compliance modes (aegis-control F-CRITICAL-002) vẫn theater

`COMPLIANCE_PINNED = &[]` empty; `min_tls_version` / `disallow_algorithms`
không có TLS-stack caller. Operator bật "FIPS mode" → không có hiệu
ứng thực. Round-1 "Tính hiệu lực" Pass/Fail risk.

---

## Mapping ngược về Hackathon scoring

Ước lượng impact của các bug CHƯA FIX:

| Tiêu chí | Điểm | Bug NOT_FIXED ảnh hưởng | Ước lượng còn lại |
|---|---:|---|---:|
| Security Effectiveness | 40 | aegis-security 11 items + H3 bypass | ~25/40 (62%) |
| Performance | 20 | (ít bị ảnh hưởng) | ~17/20 (85%) |
| Intelligence & Adaptiveness | 20 | RiskTracker key, velocity, behavior, canary, ja4 | ~10/20 (50%) |
| Architecture & Code Quality | 15 | Pipeline::inbound bypass, audit schema thiếu | ~9/15 (60%) |
| Extensibility | 10 | partial (config rule scope OK) | ~7/10 (70%) |
| Dashboard UI/UX | 10 | aegis-control fixed tốt | ~9/10 (90%) |
| Deployment & Operability | 5 | OK | ~4/5 (80%) |
| **Tổng** | **120** | | **~81/120 (67.5%)** |

So với baseline trước khi fix (~58/80 = 72.5% trong 3 rubric chính
sau đo regex-only dataset replay) — fixes đã giúp đáng kể, nhưng
còn nhiều gap. Cần priority tiếp theo:

1. **aegis-security 11 items** (rubric impact lớn nhất)
2. **H3 bypass** (full §5/§6/§10 failure trên QUIC)
3. **Compliance modes wiring** (Round-1 Pass/Fail risk nếu BTC verify thực)
4. **AuditEvent schema** (mọi audit event §6 fail vì thiếu method/path/mode)

---

## File trong folder này

```
SUMMARY.md                                     ← file này (tổng quan + status table)
01-aegis-core-verification.md                  ← chi tiết Agent A
02-entry-cli-dataplane-verification.md         ← chi tiết Agent B (4/4 FIXED)
03-proxy-full-audit-verification.md            ← chi tiết Agent C
04-aegis-control-verification.md               ← chi tiết Agent D
05-aegis-security-verification.md              ← chi tiết Agent E (vấn đề nhất)
STILL-BROKEN-CRITICAL.md                       ← 15 finding NOT_FIXED gom lại
STILL-BROKEN-PARTIAL.md                        ← 9 finding PARTIAL gom lại
NEXT-STEPS.md                                  ← roadmap fix theo priority
```

Mỗi file dùng để fix tiếp — paste lại CRITICAL số nào còn vấn đề
vào todo, đối chiếu spec, code, expected fix.
