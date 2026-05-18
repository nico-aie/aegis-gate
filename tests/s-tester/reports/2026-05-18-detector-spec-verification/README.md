---
id: 2026-05-18-detector-spec-verification
date: 2026-05-18T00:00Z
purpose: Verify từng detector trong aegis-security có đúng (A) thể lệ Hackathon §5.x, (B) wire với Dashboard config qua endpoint PUT/POST, (C) hot-reload ≤10s, (D) không vi phạm §9 forbidden patterns
scope: aegis-security detectors + aegis-control dashboard API + aegis-core config schema
methodology: source-review (4 agent verify song song, cross-check với spec)
---

# Verification — Detector vs Spec vs Dashboard config

> **Câu hỏi gốc của user**: "đọc lại rule trong Hackathon_Doc, sau đó check giúp tôi các detector hoạt động đúng với config Dashboard hay không, và đúng với thể lệ cuộc thi không, ví dụ như Ddos detector, tôi code như hiện tại có đúng yêu cầu của ban tổ chức không?"

## TL;DR

**Trả lời trực tiếp về DDoS**: **CHƯA ĐÚNG**. Code DDoS hiện tại có 3 gap nghiêm trọng so với §5.2 #03 + §5.8:

1. ❌ **`DdosDetector::check(ip)` thiếu param `tier`** → không bao giờ đọc được `cfg.tier_overrides` mà schema config đã định nghĩa.
2. ❌ **Không có nhánh fail-close cho tier CRITICAL** — khi backend rate-limiter lỗi (`Err(_)`), `data_plane.rs:417-421` fail-open cho **mọi** tier (kể cả `/login`, `/withdrawal`).
3. ❌ **Dashboard `DdosPutBody` thiếu trường `tier_overrides`** → operator không thể tune ngưỡng per-tier qua UI.

Đây chính là findings F-CRITICAL-005 từ audit security ngày 2026-05-17 — status PARTIAL vì schema config có `tier_overrides`, nhưng runtime/dashboard không wire. Chi tiết: [01-ddos-detailed.md](01-ddos-detailed.md).

**Trả lời tổng quát về tất cả detector**:

| Nhóm | Detector | Spec | Dashboard | Hot-reload | §9 | Verdict |
|---|---|:-:|:-:|:-:|:-:|---|
| Volumetric | DDoS §5.2 #03 | ❌ | ⚠️ (no tier knob) | ✅ | ✅ | **FAIL** |
| Volumetric | Rate Limit §5.2 #02 | ⚠️ (IP only) | ✅ | ✅ | ✅ | **PARTIAL** |
| Volumetric | Brute Force §5.3 | ❌ (no spraying) | ❌ (on/off only) | ❌ | ✅ | **FAIL** |
| Volumetric | Blacklist §5.2 #06 | ⚠️ (no feed load) | ✅ | ✅ | ✅ | **PARTIAL** |
| Identity | Device Fingerprint §5.2 #08 | ⚠️ (sort + no GREASE) | N/A | N/A | ✅ | **PARTIAL** |
| Identity | Behavioral §5.2 #09 | ⚠️ (4/6 signals) | ❌ (hardcoded) | ❌ | ✅ | **PARTIAL** |
| Identity | Velocity §5.2 #10 | ✅ | ⚠️ | ⚠️ | ✅ | **PARTIAL** |
| Identity | Bots §5.2 #05 | ⚠️ (no ASN, no JA4 read) | N/A | N/A | ✅ | **PARTIAL** |
| Identity | Risk Engine §5.5 | ❌ (per-IP only, spec yêu cầu {IP+device+session}) | ✅ | ✅ | ✅ | **PARTIAL** |
| Identity | Challenge §5.2 #04 | ✅ | N/A | N/A | ✅ | **PASS** |
| OWASP | SQLi §5.3 | ✅ | ✅ | ✅ | ✅ | **PASS** |
| OWASP | XSS §5.3 | ✅ | ✅ | ✅ | ✅ | **PASS** |
| OWASP | Path Traversal §5.3 | ✅ | ✅ | ✅ | ✅ | **PASS** |
| OWASP | SSRF §5.3 | ✅ | ✅ | ✅ | ✅ | **PASS** |
| OWASP | Header Injection §5.3 | ✅ | ✅ | ✅ | ✅ (đã fix F-CRITICAL-012) | **PASS** |
| OWASP | Recon §5.3 | ✅ | ✅ | ✅ | ✅ | **PASS** |
| OWASP | Body Abuse §5.3 | ✅ | ✅ | ✅ | ✅ | **PASS** |
| Engine | Rule Engine §5.4 | ✅ | ✅ | ✅ | ⚠️ (linter chặn RateLimit) | **PASS** |
| Engine | Response Filter §5.7 | ⚠️ (thiếu prefix + body cap) | ✅ | ✅ | ✅ | **PARTIAL** |
| Engine | Smart Cache §5.2 #07 | ❌ (no per-tier vary, no bypass) | ❌ (no `/api/cache`) | N/A | ✅ | **FAIL** |
| Engine | Graceful Degradation §5.8 | ⚠️ (no panic-catch, no timeout-bump) | N/A | N/A | ✅ | **PARTIAL** |

## Đếm

- **PASS**: 8/21 (38%) — toàn bộ OWASP detectors + Rule Engine + Challenge
- **PARTIAL**: 9/21 (43%) — chủ yếu identity + đa số volumetric
- **FAIL**: 4/21 (19%) — DDoS, Brute Force, Risk Engine (per-IP only), Smart Cache

## Cấu trúc report

- [01-ddos-detailed.md](01-ddos-detailed.md) — Deep dive theo yêu cầu user (DDoS làm ví dụ)
- [02-volumetric.md](02-volumetric.md) — DDoS + Rate Limit + Brute Force + Blacklist
- [03-identity.md](03-identity.md) — Fingerprint + Behavior + Velocity + Bots + Risk + Challenge
- [04-owasp-injection.md](04-owasp-injection.md) — 8 detector §5.3
- [05-rule-filter-cache.md](05-rule-filter-cache.md) — Rule Engine + Response Filter + Smart Cache + Graceful Degradation

## Ghi chú phương pháp

- 4 agent verify song song trên cùng code base, sau đó cross-check.
- Agent đôi khi quá lạc quan (ví dụ JA4 sort được khen là "deterministic" trong khi spec JA4 nguyên gốc **KHÔNG** sort cipher và **PHẢI** strip GREASE — sort_unstable hiện tại làm hỏng chỉ số `_cipher_hash` của JA4). Mọi PASS/FAIL trong bảng đã được cross-check với spec gốc + finding cũ.
- Chỉ check qua code review, không chạy test runtime trong session này.
- Tham chiếu finding cũ:
  - `2026-05-17-security-audit/F-CRITICAL-NNN-*.md` — 15 finding original
  - `2026-05-18-fix-verification/SUMMARY.md` — 60% fixed, 25% chưa fix, 15% partial
