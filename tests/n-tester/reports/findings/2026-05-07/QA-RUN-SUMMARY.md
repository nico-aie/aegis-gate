# Aegis-Gate QA Run Summary — 2026-05-07

**Mode:** Functional (auth + API sweep + 17-page coverage + SOC scenarios + security regression)  
**Tester:** Claude Aegis-WAF-Tester skill (automated, Cowork session)  
**WAF version:** 0.1.0 · build session 137+  
**Interop contract:** EN_waf_interop_contract_v2.3.md  
**Run date:** 2026-05-07  

---

## Finding counts

| Severity | Count |
|---|---|
| CRITICAL | 2 |
| HIGH | 3 |
| MEDIUM | 9 |
| LOW | 4 |
| **Total** | **18** |

---

## Per-page coverage matrix

| Page | Mounts | Data | Controls | Empty state | Notes |
|---|---|---|---|---|---|
| Overview | ✓ | ✓ | ✓ | ✓ | No in-page alert banner (LOW) |
| Live Feed | ✓ | ✓ | ✓ | ✓ | Pivot link drops query params (HIGH) |
| Incidents | ✓ | ✓ | ✓ | ✓ | — |
| Investigation | ✓ | ✓ | ✓ | ✓ | Pivot link from Live Feed broken (HIGH) |
| Top Attackers | ✓ | ✓ | ✓ | ✓ | Dev message in empty state (LOW) |
| Threat Intel | ✓ | ✓ | ✓ | ✓ | — |
| Rules | ✓ | ✓ | ✓ | ✓ | Delete confirm freezes tab (MEDIUM) |
| Detectors | ✓ | ✓ | ✓ | ✓ | — |
| Access Lists | ✓ | ✓ | ✓ | ✓ | Missing search + expiry picker (MEDIUM) |
| Routing & Upstreams | ✓ | ✓ | ✓ | ✓ | `#/routing` URL broken (MEDIUM) |
| Compliance | ✓ | ✓ | ✓ | ✓ | — |
| Performance | ✓ | ✓ | ✓ | n/a | Confirms AI over-fire visible (77% block) |
| Health & SLOs | ✓ | ✓ | ✓ | ✓ | SLO at 0% budget (secondary AI-001) |
| Audit Trail | ✓ | ✓ | ✓ | ✓ | — |
| Scaling | ✓ | ✓ | partial | ✓ | Mode override controls absent (MEDIUM) |
| Settings | ✓ | ✓ | partial | ✓ | Sessions/break-glass/integrations/certs not in UI (MEDIUM) |
| Reports | ✓ | ✓ | partial | ✓ | 2/4 report types "not wired yet" (MEDIUM) |
| Help & Guide | ✓ | ✓ | ✓ | ✓ | — |

---

## SOC analyst UX scores (S1–S8)

| Scenario | Score | Notes |
|---|---|---|
| S1 "I just got paged" | 3/5 | No in-page alert banner; "UNKNOWN" badge unexplained |
| S2 "Who's attacking me?" | 3/5 | Empty state shows dev `make mock-load-attacks` message |
| S3 "Which rule fired?" | 3/5 | Manual pivot works; cross-nav from Live Feed broken |
| S4 "Add a whitelist entry" | 4/5 | Inline form works; no expiry picker |
| S5 "Respond to SLO breach" | 4/5 | Runbook links present; VipTalk channel returning 401 |
| S6 "Understand why X was blocked" | 5/5 | Detail drawer is excellent; Copy as cURL, Block IP, Whitelist |
| S7 "Change detector sensitivity" | 5/5 | Tier/mask/AI UI clear and functional |
| S8 "Ship a config change safely" | 4/5 | Config history with version numbers; no pre-apply diff |
| **Average** | **3.9/5** | |

---

## Security regression probe results

| Probe | Expected | Result | Pass |
|---|---|---|---|
| clean GET / (no Referer) | allow (200) | 200 | ✓ |
| clean /api/users/1 (no Referer) | allow (200/404) | 404 | ✓ |
| SQLi `/login?u=1'+OR+'1'='1` | block (403) | 403 (sqli+ai) | ✓ |
| XSS `/?q=<script>alert(1)</script>` | block (403) | 403 (xss+ai) | ✓ |
| Path traversal `/files?p=../../../../etc/passwd` | block (403) | 403 (path_traversal+ai) | ✓ |
| Recon `/.env` | block (403) | 403 (recon_path+ai) | ✓ |
| Recon `/.git/config` | block (403) | 403 | ✓ |
| SSRF `/?url=http://127.0.0.1/admin` | block (403) | 403 (ssrf) | ✓ |
| SSRF `/?url=http://192.168.1.1/secret` | block (403) | 403 (ssrf) | ✓ |
| clean `/api/status` (no Referer) | allow (200) | 403 (AI FP) | ✗ |
| clean `/favicon.ico` (no Referer) | allow (200) | 403 (AI FP) | ✗ |
| clean `/static/app.js` (no Referer) | allow (200) | 403 (AI FP) | ✗ |

**Note:** AI false-positive rate at threshold 0.5 is ~77% across all traffic (confirmed via Performance page block ratio).

---

## Interop contract compliance (v2.3)

| Requirement | Status | Notes |
|---|---|---|
| CC-T1 `GET /__waf_control/capabilities` on :8080 | ❌ FAIL | 403 — SSRF detector fires on path; not intercepted before pipeline |
| CC-T2 `POST /__waf_control/reset_state` on :8080 | ❌ FAIL | 403 — plus evicts admin sessions on :9443 |
| CC-T3 `POST /__waf_control/set_profile` on :8080 | ❌ FAIL | 403 — SSRF+AI fires |
| CC-T4 `POST /__waf_control/flush_cache` on :8080 | ❌ FAIL | 403 |
| All endpoints accessible on :9443 | ✓ PASS | All return 200 with `X-Benchmark-Secret` |
| `X-WAF-Request-ID` response header | ⚠️ UNVERIFIED | CORS limitation; cannot read response headers from browser |
| `X-WAF-Action` response header | ⚠️ UNVERIFIED | CORS limitation |
| `X-WAF-Risk-Score` response header | ⚠️ UNVERIFIED | CORS limitation |
| `X-WAF-Detectors` response header | ⚠️ UNVERIFIED | CORS limitation |
| `X-WAF-Mode` response header | ⚠️ UNVERIFIED | CORS limitation |
| `X-WAF-Tier` response header | ⚠️ UNVERIFIED | CORS limitation |
| `waf_audit.log` JSONL format | ✓ PASS | Correct field names |
| `request_id` UUID v4 format | ⚠️ PARTIAL | Version nibble '4' correct; variant nibble not RFC 4122 compliant |
| `ip` field = TCP peer (not XFF) | ✓ PASS | Confirmed: ip=127.0.0.1 in log, XFF stored separately |

---

## Files

- `findings/2026-05-07/F-CRITICAL-001-interop-control-plane-8080.md`
- `findings/2026-05-07/F-CRITICAL-002-ai-threshold-observe-mode-missing.md`
- `findings/2026-05-07/F-HIGH-001-ssrf-referer-false-positive.md`
- `findings/2026-05-07/F-HIGH-002-investigation-pivot-query-params-dropped.md`
- `findings/2026-05-07/F-HIGH-003-reset-state-evicts-admin-sessions.md`
- `findings/2026-05-07/F-MEDIUM-001-uuid-variant-nibble.md`
- `findings/2026-05-07/F-MEDIUM-002-scaling-mode-override-absent.md`
- `findings/2026-05-07/F-MEDIUM-003-routing-hash-broken.md`
- `findings/2026-05-07/F-MEDIUM-004-settings-features-not-surfaced.md`
- `findings/2026-05-07/F-MEDIUM-005-access-lists-missing-controls.md`
- `findings/2026-05-07/F-MEDIUM-006-reports-not-wired.md`
- `findings/2026-05-07/F-MEDIUM-007-rule-delete-native-confirm.md`
- `findings/2026-05-07/F-MEDIUM-008-scaling-stale-peer-down.md`
- `findings/2026-05-07/F-MEDIUM-009-slo-burn-secondary.md`
- `findings/2026-05-07/F-LOW-001-overview-no-alert-banner.md`
- `findings/2026-05-07/F-LOW-002-unknown-badge-unexplained.md`
- `findings/2026-05-07/F-LOW-003-dev-message-in-prod-ui.md`
- `findings/2026-05-07/F-LOW-004-routing-url-alias.md`
