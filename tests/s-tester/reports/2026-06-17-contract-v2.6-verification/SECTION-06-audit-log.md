---
id: 2026-06-17-section-06-audit-log
contract_section: "§6 — Audit Log"
checklist_ids: C-6-*
verdict: PASS (risk_score >100 edge shared with F-V26-003)
test_mode: source-review
---

# §6 — Audit Log

Primary code: `crates/aegis-control/src/interop/audit.rs`,
write site `crates/aegis-proxy/src/admin_dispatch.rs:1344`.

## Required fields & format — ✅ PASS

| ID | Requirement | Result | Evidence |
|----|-------------|--------|----------|
| C-6-01 | `./waf_audit.log` (configurable) | ✅ | `MinimalJsonlSink::open` (`audit.rs:67`); default `./waf_audit.log` present at repo root |
| C-6-02 | append-only JSONL, SIEM-ingestible | ✅ | `OpenOptions append(true)`; one JSON obj + `\n` per `append()`; test `entry_is_one_line_no_internal_newlines` |
| C-6-03 | 8 required fields | ✅ | `MinimalAuditEntry` (`audit.rs:23`): request_id, ts_ms, ip, method, path, action, risk_score, mode |
| C-6-04 | request_id matches header, 8–64 `[A-Za-z0-9._-]` | ✅ | same UUID v4 used for header + entry (`admin_dispatch.rs:1302/1346`) |
| C-6-05 | ts_ms epoch millis integer | ✅ | `chrono::Utc::now().timestamp_millis()` |
| C-6-06 / C-6-14 | ip = TCP peer, NOT XFF | ✅ | `ip: peer.ip().to_string()` (`admin_dispatch.rs:1348`) — peer socket, not header |
| C-6-07 | method uppercase | ✅ | `method.as_str()` (hyper methods are uppercase) |
| C-6-08 | path incl. query | ✅ | `path` carries the request target |
| C-6-09 | action ∈ 6 classes | ✅ | `decision_tag.action.as_str()` |
| C-6-10 | risk_score 0–100 | ⚠️ | shares F-V26-003: same unclamped `effective_risk_score` written here |
| C-6-11 | mode matches `X-WAF-Mode` | ✅ | same `mode` var stamped on header + entry |
| C-6-12/13 | extra fields allowed, JSONL preserved | ✅ | optional `rule_id`, `tier` `#[serde(skip_serializing_if=None)]`; no secrets |

## Append-only across reset — ✅ PASS
- §2.4 cross-check: `reset_state` does not touch the sink; sink reopen is
  `append`. Test `sink_is_append_only_across_reopens` asserts 2 lines after
  reopen (C-2.4-06).

## Write coverage — ✅ PASS
- Written from `stamp_interop_response`, the single per-response choke-point,
  so every classified request produces a line (subject to load-shed verbose
  gating, which trims optional echo fields, not the 8 required ones).

## §6 IP semantics note (C-6-15) — ✅ understood
- Loopback `127.0.0.x` are treated as distinct clients for rate-limit/risk
  (see §10). Audit `ip` is the literal peer, so single-source-burst families
  correlate by TCP source as the contract expects.

## Findings
- Only the **risk_score 0–100** edge (C-6-10) overlaps **F-V26-003** — the
  fix at the stamp site (`.min(100)` on `effective_risk_score`) corrects
  both the header and this audit field simultaneously.

## Net
Audit log is fully contract-shaped. IP-source semantics are correct (the
most common audit contract failure — using XFF — is explicitly avoided here).
