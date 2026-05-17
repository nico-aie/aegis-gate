---
id: 2026-05-17-entry-cli-dataplane-audit
date: 2026-05-17T00:00Z
test_mode: source-review
scope:
  - Entry point + CLI dispatch (`crates/aegis-bin/src/main.rs`)
  - Data-plane hot path (`crates/aegis-proxy/src/data_plane.rs`,
    `crates/aegis-proxy/src/accept.rs`, `crates/aegis-proxy/src/run.rs`)
  - Cross-referenced: `crates/aegis-proxy/src/proxy.rs`,
    `crates/aegis-control/src/admin_dispatch.rs`,
    `crates/aegis-control/src/interop/{control.rs,headers.rs}`,
    `crates/aegis-proxy/src/upstream/forward.rs`
  - Compliance gate: `Hackathon_Doc/VN_waf_interop_contract_v2.3.md`
tester: Claude (source review, no live traffic)
---

# Aegis-Gate entry-point + data-plane source audit — 2026-05-17

**Mode:** Source review only — files read in full and cross-referenced
against v2.3 interop contract. No live traffic; findings derived from
code paths and contract clauses.

**WAF version:** 0.1.0 (workspace at HEAD on 2026-05-17)

**Interop contract:** [`Hackathon_Doc/VN_waf_interop_contract_v2.3.md`](../../../../Hackathon_Doc/VN_waf_interop_contract_v2.3.md)

---

## Finding counts

| Severity | Count |
|---|---|
| CRITICAL | 4 |
| HIGH     | 5 |
| MEDIUM   | 5 |
| LOW      | 0 |
| **Total** | **14** |

---

## Findings index

| ID | Severity | Title |
|---|---|---|
| F-CRITICAL-001 | CRITICAL | `/__waf_control/*` responses bypass `stamp_interop_response` — 6 mandatory §5 headers missing |
| F-CRITICAL-002 | CRITICAL | `log_only` mode ignored by rate-limit / strike-block / blacklist / risk-score block paths |
| F-CRITICAL-003 | CRITICAL | v2.3 audit sink fail-silent at boot — every decision skipped if file can't be opened |
| F-CRITICAL-004 | CRITICAL | Hard 1 MiB request-body cap blocks legitimate large requests as `body-too-large` |
| F-HIGH-001     | HIGH     | Audit-log `path` field strips query string (uses `.path()` not `.path_and_query()`) |
| F-HIGH-002     | HIGH     | `127.0.0.0/8` in default `trusted_proxies` collapses sandbox clients when XFF present |
| F-HIGH-003     | HIGH     | Upstream response body fully buffered with no cap — OOM risk under hostile/runaway upstream |
| F-HIGH-004     | HIGH     | `X-WAF-Request-Id` derived from `blake3(peer:nanos:path)` — not UUID-v4 random; collisions possible |
| F-HIGH-005     | HIGH     | `reset_state` runs subsystem callbacks sequentially without a cross-subsystem lock — not atomic |
| F-MEDIUM-ALL   | MEDIUM   | Bundle: trusted-proxies rebuilt per request · graceful-shutdown drops in-flight · TOTP not crypto-random · handover exit race · break-glass audit emits empty `request_id` |

---

## Interop contract compliance (v2.3) — quick matrix

| Clause | Requirement | Status | Evidence / finding |
|---|---|---|---|
| §5 | `X-WAF-Request-Id` on every data-plane response | ✅ | `accept.rs:1219, 1326` via `stamp_interop_response` |
| §5 | Same 6 headers on `/__waf_control/*` responses | ❌ | F-CRITICAL-001 — `accept.rs:1097-1110` early-returns |
| §5 | `X-WAF-Action` lowercase enum exact match | ✅ | `interop/headers.rs:50-61` |
| §5 | `X-WAF-Cache` UPPERCASE (currently always `BYPASS`) | ✅ | `interop/headers.rs:89-96` |
| §5 | `X-WAF-Mode` lowercase | ✅ | `interop/headers.rs:70-76` |
| §3 | `log_only` for detector blocks | ✅ | `data_plane.rs:644-660` |
| §3 | `log_only` for rate-limit / strikes / blacklist / risk-score | ❌ | F-CRITICAL-002 — 4 block paths ignore `interop_modes` |
| §6 | Audit JSONL append-only to `./waf_audit.log` | ⚠️ | F-CRITICAL-003 — fail-silent if open fails |
| §6 | Audit `ip` = TCP peer (NOT XFF) | ✅ | `admin_dispatch.rs:1064` uses `peer.ip()` |
| §6 | Audit `path` includes query string | ❌ | F-HIGH-001 — `.path()` strips query |
| §6 | Audit `request_id` matches `X-WAF-Request-Id` | ⚠️ | Format matches but entropy is hash-based — F-HIGH-004 |
| §2.3 | `GET /__waf_control/capabilities` | ✅ | `admin_dispatch.rs:741-745` |
| §2.4 | `POST /__waf_control/reset_state` synchronous + atomic + preserves audit | ⚠️ | F-HIGH-005 — sequential, no cross-subsystem lock |
| §2.5 | `POST /__waf_control/set_profile` | ✅ | `admin_dispatch.rs:770-804` |
| §2.6 | `POST /__waf_control/flush_cache` | ✅ | `admin_dispatch.rs:805-809` |
| §2.2 | `X-Benchmark-Secret` auth (constant-time) → 403 | ✅ | `interop/control.rs:242-250` |
| §2 | Control endpoints do NOT proxy to upstream | ✅ | `accept.rs:1097-1112` short-circuit |
| §8 | `./waf` + `./waf.yaml` + `./waf_audit.log` in cwd | ✅ | `main.rs:75-90`, `config.rs:185` |
| §8 | `./waf run` starts + binds before timeout | ✅ | `accept.rs:1346-1348` readiness flip after listener bound |
| §10 | Distinct `127.0.0.x` are distinct clients | ⚠️ | F-HIGH-002 — OK without XFF; breaks if XFF from loopback |
| Round-1 | Forward HTTP method/headers/body intact | ⚠️ | F-CRITICAL-004 — caps body at 1 MiB |
| Round-1 | No panic on hot path under legitimate traffic | ✅ | `.unwrap()` only on deterministic `Response::builder` constructions |

---

## Verdict

The entry point + data plane are sound enough to pass **Round 1**
under typical benchmark traffic — header pipeline is wired, audit
JSONL writes to `./waf_audit.log` with the TCP-peer `ip`, control
endpoints short-circuit the security pipeline, and no hot-path
`unwrap` is reachable from a crafted request.

The **three benchmark-scoring risks** that need to land before
running against the OC harness:

1. **F-CRITICAL-001** — `/__waf_control/*` responses currently
   carry zero `X-WAF-*` headers. Any bench tooling that asserts
   header presence uniformly will deduct per call.
2. **F-CRITICAL-002** — `set_profile mode:"log_only"` for any
   non-detector feature still blocks the request → the OC's
   log-only verification probe sees enforcement → §3 fail.
3. **F-CRITICAL-004** — single `> 1 MiB` payload in the
   benchmark corpus is enough to trip Round 1's
   "forward chính xác headers và body" criterion.

CRITICAL-003 (fail-silent audit) is the silent killer — if the
operator runs the WAF from a directory without write permission,
every benchmark run reports zero audit lines and Phase 2 scoring
drops to 0% on every contract clause that requires correlation.

Fixes for the four CRITICALs are each <100 LoC and self-contained.

---

## Files

- `F-CRITICAL-001-control-endpoints-missing-observability-headers.md`
- `F-CRITICAL-002-log-only-bypassed-by-rate-limit-strike-blacklist-risk.md`
- `F-CRITICAL-003-audit-sink-fail-silent-at-boot.md`
- `F-CRITICAL-004-request-body-1mib-hard-cap.md`
- `F-HIGH-001-audit-path-missing-query-string.md`
- `F-HIGH-002-loopback-in-trusted-proxies-default.md`
- `F-HIGH-003-upstream-body-unbounded-buffer.md`
- `F-HIGH-004-request-id-not-cryptographically-random.md`
- `F-HIGH-005-reset-state-not-atomic-across-subsystems.md`
- `F-MEDIUM-ALL.md`
