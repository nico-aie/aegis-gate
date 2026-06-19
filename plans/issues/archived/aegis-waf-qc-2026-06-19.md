# Aegis-Gate WAF — QC Report

**Date:** 2026-06-19 · **Mode:** Functional (contract-focused) · **Tester:** aegis-waf-tester
**Contract:** `Hackathon_Doc/EN_waf_interop_contract_v2.6.md`
**Focus:** Regression of core features + new *per-route monitor (log-only)* feature (commit `7ca1f74`)
**Surfaces driven:** Admin console `:9443` (logged in) + data plane `:8080` (in-page fetch, real `X-Forwarded-For`)

---

## Headline

**Findings: 1 HIGH · 1 MEDIUM · 2 LOW · 5 INFO (pass).**

The contract surface (§2 control plane, §5 headers, §6 audit) is **fully compliant**, detectors are healthy with no false positives, and all 18 dashboard pages mount cleanly. **The new per-route monitor feature has one real defect:** it correctly downgrades enforcement (forwards the request) but **stamps `X-WAF-Mode: enforce` instead of `log_only`** on both the response header and the audit log — a §5.3/§7 observability violation. The global `set_profile log_only` path does this correctly, so the bug is isolated to the new route-level path.

**Top blocker:** `HIGH-1` — per-route monitor emits the wrong `X-WAF-Mode`.
**Recommendation:** fix `HIGH-1` before the automated benchmark (Round 2 Phase 1) and the manual dashboard toggle check (Round 2 Phase 2). The Attack Battle (Round 3) runs enforce-only, so it is unaffected.

---

## Findings

### HIGH-1 — Per-route monitor mode reports `X-WAF-Mode: enforce` (should be `log_only`)
**Area:** data-plane / observability · **Component:** per-route monitor (`effective_mode`) · **Contract:** §2.7, §5.1, §5.3, §7

**Summary.** A route marked `mode: log_only` (monitor) correctly stops blocking — the request is forwarded upstream instead of returning 403. But the WAF still labels the decision `X-WAF-Mode: enforce` with `X-WAF-Action: block`, in **both** the response header and the `waf_audit.log` entry. Per §5.3, *"`X-WAF-Action` MUST match the actual behavior of the response when `X-WAF-Mode: enforce`."* Here `mode=enforce` + `action=block` but the request was **not** blocked → direct contradiction. Under §7, a benchmarker reads `action=block, mode=enforce` on a malicious request and classifies it `prevented`, while organizer-side validation sees the request reached upstream → misclassification / flaky scoring.

**Repro (clean A/B, identical XSS probe, `reset_state` between, fresh IPs):**

| Condition | Status | `X-WAF-Action` | `X-WAF-Mode` |
|---|---|---|---|
| catch-all `mode: enforce` | **403** | block | `enforce` ✅ |
| catch-all `mode: log_only` (route) | **200** (forwarded) | block | `enforce` ❌ should be `log_only` |
| global `set_profile {scope:all, mode:log_only}` | **200** (forwarded) | block | `log_only` ✅ |

Audit log confirms the same: monitored-route XSS rows show `"action":"block","mode":"enforce"` while the global-log_only rows correctly show `"mode":"log_only"`.

**Root cause (suspected).** The data-plane gates compute `effective_mode(global, route_log_only)` to decide whether to *apply* the block (so forwarding works), but the mode tag stamped onto the response header + audit record is derived from the **global** `ModeStore` mode, not the route-effective mode. Thread the route-effective mode into the `DecisionTag`/header-emit path. See `crates/aegis-proxy/src/data_plane.rs` (`effective_mode`, `log_only_intent`) and the interop header emit site.

**Severity rationale.** Breaks the contract's core promise for the new feature in exactly the dimension the contract cares about (observability). Not CRITICAL: default routes and global `log_only` are correct, and Round 3 runs enforce-only. But any route shipped in monitor mode fails §5.3 consistency on every detection.

---

### MEDIUM-2 — Monitor mode is invisible in the dashboard (no read-back, no badge)
**Area:** dashboard / admin-api · **Component:** routes editor + `/api/routes` · **Contract:** Official Rules §5.6, §11b (Round 2 Phase 2 / Round 3 dashboard monitoring)

**Summary.** The UI "Monitor only" toggle **does** drive real data-plane behavior (verified: enabling it via the editor forwarded a subsequent XSS), but the operator has **no way to see** that a route is monitored:
- `GET /api/routes` response omits the `mode` field entirely (only `default, enabled, host, id, match_type, methods, path, priority, strip_prefix, tier_override, upstream`).
- `GET /api/routes/{id}` returns `404 not found` (no per-route read endpoint).
- The routes table shows **no `monitor` badge** after saving a route to monitor (docs promise one).
- Re-opening the editor shows the "Monitor only" checkbox **unchecked** even though the route is monitored — because no read API returns `mode`, the editor can't reflect saved state.

**Impact.** During the Round 2 Phase 2 manual dashboard check and Round 3 live monitoring, an operator/judge cannot tell which routes are in monitor mode, and a monitored route silently lets attacks through with no visible indicator. Functionally the toggle works; it is purely unobservable.

**Suggested fix.** Add `mode` to the `/api/routes` list serialization (the `RouteConfigPatch` already serializes it; the list endpoint uses a separate summary shape that drops it). Then wire the table `monitor` badge and the editor checkbox to that field.

---

### LOW-3 — Access-list IP entries match TCP peer only, not `X-Forwarded-For`
**Area:** data-plane · **Component:** blacklist/whitelist · **Contract:** §10 (this is compliant)

**Summary.** A blacklist entry for an IP only blocks when that IP is the **TCP peer** (`peer_addr`); a request with `X-Forwarded-For: <blacklisted-ip>` (or `X-Real-IP`) from a different peer is **allowed**. Verified: blacklisting `198.51.100.99` did not block `XFF: 198.51.100.99`, but blacklisting the real peer `127.0.0.1` produced `403 rule=blacklist`.

This is **contract-faithful** (§10: peer is identity, XFF is spoofable/supplementary) and correct for the automated benchmark, so it is **not a bug**. Flagged LOW only as an operator-facing surprise: in a production deployment behind a trusted load balancer (real client arriving via XFF), an analyst who blacklists an attacker IP seen in the dashboard's XFF column would not actually block that client. Worth a doc note / future "trust XFF from CIDR" option.

---

### LOW-4 — `X-WAF-Rule-Id` labels some recon/command-injection hits as `path-traversal`
**Area:** data-plane · **Component:** detector rule-id mapping · **Contract:** §5.1 (cosmetic)

**Summary.** `/.env` and `/api/x?cmd=;cat+/etc/passwd` are correctly **blocked (403)**, but the `X-WAF-Rule-Id` header reports `path-traversal` rather than `recon_path` / `command_injection`. The dashboard's by-detector breakdown *does* bucket them correctly (`recon_path`, `command_injection` appear as distinct rows), so detection coverage is fine — this is only the header's most-direct-rule attribution being coarse. No PASS/FAIL impact (any blocking action satisfies §3.1 for these categories), hence LOW.

---

## INFO — passing checks (proof the run exercised the surface)

- **INFO-A · §2 control plane — fully compliant.** `GET /capabilities` 200 + well-formed (5 features, all `toggleable:true`); `set_profile` `all`/`features`/`policies` all 200 with correct `applied` + `active.overrides` key conventions (`access_control`, `rules_engine.sqli`); unsupported feature → 200 with `unsupported:["does_not_exist"]` (the safe path); `reset_state` 200 `audit_log_preserved:true`; `flush_cache` 200 `supported:true`. Auth gate: missing **and** wrong `X-Benchmark-Secret` → **403** on GET and POST.
- **INFO-B · §5 headers — fully compliant.** All 6 required `X-WAF-*` headers present on every allow/block response with correct formats (UUID request-id, integer 0–100 risk, lowercase action, hyphenated rule-id/`none`, uppercase `BYPASS`, lowercase mode).
- **INFO-C · §6 audit — fully compliant + single-write.** `waf_audit.log` block rows carry all 8 required fields (`request_id, ts_ms, ip, method, path, action, risk_score, mode`); `ip` is the TCP peer (`127.0.0.1`), not XFF. **No double-write**: 63 events / 52 distinct request_ids / **0** duplicate IDs. by-detector buckets one row per class (no `"sqli,ssrf"` combination strings).
- **INFO-D · Detectors + false-positive baseline.** sqli (union & boolean), xss, path_traversal, ssrf, recon, command_injection all fire (403). Clean baselines `/`, `/api/users/100`, `/favicon.ico` → allow, risk 0, **no** false positives, **no** spurious `ssrf` tags.
- **INFO-E · Dashboard shell.** All **18** sidebar pages mount with correct H1 and **zero** error-boundary cards; no console errors during navigation. Global `log_only` and the blacklist carve-out on a monitored route both behave correctly.

**Note (not a finding):** Overview showed `3 FIRING` (DataPlaneAvailability-1h/6h/72h) red on a freshly-booted WAF with ~no traffic. Likely an availability SLO with no samples yet rather than an outage — worth confirming it clears once traffic flows, since red badges on a healthy system add noise for a SOC analyst (S1).

---

## Contract compliance matrix (v2.6)

| § | Requirement | Status |
|---|---|---|
| §2.1–2.3 | `/__waf_control/capabilities` | ✅ |
| §2.2 | `X-Benchmark-Secret` required, 403 otherwise | ✅ |
| §2.4 | `reset_state` synchronous, preserves audit + config | ✅ |
| §2.5 | `set_profile` all/features/policies + overrides + unsupported list | ✅ |
| §2.6 | `flush_cache` | ✅ (caching present) |
| §2.7 / §5.1 | `X-WAF-Mode` correct — **enforce paths & global log_only** | ✅ |
| §2.7 / §5.3 | `X-WAF-Mode` correct — **per-route monitor** | ❌ **HIGH-1** |
| §5.1 | All 6 required headers, correct formats | ✅ |
| §6 | Audit JSONL, 8 required fields, peer IP, single-write | ✅ |
| §10 | TCP peer = identity; XFF supplementary | ✅ |
| §5.6 (rules) | Dashboard reflects WAF state — **monitor mode** | ⚠️ **MEDIUM-2** |

---

## Per-page matrix (18/18 mount, 0 errors)

Overview ✓ · Live Feed ✓ · Incidents ✓ · Investigation ✓ · Top Attackers ✓ · Routing & Upstreams ✓ · Traffic Gates ✓ · Access Lists ✓ · Detectors & Tiers ✓ · Rules ✓ · Zero Trust ✓ · Performance ✓ · Health & SLOs ✓ · Audit Trail ✓ · Scaling ✓ · Settings ✓ · Reports ✓ · Help & Guide ✓

## Test hygiene

All mutations reverted: catch-all route → `enforce`, global mode → `enforce`, both QA blacklist entries deleted (list empty), `reset_state` called. Final WAF state is clean.
