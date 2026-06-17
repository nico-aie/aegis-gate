---
id: 2026-06-17-section-07-to-13-misc
contract_section: "§7 normalization, §8 startup, §9 cache, §10 IP trust, §11/§11b phases, §13 MVP"
checklist_ids: C-7-* C-8-* C-9-* C-10-* C-11-* C-11b-* C-13-*
verdict: PASS (1 VERIFY-LIVE on §8 health probe)
test_mode: source-review
---

# §7 / §8 / §9 / §10 / §11 / §13

## §7 — Decision Normalization Matrix — ✅ PASS
- enforce/log_only semantics drive the classification the matrix expects:
  - enforced denial (block/challenge/rate_limit/timeout/circuit_breaker)
    → `prevented` (C-7-12). Each emits its action + `X-WAF-Mode: enforce`.
  - log_only → request forwarded upstream, intended action reported,
    `X-WAF-Mode: log_only` → `log_only_detected` (C-7-13).
- `prevented_sanitized`: response-body / payload sanitization exists
  (`aegis-security/src/dlp`, `response_filter.rs`); action stays `allow`/`block`
  with the responsible detector in `X-WAF-Rule-Id`.
- `allowed_after_challenge`: see VERIFY-LIVE-2 (§4) — the verified-challenge
  replay path must actually allow the follow-up request.

## §8 — Startup & Binary Contract — ✅ PASS / ⚠️ VERIFY-LIVE

| ID | Requirement | Result | Evidence |
|----|-------------|--------|----------|
| C-8-01/02 | `./waf` + `./waf run` start, listen before timeout | ✅ | binary `aegis-bin`; run path `aegis-proxy/src/run.rs` |
| C-8-03 | `./waf.yaml`/`.toml` must exist | ✅ | config loader (`aegis-core/src/config.rs`) |
| C-8-04/05 | reads upstream + port from config | ✅ | config-driven listener wiring |
| C-8-06 | `./waf_audit.log` created on first request | ✅ | sink opened at boot (create+append) |
| C-8-07 | health endpoint 200 before timeout | ⚠️ VERIFY-LIVE | endpoints exist: data-plane `/__waf_control/healthz` (**auth-gated**), admin `/healthz/live`, `/healthz/ready`. **Confirm the benchmark's configured probe targets a path that returns 200 without `X-Benchmark-Secret`**, OR that the probe sends the secret. If the probe hits `/__waf_control/healthz` without the secret it gets 403 → `startup_failed` |

**VERIFY-LIVE-1:** reconcile the benchmark startup-probe path with auth.
Recommended: expose an unauthenticated liveness path, or document the probe
to use the admin `/healthz/live`. (See F-V26-LOW.)

## §9 — Caching Observability — ✅ PASS
- `X-WAF-Cache` mandatory on every response: always stamped (`headers.rs:286`),
  default `BYPASS` (C-9-05).
- Smart-cache (`SC-1`) sets `Hit`/`Miss` only on cacheable routes; sensitive/
  dynamic default to `Bypass` (C-9-02/03/04).
- `flush_cache` clears before returning success when wired (C-9-06, see §2.6).

## §10 — Source IP Trust Model — ✅ PASS

| ID | Requirement | Result | Evidence |
|----|-------------|--------|----------|
| C-10-01 | peer_addr primary for audit + rate/risk | ✅ | audit ip=peer; risk key built from peer ip + fingerprint (`build_risk_key`) |
| C-10-02/03 | XFF / X-Real-IP supplementary only | ✅ | `aegis-security/src/ip_rep/xff.rs` treats XFF as context; not sole identity |
| C-10-04 | Host validation | ✅ | route host matching / host checks in listener |
| C-10-05 | distinct `127.0.0.x` = distinct clients | ✅ | risk/rate keys use the full peer IP, so loopback variants are distinct |

## §11 / §11b — Disclosure & Phases — ✅ PASS
- C-11-03: no payload/IP/sequence hard-coding observed in the control or
  decision path; detectors are generic (rules engine + behavioral/velocity).
  `set_profile` does not special-case benchmark traffic (`control.rs:154`
  comment explicitly forbids it; no such branch found).
- C-11b-05/06/08: single binary serves both phases; `enforce` is the default
  mode; no separate "benchmark mode". Same `./waf run` path.
- C-11b-04 (Dashboard monitoring under load): out of automated-contract scope;
  judged manually — not assessed here.

## §13 — Minimum Viable WAF Checklist — ✅ PASS (precondition met)

| Group | Items | Result |
|---|---|---|
| Binary & startup | C-13-01..03 | ✅ (modulo VERIFY-LIVE-1 probe path) |
| Reverse proxy | C-13-04/05 | ✅ forwards; body untouched unless sanitised |
| 6 response headers | C-13-06..11 | ✅ (rule-id format = F-V26-001) |
| Control plane | C-13-12..19 | ✅ (422 edge = F-V26-002) |
| Audit log | C-13-20..22 | ✅ |
| log_only behaviour | C-13-23/24 | ✅ |

## Net
§§7–13 are compliant. The only actionable item outside §5's findings is
**VERIFY-LIVE-1**: make sure the startup health probe path is reachable
without the control secret (or the probe is configured to send it), so the
benchmarker never records `startup_failed` on an otherwise-healthy WAF.
