# Run 15 — 2026-05-01 — HACK-T2 + HACK-T3 verification

End-to-end verification after **HACK-T2** (v2.3 contract
regression CI gate) + **HACK-T3** (Tier-A bonus: rule
simulator) — slices 2 + 3 of the
[`plans/hackathon-readiness.md`](../../../../plans/archive/hackathon-readiness.md)
track.

## Headline

| Surface | Result |
|---|---|
| **HACK-T2 contract checks** | **40/40 PASS** against current binary |
| **HACK-T2 negative test** | wrong `SECRET=` → exit 1 with `FAIL: [001] v2.3 §2.1` line |
| **HACK-T3 simulator unit tests** | 10/10 PASS in `aegis-control::api::simulator::tests` |
| **HACK-T3 live API** | `POST /api/rules/simulate` returns correct decisions for benign / SQLi / XSS / path-traversal probes |
| **HACK-T3 dashboard** | "Rule simulator" card on Rule Manager page renders verdict (BLOCK pill, sqli rule_id, signals table) end-to-end |
| **Workspace tests** | 41 + 872 (+10 simulator) + 173 + 496 + 888 + supporting integration tests = all PASS |
| **Bundle** | 197,203 B (192 KB) — within 256 KB budget |

## HACK-T2 — v2.3 contract regression CI gate

`tests/contract/v2.3_compliance.sh` runs **40 numbered checks**
mapped directly to v2.3 §X.Y citations. Coverage:

- **§2.1** control-endpoint dispatch — capabilities returns 200
- **§2.2** `X-Benchmark-Secret` auth — missing + wrong both 403
- **§2.3** capabilities response shape (ok / features /
  active.default_mode / active.overrides)
- **§2.4** atomic `reset_state` + audit-log preservation
  (asserts log line count is non-decreasing across reset)
- **§2.5** `set_profile` semantics with response echo
- **§2.6** `flush_cache` not-5xx
- **§5.1** every required `X-WAF-*` header on allowed
  responses with exact value-set matches (Action / Cache /
  Mode case-sensitive)
- **§5.3** every required header on **blocked** responses
- **§6** audit-log JSONL minimal schema (every mandatory
  field with valid types + value sets)
- **§6** IP semantics — drives a request with a forged XFF
  and asserts `audit.ip` is the TCP peer (`127.0.0.1`),
  NOT the spoofed value
- **§6** `X-WAF-Request-Id` ↔ `audit.request_id` correlation
- **§3.1** high-confidence injection blocked or challenged
- **§8** startup contract — binary exists + `/healthz/ready` 200

Wired into `tests/README.md` § 9 as **stage 4** (k6 scenarios
become stage 5; nightly scanners stage 6) so contract drift is
caught before perf testing burns runner time.

### Negative test
```
$ SECRET="WRONG-SECRET-XYZ" bash tests/contract/v2.3_compliance.sh
FAIL: [001] v2.3 §2.1 — GET /__waf_control/capabilities returns 200
$ echo $?
1
```

The script catches drift, not just success.

## HACK-T3 — Tier-A bonus: rule simulator

`POST /api/rules/simulate { method, path, headers, body }`
runs a synthetic request through the **same** `default_detectors()`
+ live `SharedDetectorMask` the data plane runs, returning:

```json
{
  "decision_action": "block | allow | challenge | …",
  "rule_id": "sqli | xss | …",
  "risk_score": 0..100,
  "detectors_fired": ["sqli", …],
  "signals": [{"class": "sqli", "detail": "uri"}],
  "tier": "catchall | high | critical | …",
  "muted_detectors": ["sqli", …]   // detectors disabled by mask
}
```

No side effects — no risk increment, no rate-limit consumption,
no audit emit. Operators preview without polluting state.

### Live API verification (run-15)
```
$ curl -s -X POST $ADMIN/api/rules/simulate \
    -H 'content-type: application/json' \
    -d "{\"method\":\"GET\",\"path\":\"/api/users?id=1' OR '1'='1\"}"
{
  "decision_action": "block",
  "rule_id": "sqli",
  "risk_score": 40,
  "detectors_fired": ["sqli"],
  "signals": [{"class": "sqli", "detail": "uri"}],
  "tier": "catchall",
  "muted_detectors": []
}
```

XSS in body, path-traversal, and benign requests all classify
correctly.

### Dashboard wiring
- New `RuleSimulator` card at the top of the Rule Manager page
  (`#/rules`) with a TIER A pill, method dropdown, path input,
  body input, and Simulate button.
- After click: verdict pill (BLOCK in red / ALLOW in green /
  CHALLENGE in yellow), rule_id, risk score, tier, fired
  detectors, muted detectors, and a signals table.
- Screenshots: `screenshots/rule-simulator-empty.png` (form
  before click) and `screenshots/rule-simulator-verdict.png`
  (after clicking Simulate on a SQLi probe).

### Coverage tests (10/10 PASS)
- `benign_request_returns_allow_with_zero_risk`
- `sql_injection_path_is_blocked_with_sqli_rule_id`
- `xss_query_string_is_blocked`
- `path_traversal_is_blocked`
- `defaults_when_method_omitted`
- `invalid_method_falls_back_to_get`
- `body_payload_with_xss_is_blocked`
- `muted_detectors_surface_in_response`
- `signals_include_class_and_detail`
- `response_serialises_to_expected_json_shape`

## Files touched

### HACK-T2

- `tests/contract/v2.3_compliance.sh` (new, ~280 LOC) — the
  regression script.
- `tests/README.md` § 9 — CI pipeline reference updated.

### HACK-T3

- `crates/aegis-control/src/api/simulator.rs` (new, ~370 LOC)
  with 10 unit tests.
- `crates/aegis-control/src/api/mod.rs` — `pub mod simulator;`.
- `crates/aegis-control/src/dashboard_services.rs` — new
  `detectors: Option<Arc<Vec<Box<dyn Detector>>>>` field +
  `None` default.
- `crates/aegis-proxy/src/admin_dispatch.rs` — POST
  `/api/rules/simulate` dispatch arm + `handle_simulate`.
- `crates/aegis-proxy/src/accept.rs` — `admin_accept_loop`
  accepts the new `detectors` parameter and stamps it on
  `services.detectors`.
- `crates/aegis-proxy/src/run.rs` — passes `detectors` through.
- `crates/aegis-control/assets/dashboard/src/data.jsx` — new
  `rulesSimulate` helper.
- `crates/aegis-control/assets/dashboard/src/pages.jsx` —
  new `RuleSimulator` component rendered on Rule Manager.
  Also retired `window.RULES` static fallback per HACK-T1
  spirit (was a missed item).

## Definition of Done

- [x] `tests/contract/v2.3_compliance.sh` — 40/40 PASS;
      negative test catches drift; CI stage 4.
- [x] `POST /api/rules/simulate` — wired through dispatch,
      respects live `SharedDetectorMask`, no side effects.
- [x] Dashboard "Simulate" surface on Rule Manager —
      end-to-end live (browser screenshot of verdict).
- [x] 10 simulator unit tests + full workspace tests pass.
- [x] Bundle ≤ 256 KB.
- [x] Production build clean.

## What's next

- **HACK-T4** — Tier-B bonus: config versioning + rollback UI
  on the audit chain.
- **HACK-T5** — Tier-C bonus: Syslog/CEF audit forwarder.
