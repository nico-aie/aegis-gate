# Phase 1 — CRITICAL fixes

> **Strict spec:** every fix follows `Hackathon_Doc/EN_waf_interop_contract_v2.3.md`.
> **Branch:** all changes target `develop`.

---

## C001 · `/__waf_control/*` unreachable on data-plane port (`:8080`)

**Source:** `tests/n-tester/reports/findings/2026-05-07/F-CRITICAL-001-interop-control-plane-8080.md`

### Spec citation (must satisfy)

§2.1 of v2.3:

> *"All control endpoints MUST be local/admin-only and MUST NOT be proxied to upstream."*

§4 (Decision via HTTP Response):

> *"Your WAF MUST include `X-WAF-Request-Id` on every response so the benchmarker can correlate request-level evidence across response headers and the audit log."*

The OC harness sends control calls to whichever port it sends traffic to (the contract doesn't pin the control port). Today only `:9443` works; `:8080` returns 403 (SSRF FP). That violates §2.1's reachability + §2.5's "MUST NOT special-case detection logic for benchmark traffic" — control paths are being subjected to detector pipelines instead of being short-circuited.

### Verified state (2026-05-07, on `develop`)

- `crates/aegis-proxy/src/accept.rs` has **no** early-exit for `/__waf_control/*` paths.
- The control surface is reachable only on `:9443` (admin port).
- The `staging` branch (commit `dfc487c` "Update deploy for staging") already contains the fix:
  - `accept.rs` adds an `if path.starts_with("/__waf_control/")` short-circuit
  - `admin_dispatch.rs` exports `handle_interop_control_with_rt(req, rt)` for the data-plane callsite

### Plan

**Step 1 — cherry-pick `dfc487c` from `staging` onto `develop`, drop the binary mmdb files.**

```sh
cd /Users/nico/waf-code/aegis-gate
git fetch origin staging
git checkout develop
git pull origin develop

# Cherry-pick the code-only changes; drop the 21 MB binaries
git cherry-pick origin/staging                # = dfc487c
git rm --cached data/geoip/GeoLite2-ASN.mmdb data/geoip/GeoLite2-Country.mmdb 2>/dev/null
git rm -f      data/geoip/GeoLite2-ASN.mmdb data/geoip/GeoLite2-Country.mmdb 2>/dev/null
git commit --amend --no-edit                  # rolls the rm into the same commit

# Verify only code + .gitignore changes remain (no binary lines)
git show --stat HEAD
```

Expected: 3 files changed (`accept.rs`, `admin_dispatch.rs`, `data/geoip/.gitignore`), no binary blobs.

**Step 2 — local verify on dev.**

```sh
make build
make bench-dev    # in another terminal
SECRET="waf-hackathon-2026-ctrl"

# Each of the four endpoints on the data port:
for ep in capabilities reset_state set_profile flush_cache; do
  printf "  %-18s  " "$ep"
  if [ "$ep" = "capabilities" ]; then
    METHOD="GET"
  else
    METHOD="POST"
  fi
  curl -ks -o /dev/null -w "status=%{http_code}\n" -X "$METHOD" \
    -H "X-Benchmark-Secret: $SECRET" \
    "http://127.0.0.1:8080/__waf_control/$ep"
done
# Expected: status=200 for all four.

# Confirm SSRF is NOT firing on these paths (audit log check):
grep '"path":"/__waf_control' ./waf_audit.log | head -5
# Expected: zero "rule_id":"ssrf" entries on these paths.
```

**Step 3 — regression test.**

New integration test (`crates/aegis-proxy/tests/interop_data_plane.rs`):

```rust
#[tokio::test]
async fn waf_control_reachable_on_data_plane() {
    let app = boot_test_data_plane().await;
    let resp = app.get("/__waf_control/capabilities")
        .header("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")
        .send().await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await;
    assert_eq!(body["ok"], true);
    assert!(body["features"]["rules_engine"]["policies"].as_array()
        .unwrap().iter().any(|p| p == "ai"));   // verifies C002 too
}

#[tokio::test]
async fn waf_control_not_blocked_by_ssrf() {
    let app = boot_test_data_plane().await;
    let resp = app.post("/__waf_control/reset_state")
        .header("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")
        .send().await;
    assert_eq!(resp.status(), 200);
    // Audit log: no SSRF event on this path
    let log = app.audit_lines().await;
    assert!(!log.iter().any(|l| l.contains("\"rule_id\":\"ssrf\"")
                              && l.contains("\"path\":\"/__waf_control")));
}
```

### Acceptance

- [ ] All four `/__waf_control/*` endpoints return 200 (with correct secret) on `:8080` AND `:8443` AND `:9443`
- [ ] SSRF detector does not fire on `/__waf_control/*` paths
- [ ] Cherry-pick committed cleanly without the 21 MB mmdb binaries
- [ ] Two new integration tests pass
- [ ] `make bench-dev` smoke flow from `QUICKSTART.md §8` works end-to-end

**Effort:** ~30 min (cherry-pick) + ~30 min (test) = **~1 hour total.**

---

## C002 · AI threshold over-fires + AI not exposed as a toggleable v2.3 feature

**Source:** `tests/n-tester/reports/findings/2026-05-07/F-CRITICAL-002-ai-threshold-observe-mode-missing.md`

### Strict v2.3 reframing

The QA report's recommended fix ("re-introduce `mode: observe | enforce` in `AiConfig`") is **rejected** per the operator's directive — that would be a config-side hack alongside the v2.3 control plane. The contract gives the OC harness exactly one way to disable a detector at runtime:

§2.5:
> *"`set_profile` ... toggle one feature/policy ... `enforce` / `log_only`"*
> *"Teams MUST NOT hard-code behavior for the benchmark"*

If we want the OC to be able to put AI into log_only without a YAML edit + restart, **AI must be exposed as a `(feature, policy)` pair in the capabilities response**. Currently it isn't.

### Verified state (2026-05-07, on `develop`)

| Item | State |
|---|---|
| `waf.yaml:127` | `confidence_threshold: 0.5` (the over-firing dev override) |
| `default_ai_confidence_threshold()` in `config.rs` | returns `0.85` (calibrated) |
| `rules_engine.policies` in `run.rs` | `[sqli, xss, path_traversal, ssrf, header_injection, body_abuse, recon, brute_force]` — **`ai` is missing** |
| `rule_to_feature("ai")` in `rule_map.rs` | returns `None` → falls through to `Mode::Enforce`, ignoring any operator log_only intent |
| AI detector tag | `"ai"` (verified earlier in session) |
| `mode: observe \| enforce` config field | removed (per existing doc comment in `config.rs:206`) |

So today: even if the OC sends `set_profile { scope:"all", mode:"log_only" }`, the AI detector still enforces because the rule-id-to-mode lookup misses for `"ai"`.

### Plan (strict v2.3)

**Step 1 — bump `waf.yaml` threshold to the calibrated default (immediate FP reduction).**

```yaml
# waf.yaml:127 (single-line change)
ai:
  confidence_threshold: 0.85   # was 0.5 — that triggered ~77% FP
```

This is the only config-side change. No new fields. No re-introduced `mode` enum.

**Step 2 — expose `ai` as a toggleable policy under `rules_engine`** (`crates/aegis-proxy/src/run.rs`):

```rust
features.insert(
    "rules_engine".into(),
    CapabilityFeature {
        supported: true,
        toggleable: true,
        policies: vec![
            "sqli".into(),
            "xss".into(),
            "path_traversal".into(),
            "ssrf".into(),
            "header_injection".into(),
            "body_abuse".into(),
            "recon".into(),
            "brute_force".into(),
            "ai".into(),                          // ← NEW
        ],
    },
);
```

**Step 3 — wire `ai` into the rule-id → (feature, policy) map** (`crates/aegis-control/src/interop/rule_map.rs`):

```rust
match primary {
    // … existing entries …
    "ai" => ("rules_engine", "ai"),               // ← NEW
    _ => return None,
}
```

**Step 4 — update unit tests for `rule_map` and `capabilities`.**

```rust
#[test]
fn ai_detector_maps_to_rules_engine_ai() {
    assert_eq!(rule_to_feature("ai"), Some(("rules_engine", "ai")));
}

#[test]
fn capabilities_lists_ai_under_rules_engine() {
    let c = ctx();
    let r = c.capabilities();
    let policies = r.features.get("rules_engine").unwrap().policies.clone();
    assert!(policies.contains(&"ai".to_string()));
}

#[test]
fn set_profile_can_log_only_just_ai() {
    let c = ctx();
    let req = SetProfileRequest {
        scope: SetProfileScope::Policies,
        mode: ModeRepr::LogOnly,
        feature: Some("rules_engine".into()),
        policies: Some(vec!["ai".into()]),
        ..Default::default()
    };
    c.set_profile(&req).unwrap();
    // After this, the data plane's mode_for_rule("ai") must return LogOnly,
    // and the AI detector's would-be block path falls into log_only_intent.
    assert_eq!(
        c.modes.resolve("rules_engine", Some("ai")),
        Mode::LogOnly,
    );
}
```

**Step 5 — live verification on dev** (after C001 + C002 land):

```sh
make bench-dev    # in another terminal
SECRET="waf-hackathon-2026-ctrl"
HOST="http://127.0.0.1:8080"

# 1. Confirm AI is in capabilities
curl -ks -H "X-Benchmark-Secret: $SECRET" "$HOST/__waf_control/capabilities" \
  | jq '.features.rules_engine.policies[] | select(. == "ai")'
# Expected: "ai"

# 2. Toggle AI to log_only
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["ai"]}' \
  "$HOST/__waf_control/set_profile" | jq

# 3. Send a borderline request that AI would have flagged
curl -ksi "$HOST/api/users?id=42" 2>&1 | grep -i '^x-waf-'
# Expected (per §5.3 log_only contract):
#   x-waf-action: block        (intended action)
#   x-waf-mode: log_only       (mode of firing policy)
#   x-waf-rule-id: ai          (which detector "fired")
#   HTTP/2 200                  (request actually reached upstream)

# 4. Restore enforce
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"all","mode":"enforce"}' \
  "$HOST/__waf_control/set_profile" > /dev/null
```

**Step 6 — Performance page sanity.**

After the threshold bump + AI policy wiring:

- Send synthetic clean traffic for ~5 min via `make mock-load` (no attacks)
- Performance page block ratio should drop from ~77% to ≤5%
- Health & SLOs `data_plane_availability` should start recovering above the 99.9% target after the burn window rolls

### Acceptance

- [ ] `waf.yaml` ships `confidence_threshold: 0.85`
- [ ] `capabilities` response includes `rules_engine.policies` containing `"ai"`
- [ ] `rule_map::rule_to_feature("ai")` returns `Some(("rules_engine", "ai"))`
- [ ] `set_profile` can toggle just `ai` to log_only via `scope: policies`
- [ ] In log_only, an AI-flagged request reaches upstream with `X-WAF-Action: block`, `X-WAF-Mode: log_only`, `X-WAF-Rule-Id: ai`
- [ ] Per §2.5 spec text: behavior is **NOT hard-coded** — the AI detector logic is unchanged; only its eventual block-vs-pass-through decision is gated by the same generic `mode_for_rule` lookup all detectors use
- [ ] Block ratio under benign traffic drops below 5%
- [ ] All existing rule_map + control_plane tests pass; three new tests pass

**Effort:** ~1 hour total — three small surgical edits (waf.yaml, run.rs feature list, rule_map.rs match) + tests.

---

## Sequencing

C001 lands first (cherry-pick). C002 lands second (depends on C001 for the integration test that calls `/__waf_control/capabilities` from the data-plane port).

Both ship as a single PR: `fix(critical): wire __waf_control on data plane + expose AI as toggleable policy`. ~1.5–2 hours total. Low risk — small surgical changes, each behind a regression test.
