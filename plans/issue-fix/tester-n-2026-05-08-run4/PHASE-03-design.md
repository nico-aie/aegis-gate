# Phase 3 — DESIGN (Run-4)

> **Branch:** all changes target `develop`.

Two findings that need design choices, not just code patches.

---

## SEC-M001 (re-frame) · Audit log file naming clarification

**Source:** Run-4 §SEC-M001.

### Verified state (2026-05-08, on `develop`)

The QA tested against `/tmp/aegis-dev-audit.jsonl` and applied §6 contract assertions to it. That's the **dashboard audit** (rich `AuditEvent` schema with `client_ip`, `ts` ISO 8601, `class`, `tenant_id`, `tier`, `fields.*`) — NOT the contract audit.

The contract audit lives at `./waf_audit.log` (configurable via `cfg.interop.audit_path`, default `./waf_audit.log`). Verified its actual on-disk shape:

```json
{"request_id":"8e4a002c-...","ts_ms":1777740829091,"ip":"127.0.0.1","method":"GET","path":"/health","action":"allow","risk_score":0,"mode":"enforce"}
```

Field-for-field contract-compliant: `request_id, ts_ms, ip, method, path, action, risk_score, mode`. **The schema is already correct.** The QA inspected the wrong file.

The reason both files exist: they serve two different consumers.

| Consumer | File | Schema | Why separate |
|---|---|---|---|
| Benchmark harness / OC | `./waf_audit.log` | `MinimalAuditEntry` (8-9 fields, contract §6) | Stable, narrow schema → harness can parse without breaking on additions |
| SOC operator / dashboard / SIEM | `cfg.audit.sinks[*].path` (e.g. `/tmp/aegis-dev-audit.jsonl`) | `AuditEvent` (rich, includes XFF-resolved IP, tier, detector mask state, decoded request fields) | Operator wants forensic detail; can't risk breaking the contract sink by adding fields |

This is intentional dual-sink design. The fix is **documentation** so the next QA run doesn't repeat the misread.

### Plan

**Step 1 — add a clear README to `./waf_audit.log`'s parent.** Since the file is at the cwd, the right place is the staging doc.

`deploy/STAGING-BENCHMARK.md` (new section):

```markdown
## Audit log files

The WAF writes TWO audit logs in parallel. They serve different
consumers and have different schemas — this is intentional.

| File | Schema | Consumer |
|------|--------|----------|
| `./waf_audit.log` (configurable: `cfg.interop.audit_path`) | v2.3 §6 contract — `request_id, ts_ms, ip, method, path, action, risk_score, mode, [rule_id, tier]` | Benchmark harness / OC |
| `cfg.audit.sinks[*].path` (default: `./audit.jsonl`; dev: `/tmp/aegis-dev-audit.jsonl`) | Rich `AuditEvent` — `client_ip, ts (ISO 8601), class, tenant_id, fields.{...}, ...` | SOC dashboard / SIEM |

When validating contract compliance, parse `./waf_audit.log`. The
operator audit at `cfg.audit.sinks` is for human consumption and
intentionally a different schema.
```

**Step 2 — surface the dual-sink intent in `dev.yaml`.** Add a comment over the `audit:` block:

```yaml
# This block configures the OPERATOR audit (dashboard / SIEM /
# cold-tier shipper). Schema: AuditEvent (rich, ts ISO 8601,
# client_ip XFF-resolved, fields.* nested).
#
# The CONTRACT audit (v2.3 §6: request_id, ts_ms, ip, method,
# path, action, risk_score, mode) is configured separately under
# `interop.audit_path` (default ./waf_audit.log). Both run in
# parallel; the contract audit is what the OC harness parses.
audit:
  sinks:
    ...
```

**Step 3 — surface in `interop.audit_path`'s default doc** (`config.rs:165`):

```rust
fn default_interop_audit_path() -> std::path::PathBuf {
    // ./waf_audit.log — the v2.3 §6 contract-shape audit log.
    // Distinct from the dashboard audit at cfg.audit.sinks (rich
    // AuditEvent schema). Parse THIS file for contract validation.
    std::path::PathBuf::from("./waf_audit.log")
}
```

**Step 4 — no schema or code change.** Pure doc.

### Acceptance

- [ ] `STAGING-BENCHMARK.md` has a "Audit log files" section explaining the two sinks
- [ ] `config/dev.yaml` `audit:` block has a comment pointing at the contract sink
- [ ] `default_interop_audit_path()` carries an inline pointer to the dual-sink doc
- [ ] Next QA run inspects `./waf_audit.log` for contract checks; no schema confusion

**Effort:** ~15 min.

---

## SEC-M003 · Per-request risk accumulation policy

**Source:** Run-4 §SEC-M003.

### Verified state (2026-05-08, on `develop`)

`crates/aegis-proxy/src/data_plane.rs` (around the detector hit branch):

```rust
if !signals.is_empty() {
    let total_score: u32 = signals.iter().map(|s| s.score).sum();
    let post_state = risk.record_malicious(peer_ip, total_score);
    ...
}
```

`record_malicious` adds the delta and clamps to `max`:

```rust
entry.score = (entry.score + delta).min(self.inner.thresholds.load().max);
```

Today, a single multi-class attack (e.g. SQLi probe that incidentally also hits xss + path_traversal regex) can fire 2-3 detectors at score 50 / 50 / 45 each → `total = 145` → `score = min(0+145, 100) = 100` on the very first request.

The QA's symptom: "fresh XFF IP returns `X-WAF-Risk-Score: 100` on first hit". That's not a bug per `record_malicious` — it's the consequence of summing detector signals.

**Design question: is summing the right policy?**

| Option | Behavior | Trade-off |
|---|---|---|
| **A. Status quo — `sum(signal.score)`** | Multi-class attack ⇒ score=100 immediately. Fast escalation to block. | Risk lifecycle hard to test (always at max after one hit); single ambiguous request can lock out a legit user. |
| **B. Cap to `max(signal.score)` per request** | Multi-class attack ⇒ score=50 (sqli alone). Two confirmed-attack requests needed to reach 100. | Slower escalation; benchmark-risk-test friendly; legit-user-with-one-FP gets a second chance. |
| **C. Average + count weight** | Score adds `max + 0.5*(others)` per request. | Hybrid; most complex; harder to reason about. |

**Recommend B.** Reasons:
- v2.3 contract §7 implies the benchmark verifies risk lifecycle via single-IP probe sequences. Always-at-max breaks that.
- A single legit request that trips two detectors (false positive on both) shouldn't immediately push the IP to "block territory". One detector tripping at a time = score = 50; two trips needed = score = 100. That's two confirmed signals before block — a natural threshold.
- Easy to revert if it turns out attackers exploit it (just change the line back).

### Plan

**Step 1 — change accumulation in `data_plane.rs`.**

```rust
// data_plane.rs — detector hit branch
if !signals.is_empty() {
    // SEC-M003 (2026-05-08): cap per-request contribution to
    // max(signal). Pre-fix: sum() let a single multi-class hit
    // (sqli + path_traversal + xss = 145) clamp to score=100
    // immediately, breaking risk lifecycle tests + locking
    // legit users out on a single ambiguous request.
    //
    // Now: each request contributes the strongest signal only.
    // Repeated bad requests still escalate (score+=50 each
    // → reach 100 in 2 hits); single-request false-positives
    // get a softer penalty.
    let request_score: u32 = signals.iter().map(|s| s.score).max().unwrap_or(0);
    let post_state = risk.record_malicious(peer_ip, request_score);
    ...
}
```

**Step 2 — RED test in `aegis-security::risk::tracker::tests`.**

```rust
#[test]
fn record_malicious_caps_to_thresholds_max() {
    // Sanity: clamp to max even when a single delta exceeds it.
    let cfg = RiskConfig { thresholds: RiskThresholds { challenge_at: 40, block_at: 80, max: 100 }, ..default() };
    let t = RiskTracker::new(&cfg);
    let s = t.record_malicious("1.1.1.1".parse().unwrap(), 200);
    assert_eq!(s.score, 100, "delta should clamp to max");
}
```

**Step 3 — RED test in `data_plane.rs` integration tests.**

```rust
#[tokio::test]
async fn multi_signal_request_uses_max_not_sum() {
    // SEC-M003 — a single request that fires two detectors at
    // score 50 each should leave the IP at score=50, not 100.
    let app = boot_test_data_plane().await;
    let resp = app.get("/proxy?url=http://127.0.0.1/etc/passwd").send().await;
    // Probably blocks via path_traversal + ssrf both firing.
    let snapshot = app.risk_snapshot(/* peer ip */).await;
    assert!(snapshot.score <= 50,
        "single multi-detector request must contribute max(signal), not sum; got {}", snapshot.score);
}
```

If the test infrastructure doesn't have a clean way to inspect risk state, an HTTP-side check works: after one attack, `GET /api/risk` returns the score; assert it's ≤ 50.

**Step 4 — manual verification.**

```sh
make bench-dev    # in another terminal
SECRET="waf-hackathon-2026-ctrl"

# Reset risk state cleanly
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" http://127.0.0.1:8080/__waf_control/reset_state

# Single multi-class attack (SQLi UNION, hits sqli + ai if enabled)
curl -ksi "http://127.0.0.1:8080/login?u=1' UNION SELECT password FROM users--"
# Pre-fix: X-WAF-Risk-Score: 100  (sum of sqli + ai signals)
# Post-fix: X-WAF-Risk-Score: 50   (max of sqli=50, ai=50)

# Second hit
curl -ksi "http://127.0.0.1:8080/login?u=1' UNION SELECT password FROM users--"
# Now: X-WAF-Risk-Score: 100   (50 + 50, accumulated across requests)
```

### Acceptance

- [ ] `data_plane.rs` detector-hit branch uses `max(signal.score)` not `sum(signal.score)`
- [ ] Single multi-detector attack → `X-WAF-Risk-Score: 50` (not 100)
- [ ] Two consecutive multi-detector attacks → `X-WAF-Risk-Score: 100`
- [ ] All existing risk tests still pass (`record_malicious` still clamps to max)
- [ ] New test guards the per-request-max policy

**Effort:** ~45 min. One-line change + 2 tests + manual verify.

---

## Sequencing

Single PR: `fix(risk): cap per-request risk contribution + audit-file doc (SEC-M001 + SEC-M003)`.

The audit-file doc and the risk-cap change are independent but both fall under "design clarification of existing behavior" — bundling keeps the review surface coherent.

---

## Open question for the operator

The risk-cap change is a **behavior change** that affects every block exit. If the operator wants to keep the current `sum(signal)` policy (e.g. because the benchmark explicitly rewards aggressive escalation), say so before this lands and we'll change Phase 3 to:

- Doc-only the audit-file note
- Keep `sum(signal)`
- Mark SEC-M003 as "by design — multi-detector signals stack"

Either way, document the policy choice so the next QA run doesn't flag the same behavior.
