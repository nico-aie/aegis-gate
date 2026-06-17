---
id: 2026-06-17-F-V26-LOW
severity: LOW + VERIFY-LIVE
area: "interop · misc edges"
contract: v2.6 §2.5, §4, §8
status: open
test_mode: source-review
---

# F-V26 LOW findings + items to confirm against a running WAF

## F-V26-004 (LOW) — `SetProfileRequest` uses `deny_unknown_fields`
**Component:** `crates/aegis-control/src/interop/control.rs:93`

```rust
#[serde(deny_unknown_fields)]
pub struct SetProfileRequest { scope, mode, features, feature, policies, cluster }
```

The contract's `set_profile` body schema (§2.5) is `scope` + `mode` (+
`features`/`feature`/`policies`). `deny_unknown_fields` rejects any field
not in the struct with **400**. Today that's fine — the benchmark sends only
the documented fields, and the extra `cluster` field is an *accepted*
addition (it's in the struct).

Risk: if a future benchmark build (or a forgiving harness) adds a field —
or sends the documented examples with an unexpected key — the WAF 400s
instead of ignoring it. The contract is generally lenient about extra input
(e.g. it requires accepting a body on no-param endpoints). Consider dropping
`deny_unknown_fields` (or switching to `#[serde(flatten)] extra: Map`) so
unknown fields are ignored rather than fatal.

**Severity LOW:** no current benchmark field triggers it; it's a
forward-compatibility hardening.

---

## F-V26-005 (LOW) — challenge fallback path is unsolvable
**Component:** `crates/aegis-proxy/src/data_plane.rs:1381`

When `upstream_ctx.pow_issuer` is **not** wired, the challenge 429 body
degrades to:
```json
{ "challenge": true, "reason": "...", "challenge_type": "proof_of_work" }
```
— no `challenge_token`, `difficulty`, `submit_url`, `submit_method`. The
benchmark cannot solve it → §4 records the challenge **FAILED** (no partial
credit, C-4-17).

The issuer **is** wired on the normal `./waf run` boot path
(`run.rs:1694` region), so this only bites a submission that ships without
the interop runtime (a test bundle). **Action:** confirm the graded binary
boots with `pow_issuer` present (assert at boot, or fail-fast if a
challenge-capable config has no issuer).

---

## VERIFY-LIVE-1 — §8 startup health-probe path vs auth
**Components:** `admin_dispatch.rs:994` (`/__waf_control/healthz`, auth-gated),
admin `/healthz/live` + `/healthz/ready` (`run.rs`).

§8: *"the benchmarker polls the configured health endpoint until the startup
timeout … First `200` = ready. If the WAF does not respond before the
timeout, the benchmarker records `startup_failed`."*

`/__waf_control/healthz` requires `X-Benchmark-Secret` (auth is checked
**before** the path match, `admin_dispatch.rs:969`). If the benchmark's
startup probe hits that path **without** the secret it gets **403**, never a
200 → `startup_failed` on an otherwise-healthy WAF.

**Confirm one of:**
- the benchmark health-probe is configured to a path that returns 200
  without the secret (e.g. admin `/healthz/live`), **or**
- the probe sends `X-Benchmark-Secret`, **or**
- expose an unauthenticated liveness path for the probe.

Cross-check `deploy/STAGING-BENCHMARK.md` and the benchmark harness config
for the exact probe URL.

---

## VERIFY-LIVE-2 — verified-challenge → original request proceeds (§4)
**Component:** `admin_dispatch.rs:1189` (`/challenge/verify` → 200).

§4: on success the WAF returns 200 "with a session cookie or token that
allows the original request to proceed." The handler returns
`200 {ok:true, action:"challenge_verified"}`; the comment says the
session-cookie / risk-bucket-clear that actually lets the replayed request
through is "wired by the data-plane risk-bucket clear (separate concern)"
(`admin_dispatch.rs:1186`).

**Confirm end-to-end:** after a successful verify, the *same client's* next
request to the originally-challenged route is **allowed** (not
re-challenged). If the verify doesn't clear the risk/challenge state for that
client, the benchmark's `allowed_after_challenge` (§7) flow fails even though
the PoW math is correct. This is the highest-value live test to run.
