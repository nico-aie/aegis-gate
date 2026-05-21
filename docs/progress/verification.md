# Implementation Progress — Verification

Snapshot of the most recent full-suite run (tests + clippy +
perf re-measure). Updated each time the snapshot in
`Implement-Progress.md`'s **Status** section changes.

---

## Verification (last full run)

- `cargo test --workspace` (default features) → **2,173 passed**
  (steady — Carry-over A rewrote `run_binds_and_serves_200`
  to use a mock upstream rather than asserting on the stub
  body, no net new tests).
- `cargo test -p aegis-proxy --lib benchmark::` → **21 passed**.
- `cargo test -p aegis-proxy --lib proxy::` → **10 passed**
  (3 pre-existing + 5 from B4-T3 + 2 from B5-T2).
- `cargo test -p aegis-proxy --features http3 --lib
  listener::http3::` → **15 passed** (helper layer
  unchanged across feature combos).
- `cargo test -p aegis-proxy --lib admin_sse::` → **8 passed**.
- `cargo test -p aegis-proxy --lib upstream::forward::` →
  **14 passed**.
- **Live perf re-run** (2026-04-29) — release binary +
  `config/waf.test.yaml` + docker `aegis-k6`:
  - `baseline.js` 200 VUs / 15 s → 42 287 RPS, allow-path
    p95 877 µs (was 7.21 ms), `allow_success` 1.57 % (was
    100 % — surfaced two carry-overs above).
  - `ddos-burst.js` → 40 001 auto-blocks, p95 0.48 ms.
  - `rate-limit.js` → FAIL on `status_429` assertion
    (gateway returns 403/strike instead — see
    carry-overs).
  - Logs: `tests/results/*-2026-04-29.log`. Comparison:
    [`tests/results/README-2026-04-29.md`](../../tests/results/archive/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md).
- `cargo test -p aegis-bin --bin waf -- snapshot` → **25
  passed** (15 from B4-T1 + 10 from B4-T2).
- `cargo test -p aegis-security --lib content::icap::` →
  **44 passed** (35 new + 9 pre-existing stub).
- `cargo test -p aegis-security --features geoip --lib
  geoip::` → **10 passed**.
- `cargo test -p aegis-security --features taxii --lib
  threat_intel::taxii::` → **38 passed**.
- `cargo test -p aegis-control --lib gitops::poll_driver::`
  → **9 passed**.
- `cargo test -p aegis-proxy --features consul --lib sd::consul::`
  → **16 passed**.
- `cargo test -p aegis-proxy --features etcd --lib sd::etcd::`
  → **18 passed**.
- `cargo test -p aegis-proxy --features k8s --lib sd::k8s::`
  → **24 passed**.
- `cargo test -p aegis-control --features alerts --lib slo::dispatch::`
  → **4 passed** (VipTalk routing).
- `cargo clippy --workspace --lib -- -D warnings` → clean.
- `cargo clippy --workspace --bins -- -D warnings` → clean.
- `cargo clippy -p aegis-proxy --features http3 --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-security --features geoip --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-security --features taxii,geoip --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-proxy --features
  redis,vault,aws,gcp,azure,consul,etcd,k8s --lib --
  -D warnings` → clean.
- `cargo run -p aegis-bin -- validate --config
  config/waf.dev.yaml` → `config OK`.
- `waf snapshot --output /tmp/x.json --config
  config/waf.dev.yaml` → 7,143-byte envelope, JSON
  round-trips through `python -c "json.load(...)"`.
- `waf snapshot ... --output snap.json --force` → `waf
  restore --from snap.json --config-out restored.yaml` →
  `waf validate --config restored.yaml` → all clean
  (full snapshot/restore CLI round-trip).

---

