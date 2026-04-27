# Benchmark Mode

> **Status.** Design complete; implementation tracked in
> [`../plans/benchmark-mode.md`](../plans/benchmark-mode.md) (task ID
> prefix `B-`). Disabled by default in every environment.

> **TL;DR.** A gated, opt-in operating mode that exposes per-request
> WAF diagnostics on the response (headers + dashboard panels +
> Prometheus series) so operators can measure overhead under
> realistic load without instrumenting the surrounding stack.

## Why

Requirement.md §3 sets a hard target: **p99 WAF-overhead latency ≤ 5
ms** at ≥ 5 000 RPS. Verifying that target — and finding regressions
before they ship — needs:

1. A way for an external load generator (k6, wrk, vegeta) to read the
   per-request WAF cost directly off the response, independent of any
   internal metric the WAF chooses to record.
2. A way for operators to see a live histogram of per-detector cost in
   the dashboard during a deliberate benchmark run.
3. A way to do both **without** running modified production binaries
   or special builds — the same binary, flipped via a config flag.

## Threat model

The headers this feature emits leak architecture: rule IDs, per-stage
timings, decision codes, build SHA. An attacker with this information
can:

- Probe rule boundaries (find transformations that bypass detection).
- Time individual rules to identify expensive ones for targeted DoS.
- Map rule IDs and detector names to known WAF vendors / known
  signatures.

Therefore benchmark mode is built **secure-by-default** with three
orthogonal gates: it is off by default, the data plane refuses to
emit benchmark headers unless both the source IP allowlist **and** a
presigned token header match, and any enabled state auto-expires.

## Operating modes

| Mode | Headers | Dashboard panel | Audit | Notes |
|------|---------|-----------------|-------|-------|
| `disabled` (default) | none | hidden | n/a | One bool check at request entry; effectively zero cost. |
| `headers` | `X-Aegis-*` on bench-gated requests | live | summary every 5 s | Production-tolerable for short runs. |
| `verbose` | as above | as above + per-detector live stream | as `headers`, plus a structured benchmark snapshot per 5 s window | For deep dives; never run continuously. |

Mode is a single global setting (toggling per-route is a non-goal for
v1 — see [`#deferred`](#deferred-extensions)).

## Activation gates

A request is **benchmark-gated** iff *all* of the following hold:

1. `benchmark.mode != disabled`.
2. Source IP (post-XFF resolution, same logic as
   [`tiered-protection.md`](tiered-protection.md)) is contained in
   `benchmark.source_allowlist`.
3. The request carries a header named `benchmark.required_header.name`
   whose value is a presigned HMAC over `(timestamp, request_method,
   request_path)` keyed with the secret resolved from
   `benchmark.required_header.secret_ref`. The signature must be
   ≤ 60 s old.

Requests that do not satisfy all three gates are processed normally
and **no `X-Aegis-*` benchmark header is emitted**, regardless of
mode. The benchmark context is not even allocated for them, so the
overhead of running with `mode != disabled` against ungated traffic
is the cost of one bool branch + one CIDR lookup in the request
ingress hot path.

> The `X-Aegis-Request-Id` header (see below) is emitted on **every**
> response regardless of benchmark mode — it is purely the
> standardisation of an existing internal identifier and carries no
> new information.

## Header surface

All benchmark-mode headers use the canonical prefix `X-Aegis-`. This
namespace is reserved by this document; no other feature may emit
headers with this prefix.

### Always-on (independent of benchmark mode)

| Header | Value | Notes |
|--------|-------|-------|
| `X-Aegis-Request-Id` | 16-byte hex | Mirror of the `request_id` already present in audit + access log + error envelope. Standardised here so support tickets can be correlated without reading the audit chain. Cryptographically random (not sequential). |

### Benchmark-only (emitted only on benchmark-gated responses)

| Header | Value | Notes |
|--------|-------|-------|
| `X-Aegis-Tier` | `critical` \| `high` \| `medium` \| `low` | Tier the request landed in. |
| `X-Aegis-Decision` | `allow` \| `block` \| `challenge` | Terminal pipeline decision. |
| `X-Aegis-Overhead-Us` | integer μs | Wall-clock time spent inside the WAF (rule engine + detectors + response filter). Excludes upstream and TLS. |
| `X-Aegis-Upstream-Us` | integer μs | Wall-clock upstream RTT (`upstream_send` to last byte). `0` for blocked or short-circuited requests. |
| `X-Aegis-Detectors` | `name:us[,name:us]…` | Per-detector cost. Names are stable (`rate`, `sqli`, `xss`, `path_traversal`, `ssrf`, `header_inj`, `body_abuse`, `recon`, `bots`, `dlp_in`, `dlp_out`, `api_guard`, `risk`, `challenge`). Detectors that didn't run are omitted. |
| `X-Aegis-Pipeline` | `stage:us;…` | Coarser-grain stage breakdown (`ip;fp;rules;rate;ddos;detect;api;bots;dlp;risk;upstream;respfilter`). Useful when the per-detector list is suppressed. |
| `X-Aegis-Rules` | `R-NNNN[,R-NNNN]…` | Rule ids that fired. **Suppressed** unless `benchmark.expose_rule_ids: true`. Empty header omitted. |
| `X-Aegis-Build` | git short SHA | Same value as `/api/about` `build`. Lets benchmark logs carry the binary identity without a side request. |

Header values are ASCII-only, never longer than 1024 bytes (truncated
with a trailing `;…`), and always emitted via the same response-filter
that adds security headers — so they are subject to the existing
header-injection sanitisation.

## Configuration

Top-level key in `waf.yaml`:

```yaml
benchmark:
  mode: disabled                  # disabled | headers | verbose
  source_allowlist:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
  required_header:
    name: "X-Aegis-Bench-Token"
    secret_ref: "${secret:env:AEGIS_BENCH_TOKEN}"
    signing_window: "60s"         # max signature age
  ttl: "1h"                       # auto-disable after this duration
  max_ttl: "24h"                  # config validator rejects ttl > max_ttl
  expose_rule_ids: false          # opt-in extra info disclosure
  detectors_header: true          # emit X-Aegis-Detectors
  pipeline_header: true           # emit X-Aegis-Pipeline
```

Validation rules (enforced by `aegis-core::config`):

- `mode = disabled` is the canonical "off" state. The `source_allowlist`
  and `required_header` blocks are still validated for shape so the
  config can flip on without a separate edit.
- `source_allowlist` may not be empty if `mode != disabled`. A literal
  `0.0.0.0/0` is permitted for development environments and emits a
  `WARN` in the validator (`benchmark.source_allowlist contains
  0.0.0.0/0 — benchmark headers are now IP-ungated, ensure the token
  secret is strong`).
- `secret_ref` must resolve at startup; missing secret = config rejected
  when `mode != disabled`.
- `ttl` must be ≤ `max_ttl`. A runtime enable call may pass a smaller
  TTL but never larger.
- `expose_rule_ids: true` requires `mode = verbose`. The validator
  rejects `headers` + `expose_rule_ids: true` to keep the lighter
  mode strictly less informative.

## Runtime control

The dashboard and CLI can flip benchmark state without a config
reload. State changes are persisted in process memory (with audit
entry) and the next config reload is the canonical reset point.

### Endpoints (control plane, gated by admin auth)

```
GET  /api/benchmark/status
POST /api/benchmark/enable   { "mode": "headers", "ttl_seconds": 600 }
POST /api/benchmark/disable
GET  /api/benchmark/snapshot?window=60s
```

`/api/benchmark/status` shape:

```jsonc
{
  "configured_mode": "disabled",
  "active_mode":     "headers",
  "ttl_remaining_s": 423,
  "enabled_at":      "2026-04-27T17:30:00Z",
  "enabled_by":      "admin",
  "source_allowlist": ["127.0.0.1/32"],
  "expose_rule_ids":  false
}
```

`/api/benchmark/snapshot` shape (used by the dashboard panel):

```jsonc
{
  "window_seconds": 60,
  "samples": 12053,
  "overhead_us": { "p50": 412, "p95": 1180, "p99": 2240, "max": 4980 },
  "by_detector": [
    { "name": "rate",     "samples": 12053, "p50": 5,   "p95": 12,  "p99": 28 },
    { "name": "sqli",     "samples": 12053, "p50": 80,  "p95": 220, "p99": 410 },
    { "name": "xss",      "samples": 12053, "p50": 22,  "p95": 60,  "p99": 110 }
  ],
  "by_tier": [
    { "tier": "critical", "samples":  402, "p99_us": 3200 },
    { "tier": "high",     "samples": 4810, "p99_us": 2240 }
  ],
  "decisions": { "allow": 11890, "block": 152, "challenge": 11 }
}
```

### CLI (`waf bench`)

```
waf bench enable [--ttl 1h] [--mode headers|verbose]
waf bench disable
waf bench status
```

Both surfaces (API + CLI) emit an audit entry with class `admin` and
action `bench_enable` / `bench_disable`, mirroring the existing
admin-action pattern.

### Auto-disable

Every benchmark enable call schedules a tokio task that flips
`active_mode` back to `disabled` at `enabled_at + ttl`. The reset
emits `bench_auto_disable` to the audit chain.

## Pipeline integration

A request-scoped `BenchmarkContext` is allocated only when the
request is benchmark-gated. Layout:

```rust
pub struct BenchmarkContext {
    pub request_started:     Instant,
    pub waf_started:         Instant,
    pub waf_finished:        Option<Instant>,
    pub upstream_started:    Option<Instant>,
    pub upstream_finished:   Option<Instant>,
    pub stages:              SmallVec<[StageSample; 16]>,
    pub detectors:           SmallVec<[DetectorSample; 16]>,
    pub rules_fired:         SmallVec<[RuleId; 8]>,
    pub tier:                Tier,
    pub decision:            Decision,
}
```

Detectors call `bench.detector("sqli", started)?` once, taking
`Option<&BenchmarkContext>` and skipping if `None`. The wrapper
records `Instant::now() - started` and pushes a `DetectorSample`.

> Hot-path overhead with `bench: None` (the default 99.999% case)
> reduces to a single `is_some()` check and one branch, well below
> the noise floor of the surrounding instructions.

## Prometheus metrics

The existing `waf_request_duration_seconds_bucket` measures total
wall-clock (WAF + upstream). Benchmark mode adds three series:

```
waf_bench_overhead_seconds_bucket{tier,decision}
waf_bench_detector_cost_seconds_bucket{detector}
waf_bench_mode (gauge: 0=disabled, 1=headers, 2=verbose)
```

These series are populated **only** when `mode != disabled` and **only**
for benchmark-gated requests, so production scrapes carry zero extra
data when benchmark mode is off.

## Dashboard

### Tracking page — Benchmark panel

A new tile on [`pages/tracking.md`](dashboard-enterprise/pages/tracking.md):

- Current state (`disabled` | `headers` | `verbose`) + remaining TTL
  countdown.
- Source allowlist summary (`3 CIDRs`, click → drawer).
- "Enable" / "Disable" buttons (admin-auth + CSRF + audit-logged).
- Inline overhead histogram for the last 60 s once mode is on.
- Visible only to operators; the panel is rendered conditionally based
  on `/api/about` returning `benchmark.configured_mode != null`.

### Analytics → Benchmarks subpage

A new entry under the Analytics page (no extra sidebar slot — keeps
the v1 sidebar at 11 items per
[`dashboard-enterprise/layout.md`](dashboard-enterprise/layout.md)):

- p50 / p95 / p99 overhead by tier (multi-series line chart).
- Per-detector cost heatmap (rows = detectors, columns = 1 min
  buckets, colour = p99).
- Top-N expensive rules (only when `expose_rule_ids: true`).
- Time-series WAF overhead vs RPS (dual-axis line).
- "Benchmark mode is currently disabled — enable from the
  [Tracking](/dashboard/tracking) page" banner when off.

## Tests

| Test | Crate | Purpose |
|------|-------|---------|
| `headers_emitted_when_gated` | `aegis-proxy` | Allowlisted IP + valid token → `X-Aegis-Overhead-Us` present and parses as integer. |
| `headers_suppressed_without_token` | `aegis-proxy` | Allowlisted IP, no token → no `X-Aegis-*` benchmark headers (request id still present). |
| `headers_suppressed_off_allowlist` | `aegis-proxy` | Valid token, off-allowlist IP → no headers. |
| `rule_ids_suppressed_by_default` | `aegis-proxy` | Gated request, `expose_rule_ids: false` → no `X-Aegis-Rules`. |
| `auto_disable_after_ttl` | `aegis-control` | Enable with 200 ms TTL → status flips to `disabled` and emits `bench_auto_disable` audit entry. |
| `audit_entry_on_enable` | `aegis-control` | Enable call writes `bench_enable` to audit chain. |
| `verbose_mode_summary_cadence` | `aegis-control` | Verbose mode with 1 s window emits exactly one summary per second under sustained load. |
| `cost_when_disabled_is_below_noise` | `aegis-proxy` (criterion bench) | Same workload with `mode: disabled` shows ≤ 1 % delta vs the baseline (no benchmark feature compiled). |
| `gate_failures_are_audit_logged` | `aegis-proxy` | Wrong-token request to a benchmark-mode endpoint emits one rate-limited `bench_gate_failed` system audit (defends against probing). |
| `header_size_bound` | `aegis-proxy` | Synthetic worst-case (100 detectors, 1000 rules) stays under the 1024-byte truncation point. |

A k6 script under `tests/load/bench-headers.js` reads the
`X-Aegis-Overhead-Us` header on every response and produces a CSV
feeding into the SLO regression harness.

## Deferred extensions

The following are explicitly out of scope for the first benchmark
release. They are listed so future authors don't accidentally rebuild
them from scratch.

- **Per-route benchmark mode.** Mode is global in v1.
- **Trace export of bench samples.** Samples currently flow only via
  headers + Prometheus + the dashboard. OTLP integration would need
  a new `waf.bench` span attribute set; revisit when an explicit
  request comes in.
- **Cross-cluster aggregation.** Each node reports its own snapshot;
  cluster-wide rollup is the operator's job (Prometheus federation /
  Grafana). A `/api/cluster/benchmark` aggregate could land if there
  is demand.
- **Header signing for headers themselves.** The diagnostic headers
  are not authenticated — a downstream proxy could rewrite them. This
  is acceptable: bench mode is opt-in and gated, the headers are
  advisory, and the canonical numbers live in Prometheus.

## Cross-references

- Plan — [`../plans/benchmark-mode.md`](../plans/benchmark-mode.md)
- Performance target — [`../Requirement.md`](../Requirement.md) §3
- Pipeline — [`../Architecture.md`](../Architecture.md) §5
- Observability surface — [`observability-prometheus-otel.md`](observability-prometheus-otel.md)
- Dashboard panels — [`dashboard-enterprise/pages/tracking.md`](dashboard-enterprise/pages/tracking.md),
  [`dashboard-enterprise/pages/analytics.md`](dashboard-enterprise/pages/analytics.md)
- API surface — [`dashboard-enterprise/api.md`](dashboard-enterprise/api.md) §benchmark
- Audit chain — [`audit-logging.md`](audit-logging.md)
