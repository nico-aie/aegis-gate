# `waf.yaml` configuration reference

Every top-level block of `waf.yaml`, the operator-relevant knobs
inside it, the default value, and a link to the deep-dive doc when
one exists. Sized so an operator can scan it in 5 minutes; the
authoritative per-field doc-comments live on the Rust structs in
[`crates/aegis-core/src/config.rs`](../crates/aegis-core/src/config.rs).

> **Picking which file to start from:** see
> [`README.md`](./README.md) for the profile decision tree.
> **Hot-reloadable vs restart-only:** most fields hot-reload via
> the config-watcher; restart-only knobs are flagged in each
> section.

---

## Top-level layout

```yaml
node:        { … }   # cluster identity
listeners:   { … }   # bind addresses
tls:         { … }   # cert sources
routes:      [ … ]   # path → upstream
upstreams:   { … }   # backend pools
detectors:   { … }   # OWASP + Phase F detector toggles + per-tier mask
ai:          { … }   # ONNX classifier
risk:        { … }   # cumulative-score + strike thresholds
load_mode:   { … }   # auto-degradation triggers
load_shedder:{ … }   # adaptive concurrency
ddos:        { … }   # per-IP burst + EWMA spike
rate_limit:  { … }   # per-IP token bucket
state:       { … }   # in-memory or Redis-backed
admin:       { … }   # dashboard auth + listener
audit:       { … }   # chain + sinks
slo:         { … }   # SLO + alert receivers
compliance:  { … }   # PCI/HIPAA/SOC2/GDPR/FedRAMP profile clamp
gitops:      { … }   # git poll
runtime:     { … }   # workers + CPU pin
interop:     { … }   # control-plane contract
logging:     { … }   # verbosity
proxy:       { … }   # global body cap
```

---

## `node`

Stable identity for HA clustering. Required when `state.backend: redis`.

| Field | Default | Notes |
|---|---|---|
| `id` | `waf-1` | Used for leader election + audit `node_id` field |
| `region` | `unknown` | Optional region tag — surfaces in audit + dashboard |

```yaml
node:
  id: waf-a
  region: us-east-1
```

Deep-dive: [`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md).

---

## `listeners`

Bind addresses for the data plane (where traffic enters) and the
admin plane (where the dashboard + control-plane API live).

| Field | Default | Notes |
|---|---|---|
| `data[]` | required | List of `{ bind, tls }` — usually `:8080` plain + `:8443` TLS |
| `admin.bind` | `127.0.0.1:9443` | **Never expose to the public internet** |
| `force_https.bind` | unset | Optional plain-HTTP listener that 301-redirects to TLS |

```yaml
listeners:
  data:
    - bind: 0.0.0.0:8080
      tls: false
    - bind: 0.0.0.0:8443
      tls: true
  admin:
    bind: 10.0.0.5:9443        # internal address only
```

**Restart-only:** listener bind addresses don't hot-reload.

Deep-dive: [`docs/architecture/protocols.md`](../docs/architecture/protocols.md).

---

## `tls`

Cert sources for any `data` listener marked `tls: true`. Pick one
of `certificates` (file-backed) or `acme` (Let's Encrypt).

| Field | Default | Notes |
|---|---|---|
| `min_version` | `"1.2"` | `"1.2"` or `"1.3"`; FIPS clamp forbids < 1.2 |
| `certificates[]` | unset | List of `{ cert_path, key_ref, hosts }` |
| `acme.email` | unset | Required when using ACME |
| `acme.directory_url` | LE prod | Override for staging / private CA |

```yaml
tls:
  min_version: "1.3"
  certificates:
    - cert_path: /etc/aegis/tls.crt
      key_ref:   "${secret:file:/etc/aegis/tls.key}"
      hosts:     [api.example.com]
```

Deep-dive: [`docs/data-plane/tls-termination.md`](../docs/data-plane/tls-termination.md).

---

## `routes`

Path-prefix or host+path matching, each mapped to one `upstreams.*`
pool. First match wins (most-specific paths first).

| Field | Default | Notes |
|---|---|---|
| `id` | required | Stable name; used in audit + dashboard |
| `path` | required | Match string (e.g. `/api/`) |
| `match_type` | `prefix` | `prefix` or `exact` |
| `upstream` | required | Key into `upstreams` |
| `quota.client_max_body_size` | inherits `proxy.max_body_bytes` | Per-route body cap |

```yaml
routes:
  - id: api-v1
    path: /api/v1/
    match_type: prefix
    upstream: api-pool
    quota:
      client_max_body_size: 5242880    # 5 MiB just for /api/v1/
```

Deep-dive: [`docs/data-plane/routing-ingress.md`](../docs/data-plane/routing-ingress.md)
+ [`docs/data-plane/per-route-quotas.md`](../docs/data-plane/per-route-quotas.md).

---

## `upstreams`

Backend pools — addresses, load-balancing, health, circuit breaker.

| Field | Default | Notes |
|---|---|---|
| `<pool>.members[]` | required | `{ addr, weight, zone, host_header }` |
| `<pool>.lb` | `round_robin` | `round_robin` / `least_conn` / `weighted` |
| `<pool>.health` | unset | `{ path, interval_ms, timeout_ms }` for active probes |
| `<pool>.circuit_breaker` | unset | `{ error_rate_threshold, open_duration_ms }` |
| `<pool>.connection.max_idle_per_host` | 32 | TCP keep-alive pool size |

```yaml
upstreams:
  api-pool:
    members:
      - { addr: 10.0.1.10:8080, weight: 1 }
      - { addr: 10.0.1.11:8080, weight: 1 }
    lb: least_conn
    health:
      path: /healthz
      interval_ms: 5000
      timeout_ms: 1000
```

Deep-dive: [`docs/data-plane/upstream-pools.md`](../docs/data-plane/upstream-pools.md).

---

## `detectors`

OWASP + Phase F detector chain. Each class is hot-toggleable via
the dashboard (Detectors page) or `PUT /api/detectors`. Per-tier
overrides under `per_tier` flip a class on/off for one traffic
tier without changing the global mask.

| Class | Default | Notes |
|---|---|---|
| `sqli`, `xss`, `path_traversal`, `ssrf`, `header_injection`, `body_abuse`, `recon`, `brute_force`, `command_injection`, `template_injection`, `nosql_injection` | `enabled: true` | OWASP-style pattern detectors |
| `open_redirect` | `enabled: true` | Plus `allowed_domains[]` operator allowlist |
| `behavior_signals` | `enabled: false` | Stateful per-IP (no_ua, missing_referer, zero_depth). Default OFF — see [`docs/security/detectors/behavior-signals.md`](../docs/security/detectors/behavior-signals.md) |
| `velocity` | `enabled: true` | Cross-endpoint sequence engine (login→deposit). Zero cost when upstream has no matching routes |
| `canary` | `enabled: false` | Operator-supplied recon tripwire — also gated by `risk.canary_paths` |
| `per_tier.<tier>.<class>` | unset | Per-tier override; `None` inherits global |
| `persistence.path` | unset | File-backed snapshot of dashboard mask edits across restart |

```yaml
detectors:
  sqli:             { enabled: true }
  xss:              { enabled: true }
  behavior_signals: { enabled: true }
  open_redirect:
    enabled: true
    allowed_domains:
      - my-app.com
      - "*.safe.example"
  per_tier:
    critical:
      brute_force: true
    low:
      recon: false
  persistence:
    path: /var/lib/aegis/detector-mask.json
```

Deep-dive: per-detector pages under
[`docs/security/detectors/`](../docs/security/detectors/) — one
`.md` per class with score, surface, and tuning notes. Index:
[`docs/security/detectors/README.md`](../docs/security/detectors/README.md).

---

## `ai`

ONNX-classifier detector. Lives in a sibling block (not under
`detectors:`) because the model load + AtomicBool runtime gate
are separate from the bitmask. As of 2026-05-19 the AI mask bit
is also reflected in the dashboard Detectors page and per-tier
overrides apply.

| Field | Default | Notes |
|---|---|---|
| `enabled` | `false` | **Off by default** — the bundled model over-fires below threshold 0.95 |
| `model_path` | unset | Path to the ONNX classifier (build with `--features ai`) |
| `confidence_threshold` | `0.85` | Don't ship `enabled: true` below `0.95` without a per-deployment calibration pass |

```yaml
ai:
  enabled: true
  model_path: data/ai_model/waf_model.onnx
  confidence_threshold: 0.95
```

Hot-flippable via `PUT /api/ai/enabled` (audit-mutated).

---

## `risk`

Cumulative per-IP risk score (decaying) plus per-IP lifetime
strike counter. Detector hits increase the score; sustained
high-risk IPs eventually trip the strike block.

| Field | Default | Notes |
|---|---|---|
| `weights.detector_hit` | `25` | Score added per detector firing |
| `weights.bad_asn` / `bad_ja4` / `failed_auth` / `bot_unknown` / `repeat_offender` | various | See [`docs/security/risk-scoring.md`](../docs/security/risk-scoring.md) |
| `decay_half_life` | `"5m"` | How fast accumulated score decays |
| `thresholds.challenge_at` | `30` | Score threshold for challenge tier |
| `thresholds.block_at` | `70` | Score threshold for block tier |
| `thresholds.max` | `100` | Hard ceiling (clamped on update) |
| `strikes.block_at` | `50` | Lifetime strikes that trip permanent block |
| `trust_recovery.per_hour` | `30` | Trust-recovery rate when an IP behaves |
| `canary_paths[]` | `[]` | Hit on any of these → auto-block. Consumed by the `canary` detector |

```yaml
risk:
  weights:
    detector_hit: 25
    failed_auth: 20
    bad_ja4: 10
  decay_half_life: "5m"
  thresholds:
    challenge_at: 30
    block_at:     70
    max:          100
  strikes:
    block_at: 50
  canary_paths:
    - /wp-admin
    - /.env
```

Hot-reloadable via dashboard (Traffic Gates → #3) or
`PUT /api/risk/thresholds`. Operator playbook:
[`docs/operator/risk-tuning.md`](../docs/operator/risk-tuning.md).

---

## `load_mode`

Three auto-degradation tiers — `normal`, `elevated`, `critical`.
Detector chain ratchets down in the latter two so the gateway
keeps serving under sustained pressure.

| Field | Default | Notes |
|---|---|---|
| `elevated_rps` | `500` | Trigger threshold (rolling RPS) for `elevated` |
| `critical_rps` | `2000` | Trigger threshold for `critical` |
| `sample_interval` | `"1s"` | Rolling window size |
| `hysteresis` | `0.10` | Avoids flap — `next - hysteresis` to drop back |

```yaml
load_mode:
  elevated_rps:   500
  critical_rps:   2000
  sample_interval: 1s
  hysteresis:      0.10
```

Deep-dive: [`docs/data-plane/graceful-degradation.md`](../docs/data-plane/graceful-degradation.md).

---

## `load_shedder`

Adaptive concurrency limiter (Gradient2). When the in-flight
count exceeds the auto-tuned limit, the data plane returns 503 +
`Retry-After: 1` to lower-tier requests; Critical-tier traffic is
never shed.

| Field | Default | Notes |
|---|---|---|
| `enabled` | `true` | Round-3 resilience scoring depends on this |
| `initial_limit` | `1000` | Starting concurrency cap |
| `min_limit` | `100` | Floor — Gradient2 won't tune below this |

Deep-dive: source comments in
[`crates/aegis-proxy/src/shed.rs`](../crates/aegis-proxy/src/shed.rs).

---

## `ddos`

Per-IP sliding-window burst gate + cluster-wide EWMA spike
detection. Returns 403 + `X-WAF-Action: block` on burst-exceed
and auto-blocks the offending IP for `block_ttl_s` seconds.

| Field | Default | Notes |
|---|---|---|
| `enabled` | `true` | Hot-flippable from dashboard (2026-05-19) |
| `observe_only` | `false` | Audit-only — never 403s |
| `per_ip_limit` | `1000` | Requests per window |
| `per_ip_window_s` | `60` | Sliding window (seconds) |
| `block_ttl_s` | `300` | Auto-block duration |
| `spike_multiplier` | `3.0` | Cluster-spike trigger: current > baseline × this |
| `tightened_per_ip_rps` | `20` | Tightened cap when spike is active |
| `tier_overrides.<tier>` | unset | Per-tier per_ip_limit + window |
| `failure_mode.<tier>` | tier default | `fail_close` / `fail_open` on backend error |

```yaml
ddos:
  enabled: true
  observe_only: false
  per_ip_limit:        1000
  per_ip_window_s:     60
  block_ttl_s:         300
  spike_multiplier:    3.0
  tightened_per_ip_rps: 20
```

Hot-flippable; deep-dive: [`docs/security/ddos-protection.md`](../docs/security/ddos-protection.md).

---

## `rate_limit`

Per-IP token-bucket limiter. Distinct from DDoS: rate-limit returns
**429** (not 403) and doesn't auto-block; tune for steady-state
budget, use DDoS for sustained-flood quarantine.

| Field | Default | Notes |
|---|---|---|
| `enabled` | `true` | Hot-flippable |
| `requests_per_window` | `100` | Token-bucket capacity |
| `window` | `"60s"` | Refill interval |

Deep-dive: [`docs/security/rate-limiting.md`](../docs/security/rate-limiting.md).

---

## `state`

Where per-IP counters, leader leases, and the strike map live.

| Field | Default | Notes |
|---|---|---|
| `backend` | `in_memory` | `in_memory` (single node) or `redis` (HA) |
| `redis.urls[]` | unset | Required when `backend: redis` |
| `redis.pool_size` | `16` | Connection pool |
| `redis.timeout` | `"100ms"` | Per-op timeout |

```yaml
state:
  backend: redis
  redis:
    urls: ["redis://aegis-redis:6379"]
    pool_size: 16
    timeout: "100ms"
```

Deep-dive: [`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md).

---

## `admin`

Dashboard authentication, CSRF, session cookies, optional mTLS.

| Field | Default | Notes |
|---|---|---|
| `dashboard_auth.users[]` | empty | `{ user, password_hash, totp_secret_b32 }` |
| `dashboard_auth.ip_allowlist[]` | empty (allow-all) | CIDRs of operator subnets |
| `dashboard_auth.csrf_secret_ref` | inline placeholder | Use `${secret:*}` in prod |
| `dashboard_auth.max_request_body_bytes` | `1 MiB` | Per-request cap on the admin plane |
| `dashboard_auth.session_idle_seconds` | `3600` | Session-cookie TTL |
| `dashboard_auth.allow_ca_upload` | `false` | Opt-in for the mTLS CA-bundle upload card |
| `mtls.mode` | `optional` | `disabled` / `optional` / `required` |

```yaml
admin:
  bind: 10.0.0.5:9443
  dashboard_auth:
    users:
      - user: admin
        password_hash: "${secret:vault:secret/aegis/admin#hash}"
        totp_secret_b32: "${secret:vault:secret/aegis/admin#totp}"
    ip_allowlist:
      - 10.0.0.0/8
    csrf_secret_ref: "${secret:vault:secret/aegis/csrf#value}"
```

Deep-dive: [`docs/control-plane/dashboard-auth.md`](../docs/control-plane/dashboard-auth.md).

---

## `audit`

Hash-chained audit log of every decision + every mutation. Two
sinks run in parallel: the **operator sink** (`audit.sinks`) for
SIEM forwarding, and the **contract sink** (`interop.audit_path`)
for the benchmark / Round-2 contract.

| Field | Default | Notes |
|---|---|---|
| `sinks[]` | empty (in-memory ring only) | jsonl, syslog, kafka, splunk, S3 — see deep-dive |
| `chain.enabled` | `true` | Hash-chain every event |
| `retention` | `"7d"` | jsonl rotation |
| `pseudonymize_ip` | `false` | PII clamp — replaces IPs with stable hashes |

```yaml
audit:
  sinks:
    - jsonl:
        path: /var/log/aegis/audit.jsonl
  chain:
    enabled: true
  retention: 30d
  pseudonymize_ip: true
```

Deep-dive: [`docs/observability/audit-logging.md`](../docs/observability/audit-logging.md).

---

## `slo`

SLO definitions + multi-burn alert receivers (VipTalk / Slack /
PagerDuty / generic webhook).

| Field | Default | Notes |
|---|---|---|
| `objectives[]` | sane defaults | `{ name, target, window }` |
| `receivers[]` | empty | Where to ship burn-rate alerts |
| `alert_routing` | tier-based | Override per-objective routing |

Deep-dive: [`docs/observability/slo-sli-alerting.md`](../docs/observability/slo-sli-alerting.md).

---

## `compliance`

Compliance profile clamp. Today the clamp is **deferred** — the
`modes` list is informational (shows on the Compliance dashboard)
but doesn't pin any detector class on (`COMPLIANCE_PINNED` is
empty). Re-enable by repopulating the const and the clamp logic
in `enforce_compliance_clamp`.

| Field | Default | Notes |
|---|---|---|
| `modes[]` | empty | `pci`, `hipaa`, `soc2`, `gdpr`, `fedramp`, `fips` |

Deep-dive: [`docs/operations/compliance.md`](../docs/operations/compliance.md).

---

## `gitops`

Pull config from a Git repo on a schedule. Optional — disabled by
default; alternative to filesystem hot-reload.

| Field | Default | Notes |
|---|---|---|
| `enabled` | `false` | Opt-in |
| `repo` | unset | Git URL |
| `branch` | `main` | Branch to track |
| `path` | `waf.yaml` | Path within the repo |
| `poll_interval` | `"30s"` | How often to fetch |

Deep-dive: [`docs/control-plane/gitops-change-management.md`](../docs/control-plane/gitops-change-management.md).

---

## `runtime`

Tokio worker count + CPU pinning. **Restart-only.**

| Field | Default | Notes |
|---|---|---|
| `workers` | num_cpus | Worker thread count |
| `cpu_affinity[]` | unset | CPU IDs to pin workers to |
| `blocking_threads` | `512` | Tokio blocking-pool size |

Deep-dive: [`docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md).

---

## `interop`

External control-plane contract (`/__waf_control/*` endpoints).
The benchmark harness drives this; humans usually leave it on
with default settings.

| Field | Default | Notes |
|---|---|---|
| `enabled` | `true` | Required for Round-2 scoring |
| `audit_path` | `./waf_audit.log` | Contract audit log path (§6) |
| `benchmark_secret_ref` | inline placeholder | `X-Benchmark-Secret` header value; use `${secret:*}` in prod |

Deep-dive: [`plans/archive/interop-contract.md`](../plans/archive/interop-contract.md)
+ [`docs/control-plane/api.openapi.yaml`](../docs/control-plane/api.openapi.yaml)
for the request/response shapes.

---

## `logging`

Tracing verbosity. Hot-flippable via the v2.3 control plane.

| Field | Default | Notes |
|---|---|---|
| `verbosity` | `info` | `silent` / `error` / `warn` / `info` / `debug` / `trace` |

---

## `proxy`

Global request-body cap. Per-route override:
`routes[].quota.client_max_body_size`.

| Field | Default | Notes |
|---|---|---|
| `max_body_bytes` | `10485760` (10 MiB) | Requests over this return 413 |

```yaml
proxy:
  max_body_bytes: 52428800       # 50 MiB
```

---

## Where the source-of-truth field docs live

Every field on `WafConfig` and its sub-structs has a `///` doc
comment in [`crates/aegis-core/src/config.rs`](../crates/aegis-core/src/config.rs).
Open the struct, the field, read the comment — it explains the
intent, the default, and any non-obvious interaction. The
inline `# comments` in `prod-balanced.yaml` repeat the same
narrative in YAML form.

For things this reference doesn't cover (rule DSL, audit
chain semantics, mTLS layer details, etc.), follow the deep-dive
link in each section.
