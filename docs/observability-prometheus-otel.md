# Observability: Prometheus & OpenTelemetry (v2, new)

> **New in v2.** Prometheus `/metrics` endpoint on the control-plane
> listener, W3C Trace Context propagation, OTLP exporter, and
> configurable access-log formats. See also [`slo-sli-alerting.md`](./slo-sli-alerting.md).

## Purpose

Make the WAF a first-class citizen in modern observability stacks:
Prometheus scrape, Grafana dashboards, distributed traces via OTel,
and nginx-compatible access logs for legacy tooling.

## Prometheus metrics

Exposed on the control-plane listener at `/metrics` (see
[`dashboard.md`](./dashboard.md)). Key series:

### Request / decision
- `waf_requests_total{tenant,route,tier,decision,status}`
- `waf_request_duration_seconds_bucket{tenant,route,tier}` (histogram)
- `waf_response_bytes_bucket{tenant,route}`

### Detection
- `waf_detector_hits_total{detector,tenant,route}`
- `waf_rule_hits_total{rule_id,tenant}`
- `waf_risk_score_bucket{tenant}`

### Upstream
- `waf_upstream_requests_total{pool,member,status}`
- `waf_upstream_duration_seconds_bucket{pool,member}`
- `waf_upstream_circuit_state{pool,member}` (0/1/2)
- `waf_upstream_healthy_members{pool}`

### Challenge
- `waf_challenge_issued_total{level}`
- `waf_challenge_passed_total{level}`
- `waf_challenge_failed_total{level}`

### State backend
- `waf_state_ops_total{backend,op,result}`
- `waf_state_op_duration_seconds_bucket{backend,op}`

### Audit sinks
- `waf_audit_events_total{sink,class}`
- `waf_audit_drops_total{sink,reason}`

### Config
- `waf_config_reloads_total{result}`
- `waf_config_version` (gauge, hash prefix)

### Shadow / retries
- `waf_shadow_requests_total{route}`
- `waf_retries_total{pool,result}`

### Benchmark mode
- `waf_bench_overhead_seconds_bucket{tier,decision}` (histogram, WAF-only portion of latency)
- `waf_bench_detector_cost_seconds_bucket{detector}` (histogram, per-detector cost)
- `waf_bench_mode` (gauge: `0` disabled, `1` headers, `2` verbose)

These series are populated **only** when `benchmark.mode != disabled`
and only for benchmark-gated requests, so production scrapes carry
zero extra cardinality when the feature is off. Full design —
[`benchmark-mode.md`](benchmark-mode.md).

## Traces (OpenTelemetry)

- Every request gets a server span `waf.request`
- Child spans: `waf.rule_engine`, `waf.detect.<name>`, `waf.upstream`,
  `waf.challenge`
- `traceparent` / `tracestate` headers are parsed on inbound and
  forwarded upstream; a new span context is created when absent
- OTLP exporter over gRPC or HTTP/protobuf (feature-gated)

```yaml
otel:
  enabled: true
  exporter: otlp
  endpoint: "http://otel-collector.internal:4317"
  sampler: parent_based_traceidratio
  ratio: 0.05
  resource:
    service.name: waf
    deployment.environment: prod
```

## Access logs

Nginx-compatible `combined` format plus JSON and a custom template.
Written by a dedicated sink (see
[`audit-logging.md`](./audit-logging.md)):

```yaml
access_log:
  enabled: true
  format: custom
  template: '$client_ip - $user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" rt=$request_time rid=$request_id tier=$tier decision=$decision'
```

Variables use `$var` syntax shared with
[`transformations-cors.md`](./transformations-cors.md).

## Response correlation header

Every WAF response carries an `X-Aegis-Request-Id` header whose
value mirrors the `request_id` field in the access log, audit
chain, and error envelope. This is always-on (independent of
benchmark mode) so support tickets can correlate without reading
the audit chain. The id is 16 hex characters of cryptographically
random data, not sequential.

When [benchmark mode](benchmark-mode.md) is enabled and a request
passes its activation gate, additional `X-Aegis-*` headers carry
per-request diagnostics (tier, decision, WAF overhead, per-detector
cost, fired rule ids when permitted).

## Health endpoints

Already listed in [`dashboard.md`](./dashboard.md):

- `/healthz/live` — process alive
- `/healthz/ready` — ready to serve (state backend reachable, certs
  loaded, ≥ 1 healthy upstream member)
- `/healthz/startup` — first config load complete

## Implementation

- `src/obs/metrics.rs` — `prometheus` crate registry
- `src/obs/otel.rs` — OTLP exporter, span helpers
- `src/obs/trace_ctx.rs` — W3C Trace Context parse / propagate
- `src/obs/access_log.rs` — template engine + sink writer

## Performance notes

- Metric increments are lock-free atomics
- Histogram observation is O(log n) on bucket boundaries
- Tracing uses `tracing` with a sampling subscriber; off-path cost is
  near zero when the span is not recorded
