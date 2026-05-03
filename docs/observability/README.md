# Observability

Metrics, audit, SIEM forwarding, and SLO/SLI alerting. Implementation
lives in `crates/aegis-control/src/{metrics,audit,slo,…}`; per-feature
plans are tracked in [`../../plans/`](../../plans/).

| Doc | Summary |
|---|---|
| [prometheus-otel.md](./prometheus-otel.md) | Metrics families, OTel traces, configurable access logs |
| [audit-logging.md](./audit-logging.md) | Hash-chained audit + change log; AuditedMutate (P1) and verbosity gating (P8) |
| [siem-log-forwarding.md](./siem-log-forwarding.md) | Syslog / CEF / LEEF / OCSF / Kafka cold-tier surface (P8 surface @ `/api/cold-tier`) |
| [slo-sli-alerting.md](./slo-sli-alerting.md) | SLOs, burn-rate alerts, runbooks |

The Prometheus histograms registered for the security pipeline are
documented in
[`prometheus-otel.md`](./prometheus-otel.md#waf-stages); per-stage
latency timing landed under F-T10.
