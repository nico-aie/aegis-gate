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

## Local dev observability stack — `make obs-up`

`make obs-up` brings up Prometheus + Grafana + Jaeger via
[`deploy/docker-compose.dev.yml`](../../deploy/docker-compose.dev.yml).
The stack pre-loads three Grafana dashboards (Aegis WAF Overview,
Runtime, Redis) from
[`deploy/grafana/dashboards/`](../../deploy/grafana/dashboards/) and a
Prometheus datasource from
[`deploy/grafana/provisioning/datasources/datasources.yaml`](../../deploy/grafana/provisioning/datasources/datasources.yaml).

URLs (mirror of `make urls`):
- Prometheus: <http://localhost:9090/>
- Grafana: <http://localhost:3000/> (admin/admin)
- Jaeger: <http://localhost:16686/>

### Empty Grafana panels — diagnostic checklist

Symptom: dashboards exist but every panel says "No data". Walk
through these in order:

1. **Is the WAF running?** `make run` (foreground) or `make run-bg`
   in another terminal. Verify with `curl http://localhost:9443/healthz/ready`.
2. **Is `/metrics` reachable from your shell?** `curl http://localhost:9443/metrics | head` should print Prometheus exposition lines starting with `# HELP waf_…`. If not, the WAF binary isn't running or its admin listener isn't bound on a Docker-reachable interface.
3. **Is the admin listener bound on `0.0.0.0` (not `127.0.0.1`)?** Docker containers cannot reach the host's loopback by default. `config/dev.yaml` ships with `listeners.admin.bind: "0.0.0.0:9443"` — if you've forked it to `127.0.0.1:9443`, the Prometheus container scraping `host.docker.internal:9443` will fail.
4. **Is Prometheus actually scraping?** Visit <http://localhost:9090/targets> — the `aegis-waf` job should show `state: UP`. If it's `DOWN`, inspect `lastError` on the same page.
5. **Has the WAF received traffic?** Counter / histogram series are zero-empty until at least one request flows through. Hit the data plane: `curl http://localhost:8080/`. The dashboard time range defaults to "last 1 hour" — give it a few seconds to populate.
6. **Datasource UID match?** If you've forked the dashboards, ensure each `${datasource}` template variable defaults to `aegis-prometheus` (the UID in `datasources.yaml`).
7. **Time window?** Top-right Grafana time range — switch to "Last 5 minutes" if "Last 1 hour" predates the current run.

If after this the panels are still empty: `docker logs -f aegis-prometheus` and `docker logs -f aegis-grafana` will show the actual scrape / dashboard errors.
