# SigNoz — OTLP observability backend for Aegis-Gate

SigNoz is the chosen backend for Aegis-Gate's OpenTelemetry export
(traces today; metrics + logs next). It's OTel-native, single-stack
(ClickHouse-backed), self-hostable, and ships its own UI — no separate
Grafana/Tempo/Loki wiring.

> **Why SigNoz over the dev stack's Jaeger?** The repo's
> `docker-compose.dev.yml` also runs Jaeger (OTLP `:4317`) + Grafana,
> which is a perfectly good traces path. SigNoz was chosen as the
> primary backend for a single OTel-native pane across all three
> signals. **Don't run both on `:4317`** — pick one OTLP target.

## What the WAF emits

The WAF exports **OTLP gRPC** spans for every `tracing` span when built
with `--features otel` and given an endpoint:

```bash
cargo build -p aegis-bin --features "redis geoip alerts ai affinity otel"
```

```yaml
# config: observability.otel
observability:
  otel:
    endpoint: "http://127.0.0.1:4317"   # SigNoz collector (gRPC)
    sample_ratio: 0.10                   # 10% in prod; 1.0 in dev
    # headers: { "signoz-access-token": "${secret:signoz_token}" }  # SigNoz Cloud
```

The exporter is best-effort: if the collector is unreachable at boot the
WAF still starts and the SDK retries on its batch schedule.

## Bring SigNoz up

SigNoz's stack (ClickHouse + collector + query-service + UI) is large
and version-sensitive, so use **SigNoz's own maintained compose** rather
than a hand-forked copy here:

```bash
git clone -b main https://github.com/SigNoz/signoz.git
cd signoz/deploy/docker
docker compose up -d
```

This exposes (ports vary by SigNoz version):

| Port | Purpose |
|---|---|
| `4317` | OTLP gRPC (point the WAF here) |
| `4318` | OTLP HTTP |
| `8080` or `3301` | SigNoz UI (v0.126+ uses `:8080`) |

> **⚠ First-run onboarding is REQUIRED before any telemetry ingests.**
> Newer SigNoz (v0.126+) has the otel-collector register with the
> query-service over `opamp`, and **registration fails until an
> organization/admin account exists** — the query-service logs
> `cannot create agent without orgId` and the collector **rejects all
> OTLP** (even a direct `curl` to `:4318` resets; ClickHouse stays
> empty). Open the SigNoz UI and create the first admin account/org
> FIRST; ~30s later the collector picks up its config and starts
> ingesting. This is a SigNoz setup step, not a WAF issue.

> **⚠ Port clash:** SigNoz v0.126's UI binds `:8080`, which collides
> with the WAF's default data-plane port. To run both, remap one — e.g.
> change the `signoz` service's published port to `8090:8080` in
> SigNoz's compose, or move the WAF data-plane bind. (`make run-copilot`
> uses `dev.yaml` which binds `:8080`.)

Then point the WAF's `observability.otel.endpoint` at
`http://<signoz-host>:4317`, build with `--features otel`, drive
traffic, and open the SigNoz UI → **Traces** to see `service.name =
aegis-gate` spans.

> SigNoz Cloud: set `endpoint` to the region ingest URL and add the
> `signoz-access-token` header (via the `headers` map + a secret ref).

## Optional: redaction / fan-out via an OTel Collector

WAF spans can carry request URIs / headers (PII, tokens). To scrub
before egress — and to fan out to more than one backend — put an OTel
Collector between the WAF and SigNoz using
[`../otel/collector.yaml`](../otel/collector.yaml): the WAF points at the
Collector (`:4317`), the Collector redacts + exports to SigNoz. This is
the recommended posture for production; direct-to-SigNoz is fine for dev.

## All three signals via the Collector

To get **metrics + logs** into SigNoz alongside traces, run the
in-between Collector ([`../otel/collector.yaml`](../otel/collector.yaml)) —
it's wired for all three:

- **Traces (P1)** — OTLP from the WAF → SigNoz.
- **Metrics (P2)** — the Collector's `prometheus` receiver scrapes the
  WAF's `/metrics` (admin listener `:9443`) and converts to OTLP. **No
  app change** — the existing Prometheus endpoint is reused.
- **Logs (P3)** — the Collector's `filelog` receiver tails the WAF's
  JSON log and converts to OTLP logs. Redirect the WAF's stdout to a
  file the collector can read:
  ```bash
  ./waf run --config config/dev.yaml >> /var/log/aegis/waf.json 2>&1
  ```
  (bind-mount that path into the collector; adjust `filelog.include`).

Point the WAF's `observability.otel.endpoint` at the **Collector**
(`:4317`) instead of SigNoz directly; the Collector redacts + forwards
all three signals to SigNoz.

## Status / roadmap

- ✅ **Traces** over OTLP (app exporter, `--features otel`).
- ✅ **Metrics + Logs** via the Collector (config above) — pending a
  live end-to-end smoke against a running SigNoz.
- ⏳ *Optional* app-side OTLP push for metrics/logs (drops the
  Prometheus scrape / filelog tail) — only if you want to retire those.
- ⏳ SIGTERM flush of the in-flight span batch (`OTEL_PROVIDER` OnceLock
  in `otel.rs` is parked for the shutdown hook).

Plan: [`../../plans/future/observability-otel-and-alerts.md`](../../plans/future/observability-otel-and-alerts.md).
