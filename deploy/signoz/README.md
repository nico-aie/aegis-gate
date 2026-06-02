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

This exposes:

| Port | Purpose |
|---|---|
| `4317` | OTLP gRPC (point the WAF here) |
| `4318` | OTLP HTTP |
| `3301` | SigNoz UI |

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

## Status / roadmap

- ✅ **Traces** over OTLP (this).
- ⏳ **Metrics** — easiest via the Collector's `prometheus` receiver
  scraping the WAF's existing `/metrics` (P2).
- ⏳ **Logs** — OTLP log exporter (P3).
- ⏳ SIGTERM flush of the in-flight span batch (`OTEL_PROVIDER` OnceLock
  in `otel.rs` is parked for the shutdown hook).

Plan: [`../../plans/future/observability-otel-and-alerts.md`](../../plans/future/observability-otel-and-alerts.md).
