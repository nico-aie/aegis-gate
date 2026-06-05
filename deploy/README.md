# `deploy/` — Dev infrastructure

Docker-Compose files, helper scripts, and reference configs for
running Aegis-Gate and its dependencies locally. **Not production
manifests.**

For dev setup steps see [`../QUICKSTART.md`](../QUICKSTART.md).
For a benchmark-ready single Linux host (Docker infra + native
WAF, AI-assistant-driven) see
[`./STAGING-BENCHMARK.md`](./STAGING-BENCHMARK.md).
For multi-node production deployment see [`./GUIDE.md`](./GUIDE.md).
For a **fleet simulation** — one infra host (Redis + multi-protocol mock +
SigNoz + **HAProxy L4/TPROXY** LB) fronting **N WAF nodes**, AI-assistant-
driveable — see [`./HACKATHON-FLEET.md`](./HACKATHON-FLEET.md).
For a **concrete 3-VM deployment** (Cloudflare **DNS-only** + DNS round-robin,
WAF nodes at the TLS edge, shared-Redis cluster, all protocols + full feature
set) see [`./HACKATHON-DEPLOY.md`](./HACKATHON-DEPLOY.md).

## Contents

| File | Purpose |
|---|---|
| `STAGING-BENCHMARK.md` | **Single-Linux-host staging deploy** — Docker infra + native WAF, mechanical step-by-step (Verify / Expected pairs), AI-assistant-driveable |
| `GUIDE.md` | **Production deploy** — multi-node, image, Helm, config plane |
| `HACKATHON-FLEET.md` | **Multi-node fleet sim (generic)** — infra host (Redis + multi-protocol mock + SigNoz + **HAProxy L4/TPROXY** LB) + N WAF nodes at the TLS edge; TPROXY return-routing, per-node config, per-protocol verification, LB-options appendix |
| `HACKATHON-DEPLOY.md` | **Concrete 3-VM deployment** — Cloudflare **DNS-only** + DNS round-robin (no LB box), 2 WAF nodes at the TLS edge + 1 infra VM; DNS-01 wildcard certs, shared-Redis cluster, all protocols, full feature set (JA3/JA4 + per-IP). AI-driveable checklist |
| `docker-compose.dev.yml` | Default dev stack — etcd, Prometheus, Grafana, Jaeger, Redis (+exporter), httpbin |
| `grafana/` | Grafana provisioning + dashboards (datasources auto-loaded, three dashboards file-provisioned) |
| `docker-compose.test.yml` | Adds attacker / k6 / nuclei / etcdctl for the test pyramid |
| `prometheus/prometheus.yml` | Scrape config — both planes labelled `plane=control|data` |
| `haproxy/haproxy.cfg` | Reference LB config for the HA cluster fixture (HA-T1) |
| `pebble/` | ACME test server for cert issuance tests |
| `Dockerfile` | **Production container image** (B6-T1) — multi-stage, distroless `cc`, runs as `nonroot` (uid 65532). Build with `bash deploy/docker-build.sh`. |
| `docker-build.sh` | buildx wrapper for multi-arch (amd64 + arm64) production image builds |
| `helm/aegis-gate/` | **Production Helm chart** (B6-T2) — Deployment + Services (data + admin) + ConfigMap + PDB + NetworkPolicy + optional HPA / ServiceMonitor / Ingress. See `helm/aegis-gate/README.md`. |

## Service ports (default)

| Service | Plane | Port | Purpose |
|---|---|---|---|
| WAF data | data | 8080 / 8443 | plaintext / TLS data plane |
| WAF admin | control | 9443 | dashboard + admin API |
| WAF metrics | data | 9100 | Prometheus `/metrics` |
| etcd | control | 2379 | optional service-discovery store (`sd::etcd`) |
| Redis | data | 6379 | optional state store |
| Prometheus | control | 9090 | UI + query API |
| Grafana | control | 3000 | dashboards UI (anonymous editor in dev; admin / admin) |
| Jaeger | control | 16686 | tracing UI |
| Redis exporter | data | 9121 | Prometheus metrics for Redis |
| httpbin | data | 8081 | mock upstream |
| HAProxy stats | control | 8404 | LB stats (only with `--profile ha`) |
| HAProxy VIP | data | 9180 / 9443 | plaintext / TLS VIP (only with `--profile ha`) |

Override in a local `.env` (not committed).

## Observability stack

The dev compose ships a complete metrics + tracing surface so an
operator can walk into the deploy with zero config.

```
WAF data plane :9100/metrics ─┐
WAF admin     :9443/metrics ─┼─► Prometheus :9090 ──► Grafana :3000
Redis (via exporter :9121)  ─┘                            │
                                                          ▼
WAF (OTel exporter — pending) ───► Jaeger :16686 ◄────────┘
                                              (Grafana cross-links)
```

### Bring it up

```sh
docker compose -f deploy/docker-compose.dev.yml up -d \
  prometheus grafana jaeger redis redis-exporter
# wait ~5 s for grafana-data init
open http://localhost:3000   # admin / admin (anonymous editor too)
```

### Dashboards (file-provisioned)

| Dashboard | UID | Covers |
|---|---|---|
| **Aegis WAF — Overview** | `aegis-waf-overview` | Per-stage request latency (p50/p95/p99 from `waf_request_duration_ms`), heatmap on `total`, request rate, and pre-staged panels for the request/block/challenge/detector counters that light up as instrumentation lands. |
| **Aegis WAF — Redis** | `aegis-redis` | Up/down, connected clients, memory, command rate, keyspace hit ratio, evictions, per-DB key counts, replication slot. |
| **Aegis WAF — Runtime** | `aegis-runtime` | Process CPU / RSS / FDs / uptime from the embedded `prometheus 0.13` client, plus a reserved panel for `aegis_runtime_*` series that ship once the `tokio_unstable` build flag wires in. |

Provisioning lives in `deploy/grafana/`:
- `provisioning/datasources/datasources.yaml` — Prometheus (default) + Jaeger.
- `provisioning/dashboards/dashboards.yaml` — file provider; auto-reloads every 30 s.
- `dashboards/*.json` — the three dashboards above.

### Honest disclosure (audit-driven)

Per the 2026-04-30 storage + observability audit, with status as
of 2026-05-01:

**Prometheus instrumentation — closed (PROM-T1 + PROM-T2 + PROM-T3):**
Every WAF-specific series the dashboards reference now emits live
data on the next traffic event:
- `waf_request_duration_ms{stage}` — per-stage latency histogram (F-T10)
- `waf_requests_total{action}` — request rate by decision (PROM-T1)
- `waf_upstream_members_{healthy,total}{pool}` — pool gauges, synced every 5 s (PROM-T1)
- `waf_detector_hits_total{class}` — per-class firings (PROM-T2)
- `waf_state_backend_ops_total{op,outcome}` — Redis / in-memory dispatch (PROM-T3)
- `waf_audit_events_total{class}` — events flowing through the AuditBus (PROM-T3)

**OTel tracing — exporter wired (OTEL-T2 closed 2026-05-01).**
The OTLP gRPC exporter ships every `tracing` span the WAF
emits to the configured collector. To enable, build with
`cargo build -p aegis-bin --features otel` and set
`cfg.observability.otel.endpoint` (e.g. `"http://jaeger:4317"`)
+ optional `sample_ratio` (default 1.0). On boot you'll see
`INFO: OTLP tracing exporter wired endpoint=...` followed by
JSON-formatted logs (the OTel-mode subscriber). Jaeger is in
the compose so traces appear at `http://localhost:16686` on
first traffic. Default build (no feature) keeps the stdout
JSON layer only and warn-logs if the endpoint is set.

**OTel coverage scope.** Today the exporter ships every span
created by `tracing::info!` / `warn!` etc. — `#[instrument]`
attributes on hot-path functions (request handler entry, audit
emit, state-backend dispatch) is the next slice (OTEL-T3) and
will produce richer per-request span trees in Jaeger.

**Tokio runtime metrics** (`aegis_runtime_active_workers` /
`aegis_runtime_blocking_queue_depth`) need the `tokio_unstable`
build flag — a follow-up to the Runtime dashboard's reserved
panel.

### Production hardening

In production: set `GF_SECURITY_ADMIN_PASSWORD` from a secret, set
`GF_AUTH_ANONYMOUS_ENABLED=false`, drop the `redis-exporter` if
your prod deploy uses managed Redis (CloudWatch / ElastiCache /
Memorystore exposes its own metrics). The Helm chart will pick up
a tweaked compose layout in a follow-up.

## HA-cluster fixture (opt-in)

When you want to drive two WAF nodes through a single VIP — the
production topology — add the `ha` profile:

```sh
# 1. Build with redis support
cargo build -p aegis-bin --release --features redis

# 2. Bring up the LB (HAProxy)
docker compose -f deploy/docker-compose.dev.yml --profile ha up -d aegis-lb

# 3. Start two WAF nodes against the cluster fixtures
target/release/waf run --config config/cluster-a.yaml &  # :8080 / admin :9443
target/release/waf run --config config/cluster-b.yaml &  # :8090 / admin :9543

# 4. Hit the VIP — HAProxy load-balances to both
curl -sI http://127.0.0.1:9180/

# 5. Stats — proves both backends served traffic
curl -s 'http://127.0.0.1:8404/;csv' | awk -F, '$1=="cluster_http"{print $2,$8}'

# 6. Tear down
pkill -f 'target/release/waf'
docker compose -f deploy/docker-compose.dev.yml --profile ha down
```

Topology, LB recipes for production, and design rationale:
[`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md).
The cluster smoke + LB tests live under
[`../tests/cluster/`](../tests/cluster/) (`05` and `06` are gated
by `AEGIS_LB_TESTS=1`).

## Adding a service

1. Decide which plane it belongs to and update the table above.
2. Add it to `docker-compose.dev.yml` (W1–W3 services only) or
   `docker-compose.test.yml` (test-only tooling).
3. Add a row to [`../docs/dependencies.md`](./dependencies.md).
4. If it changes Prometheus targets, set the right `plane` label
   in `prometheus/prometheus.yml`.
5. Make sure the WAF still boots when the service is absent —
   every dev dep must have a fallback.
