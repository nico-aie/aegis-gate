# `deploy/` — Dev and Test Infrastructure

Docker-Compose files and helper scripts for running Aegis-Gate and
its dependencies locally. **Not production manifests** — those
live under `deploy/prod/` once we reach W5.

See [`../docs/dependencies.md`](../docs/dependencies.md) for the
authoritative list of services, versions, and fallbacks, and
[`etcd/README.md`](etcd/README.md) for the control-plane key layout.

## Control Plane vs Data Plane

Aegis-Gate runs as two cleanly separated planes. Every service in
this directory belongs to one or the other.

| Plane   | Purpose                                      | Services (compose)         |
|---------|----------------------------------------------|----------------------------|
| Control | Config source of truth, observability, audit | `etcd`, `prometheus`, `jaeger` |
| Data    | Request handling, optional rate-limit store  | (WAF), `redis`*, `httpbin` |

`*` Redis is **optional**. The WAF falls back to an in-memory
counter store when absent. Redis is never used for config — etcd
is the only config source.

## Files

| File                        | Purpose                                   |
|-----------------------------|-------------------------------------------|
| `docker-compose.dev.yml`    | Minimum stack for W1–W3 local development |
| `docker-compose.test.yml`   | Dev stack + attacker / k6 / nuclei / etcdctl containers |
| `prometheus/prometheus.yml` | Scrape config — both planes, `plane=control|data` label |
| `etcd/bootstrap.sh`         | Idempotently seeds `/aegis/config/waf` from `seed.yaml` |
| `etcd/seed.yaml`            | Minimal valid `WafConfig` for dev bring-up |
| `etcd/README.md`            | Key layout, CAS semantics, DR              |

## Quick start

```sh
# Bring up the control plane + optional data-plane add-ons
docker compose -f deploy/docker-compose.dev.yml up -d

# Seed the dev config into etcd (idempotent)
./deploy/etcd/bootstrap.sh

# Run the gateway — it reads config from etcd, not from a file
cargo run -p aegis-bin -- run

# Tear down
docker compose -f deploy/docker-compose.dev.yml down -v
```

The gateway connects to `ETCD_ENDPOINTS=http://localhost:2379` by
default. Override via env var or `--etcd` CLI flag.

## Ports

| Service      | Host port | Plane   | Purpose                                 |
|--------------|-----------|---------|-----------------------------------------|
| waf (data)   | 8443      | data    | TLS data plane                          |
| waf (data)   | 8080      | data    | plaintext data plane (dev only)         |
| waf (admin)  | 9443      | control | dashboard + admin API                   |
| waf (metrics)| 9100      | data    | Prometheus `/metrics`                   |
| etcd         | 2379      | control | config source of truth                  |
| redis        | 6379      | data    | optional counter store                  |
| prometheus   | 9090      | control | UI + query API                          |
| jaeger       | 16686     | control | tracing UI                              |
| httpbin      | 8081      | data    | mock upstream target                    |

Override any of these via environment variables in `.env` (not committed).

## Health checks

Once the stack is up:

```sh
# Control plane
docker exec aegis-etcd etcdctl endpoint health
curl -sf http://localhost:2379/metrics | head
curl -sf http://localhost:9090/-/ready            # Prometheus
curl -sf http://localhost:16686/                  # Jaeger UI

# WAF (after `cargo run`)
curl -sf http://localhost:9100/metrics | head
curl -sf http://localhost:9443/healthz/ready

# Data plane
redis-cli -h localhost ping                       # if Redis on
curl -sf http://localhost:8081/status/200         # httpbin
```

## Interacting with etcd

```sh
# Read the current compiled config
docker exec aegis-etcdctl etcdctl get /aegis/config/waf --print-value-only

# Watch for changes in real time
docker exec -it aegis-etcdctl etcdctl watch --prefix /aegis/config/

# Write a new config from a YAML file on the host
cat config/waf.new.yaml | docker exec -i aegis-etcdctl \
  etcdctl put /aegis/config/waf
```

`aegis-etcdctl` only exists when the **test** compose overlay is
up. For dev-only setups, run `etcdctl` on the host (pointing at
`localhost:2379`) or `docker exec aegis-etcd etcdctl ...`.

## Adding a service

1. Decide which plane it belongs to. Record the answer here and in the table above.
2. Update `docker-compose.dev.yml` (W1–W3 services only) or `docker-compose.test.yml` (test-only tooling).
3. Add a row to `../docs/dependencies.md`.
4. If it changes Prometheus targets, update `prometheus/prometheus.yml` with the correct `plane` label.
5. If the WAF needs to talk to it, make sure there's a fallback for when the service is absent — the WAF must boot without any optional service.
