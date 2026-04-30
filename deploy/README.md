# `deploy/` — Dev infrastructure

Docker-Compose files, helper scripts, and reference configs for
running Aegis-Gate and its dependencies locally. **Not production
manifests.**

For dev setup steps see [`../QUICKSTART.md`](../QUICKSTART.md).
For production deployment see [`./GUIDE.md`](./GUIDE.md).

## Contents

| File | Purpose |
|---|---|
| `docker-compose.dev.yml` | Default dev stack — etcd, Prometheus, Jaeger, Redis, httpbin |
| `docker-compose.test.yml` | Adds attacker / k6 / nuclei / etcdctl for the test pyramid |
| `prometheus/prometheus.yml` | Scrape config — both planes labelled `plane=control|data` |
| `etcd/bootstrap.sh` | Idempotently seeds `/aegis/config/waf` from `seed.yaml` |
| `etcd/seed.yaml` | Minimal valid `WafConfig` for dev bring-up |
| `etcd/README.md` | etcd key layout, CAS semantics, DR |
| `haproxy/haproxy.cfg` | Reference LB config for the HA cluster fixture (HA-T1) |
| `pebble/` | ACME test server for cert issuance tests |

## Service ports (default)

| Service | Plane | Port | Purpose |
|---|---|---|---|
| WAF data | data | 8080 / 8443 | plaintext / TLS data plane |
| WAF admin | control | 9443 | dashboard + admin API |
| WAF metrics | data | 9100 | Prometheus `/metrics` |
| etcd | control | 2379 | config source of truth |
| Redis | data | 6379 | optional state store |
| Prometheus | control | 9090 | UI + query API |
| Jaeger | control | 16686 | tracing UI |
| httpbin | data | 8081 | mock upstream |
| HAProxy stats | control | 8404 | LB stats (only with `--profile ha`) |
| HAProxy VIP | data | 9180 / 9443 | plaintext / TLS VIP (only with `--profile ha`) |

Override in a local `.env` (not committed).

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
3. Add a row to [`../docs/dependencies.md`](../docs/dependencies.md).
4. If it changes Prometheus targets, set the right `plane` label
   in `prometheus/prometheus.yml`.
5. Make sure the WAF still boots when the service is absent —
   every dev dep must have a fallback.
