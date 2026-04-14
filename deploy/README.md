# `deploy/` — Dev and Test Infrastructure

Docker-Compose files and helper scripts for running Aegis-Gate and
its dependencies locally. **Not production manifests** — those
live under `deploy/prod/` once we reach W5.

See [`../docs/dependencies.md`](../docs/dependencies.md) for the
authoritative list of services, versions, and fallbacks.

## Files

| File                        | Purpose                                   |
|-----------------------------|-------------------------------------------|
| `docker-compose.dev.yml`    | Minimum stack for W1–W3 local development |
| `docker-compose.test.yml`   | Dev stack + attacker container + mock upstream for security/load tests |
| `prometheus/prometheus.yml` | Scrape config pointing at `waf:9100`      |

## Quick start

```sh
# Bring up Redis, Prometheus, Jaeger, and a mock upstream
docker compose -f deploy/docker-compose.dev.yml up -d

# Run the gateway against the dev stack
cargo run -p aegis-bin -- run --config config/waf.dev.yaml

# Tear down
docker compose -f deploy/docker-compose.dev.yml down -v
```

## Ports

| Service      | Host port | Purpose                                 |
|--------------|-----------|-----------------------------------------|
| waf (data)   | 8443      | TLS data plane                          |
| waf (data)   | 8080      | plaintext data plane (dev only)         |
| waf (admin)  | 9443      | admin API + dashboard                   |
| waf (metrics)| 9100      | Prometheus `/metrics`                   |
| redis        | 6379      | state backend                           |
| prometheus   | 9090      | UI + query API                          |
| jaeger       | 16686     | tracing UI                              |
| httpbin      | 8081      | mock upstream target                    |

Override any of these via environment variables in
`.env` (not committed).

## Health checks

Once the stack is up:

```sh
curl -sf http://localhost:9100/metrics | head
curl -sf http://localhost:9443/healthz/ready
curl -sf http://localhost:9090/-/ready         # Prometheus
curl -sf http://localhost:16686/               # Jaeger UI
```

## Adding a service

1. Update `docker-compose.dev.yml` (keep it minimal — only services
   needed for W1–W3 go here; test-only dependencies go in
   `docker-compose.test.yml`).
2. Add a row to `docs/dependencies.md`.
3. If the gateway needs the service, add a corresponding block to
   `config/waf.dev.yaml`.
