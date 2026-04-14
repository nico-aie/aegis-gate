# External Dependencies

Authoritative list of services Aegis-Gate talks to, their role,
feature flag, fallback when absent, and the week they first matter
in the implementation plan.

> **Rule of thumb.** Only Prometheus is "nice to have from day one".
> Everything else has a working fallback so a developer can build
> and run the gateway on a laptop with zero external services.

## Required / Optional Matrix

| Service                    | Required? | Feature flag | Used by                        | Fallback when absent              | First needed |
|----------------------------|-----------|--------------|--------------------------------|-----------------------------------|--------------|
| Redis 7+                   | optional  | `redis`      | M1 `StateBackend`              | `in_memory` backend, single-node  | W5 (HA)      |
| Redis Cluster              | optional  | `redis`      | M1 `StateBackend` (sharded)    | single-node Redis or in-memory    | W5 (HA)      |
| Raft (embedded `openraft`) | optional  | `raft`       | M1 `StateBackend` (air-gapped) | Redis or in-memory                | W6+          |
| HashiCorp Vault            | optional  | `vault`      | M3 `SecretProvider`            | `env` + `file` providers          | W4           |
| AWS Secrets Manager        | optional  | `aws-sm`     | M3 `SecretProvider`            | `env` + `file` providers          | W4           |
| GCP Secret Manager         | optional  | `gcp-sm`     | M3 `SecretProvider`            | `env` + `file` providers          | W4           |
| Azure Key Vault            | optional  | `azure-kv`   | M3 `SecretProvider`            | `env` + `file` providers          | W4           |
| Prometheus 2.45+           | recommended | always     | M3 `/metrics` scrape           | none — metrics still exposed      | W3           |
| OTLP collector (Jaeger/Tempo) | optional | `otel`      | M3 tracing exporter            | tracing disabled                  | W3           |
| MaxMind GeoLite2 (City+ASN) | optional | always      | M2 geoip + ASN reputation      | geoip disabled, ASN skipped       | W3           |
| IP reputation feeds        | optional  | always       | M2 threat intelligence         | empty feed, no reputation deltas  | W4           |
| STIX/TAXII / MISP          | optional  | always       | M2 threat intel feeds          | empty feed                        | W4           |
| ClamAV (or ICAP server)    | optional  | `icap`       | M2 content scanning            | scanning disabled                 | W5           |
| Consul                     | optional  | `consul`     | M1 service discovery           | `file` / `dns_srv` discovery      | W4           |
| etcd                       | optional  | `etcd`       | M1 service discovery           | `file` / `dns_srv` discovery      | W4           |
| Kubernetes API             | optional  | `k8s`        | M1 service discovery           | `file` / `dns_srv` discovery      | W4           |
| Kafka                      | optional  | `kafka`      | M3 audit sink                  | JSONL sink                        | W5           |
| Splunk HEC                 | optional  | always       | M3 audit sink                  | JSONL sink                        | W5           |
| SIEM (Syslog/CEF/LEEF/OCSF) | optional | always       | M3 audit sink                  | JSONL sink                        | W5           |
| ACME server (e.g. Let's Encrypt) | optional | `acme`  | M1 TLS cert issuance           | manual cert files in config       | W4           |
| OCSP responder             | optional  | always       | M1 TLS stapling                | stapling disabled                 | W4           |
| HSM / PKCS#11              | optional  | `hsm`        | M1 TLS private keys            | software keys                     | W6+          |
| OIDC IdP (e.g. Keycloak)   | optional  | always       | M3 admin login                 | API tokens + Basic auth           | W4           |
| OPA                        | optional  | `opa`        | M2 policy decisions            | built-in rule engine only         | W5           |

## Dev Defaults (what `deploy/docker-compose.dev.yml` runs)

The dev compose file brings up only the services needed for the
Week 1–3 milestones. Everything else is added as that week's
integration work starts.

| Service       | Image                       | Port  | Purpose                        |
|---------------|-----------------------------|-------|--------------------------------|
| Redis         | `redis:7-alpine`            | 6379  | State backend (optional)       |
| Prometheus    | `prom/prometheus:v2.51.0`   | 9090  | Scrapes `waf:9100/metrics`     |
| Jaeger        | `jaegertracing/all-in-one:1.57` | 16686 | OTLP collector + UI       |
| Upstream mock | `mccutchen/go-httpbin:v2.15.0` | 8080 | Backend target for smoke tests |

## Production Version Pins

When running against real infrastructure, these are the minimum
versions we test against. Older versions may work but are not
supported.

- Redis: **7.2** (sliding-window Lua scripts assume 7.x atomics)
- Vault: **1.15** (kv v2 engine)
- Prometheus: **2.45** (native histograms)
- OTLP collector: any version speaking OTLP/gRPC 1.0
- Consul: **1.18**, etcd: **3.5**, Kubernetes: **1.28**
- Kafka: **3.5** (idempotent producer)
- OpenSSL / rustls: rustls 0.23+, or `fips` feature (BoringSSL + FIPS module)

## When Each Dependency Enters the Plan

| Week | Milestone                           | New dependencies introduced        |
|------|-------------------------------------|------------------------------------|
| W1   | `./waf run` boots, `NoopPipeline`   | none (everything in-memory)        |
| W2   | First SQLi rule blocks              | none                               |
| W3   | TLS + JWT + Prometheus scrape       | Prometheus, GeoLite2 (optional)    |
| W4   | OIDC admin login, tenant isolation  | Vault, OIDC IdP, ACME, Consul (any)|
| W5   | 2-node HA, red-team suite, 5k RPS   | Redis Cluster, ICAP, Kafka         |
| W6+  | Air-gapped / FIPS deployments       | Raft, HSM                          |

## Adding a New Dependency

1. Add a row to the matrix above in the same PR that introduces the dependency.
2. Add (or justify skipping) a feature flag in `Cargo.toml`.
3. Document the fallback behavior when the dependency is absent.
4. If it changes the dev bring-up, update `deploy/docker-compose.dev.yml` and `deploy/README.md`.
5. If it has a minimum version, add it to **Production Version Pins** above.
