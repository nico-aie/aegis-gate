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
| **etcd 3.5+**              | **required** | always    | M3 `ConfigStore` + leases + `etcd` secret provider | local `last-good-config.yaml` cache (read-only, banner) | W1 |
| Redis 7+                   | optional  | `redis`      | M1/M2 `CounterStore` (rate limits, cache) — **NOT config** | `InMemoryCounterStore`, single-node | W5 (HA) |
| Redis Cluster              | optional  | `redis`      | M1/M2 `CounterStore` (sharded) | single-node Redis or in-memory    | W5 (HA)      |
| HashiCorp Vault            | deferred  | `vault`      | M3 `SecretProvider` (future)   | `env` + `file` + `etcd` providers | deferred     |
| AWS / GCP / Azure secret managers | deferred | `aws-sm`/`gcp-sm`/`azure-kv` | M3 `SecretProvider` (future) | `env` + `file` + `etcd` providers | deferred |
| Prometheus 2.45+           | recommended | always     | M3 `/metrics` scrape           | none — metrics still exposed      | W3           |
| OTLP collector (Jaeger/Tempo) | optional | `otel`      | M3 tracing exporter            | tracing disabled                  | W3           |
| MaxMind GeoLite2 (City+ASN) | optional | always      | M2 geoip + ASN reputation      | geoip disabled, ASN skipped       | W3           |
| IP reputation feeds        | optional  | always       | M2 threat intelligence         | empty feed, no reputation deltas  | W4           |
| STIX/TAXII / MISP          | optional  | always       | M2 threat intel feeds          | empty feed                        | W4           |
| ClamAV (or ICAP server)    | optional  | `icap`       | M2 content scanning            | scanning disabled                 | W5           |
| Consul                     | deferred  | `consul`     | M1 service discovery (future)  | `file` / `dns_srv` / `etcd` SD    | deferred     |
| Kubernetes API             | deferred  | `k8s`        | M1 service discovery (future)  | `file` / `dns_srv` / `etcd` SD    | deferred     |
| Kafka                      | optional  | `kafka`      | M3 audit sink                  | JSONL sink                        | W5           |
| Splunk HEC                 | optional  | always       | M3 audit sink                  | JSONL sink                        | W5           |
| SIEM (Syslog/CEF/LEEF/OCSF) | optional | always       | M3 audit sink                  | JSONL sink                        | W5           |
| ACME server (e.g. Let's Encrypt) | optional | `acme`  | M1 TLS cert issuance           | manual cert files in config       | W4           |
| OCSP responder             | optional  | always       | M1 TLS stapling                | stapling disabled                 | W4           |
| HSM / PKCS#11              | optional  | `hsm`        | M1 TLS private keys            | software keys                     | W6+          |
| OIDC IdP                   | **deferred** | —         | —                              | local argon2id password + HMAC session (see `docs/dashboard-auth.md`) | — |
| OPA                        | optional  | `opa`        | M2 policy decisions            | built-in rule engine only         | W5           |

## Dev Defaults (what `deploy/docker-compose.dev.yml` runs)

The dev compose file brings up only the services needed for the
Week 1–3 milestones. Everything else is added as that week's
integration work starts.

| Service       | Image                            | Port  | Plane   | Purpose                         |
|---------------|----------------------------------|-------|---------|---------------------------------|
| etcd          | `quay.io/coreos/etcd:v3.5.13`    | 2379  | control | Config source of truth          |
| Prometheus    | `prom/prometheus:v2.51.0`        | 9090  | control | Scrapes both planes             |
| Jaeger        | `jaegertracing/all-in-one:1.57`  | 16686 | control | OTLP collector + UI             |
| Redis         | `redis:7-alpine`                 | 6379  | data    | Counter store (optional)        |
| Upstream mock | `mccutchen/go-httpbin:v2.15.0`   | 8081  | data    | Backend target for smoke tests  |

## Production Version Pins

When running against real infrastructure, these are the minimum
versions we test against. Older versions may work but are not
supported.

- etcd: **3.5.13+** (Watch API v3, lease API, revision-aware txn)
- Redis: **7.2** (sliding-window Lua scripts assume 7.x atomics)
- Prometheus: **2.45** (native histograms)
- OTLP collector: any version speaking OTLP/gRPC 1.0
- Consul: **1.18**, etcd: **3.5**, Kubernetes: **1.28**
- Kafka: **3.5** (idempotent producer)
- OpenSSL / rustls: rustls 0.23+, or `fips` feature (BoringSSL + FIPS module)

## When Each Dependency Enters the Plan

| Week | Milestone                              | New dependencies introduced        |
|------|----------------------------------------|------------------------------------|
| W1   | `./waf run` boots from etcd, NoopPipeline | **etcd** (required)             |
| W2   | First SQLi rule blocks, etcd watch hot-reload | none                        |
| W3   | TLS + JWT + Prometheus scrape          | Prometheus, GeoLite2 (optional)    |
| W4   | Dashboard auth (argon2+session), ACME  | ACME server                        |
| W5   | 2-node HA, red-team suite, 5k RPS      | Redis / Redis Cluster, ICAP, Kafka |
| W6+  | FIPS hardening                         | HSM                                |

## Adding a New Dependency

1. Add a row to the matrix above in the same PR that introduces the dependency.
2. Add (or justify skipping) a feature flag in `Cargo.toml`.
3. Document the fallback behavior when the dependency is absent.
4. If it changes the dev bring-up, update `deploy/docker-compose.dev.yml` and `deploy/README.md`.
5. If it has a minimum version, add it to **Production Version Pins** above.
