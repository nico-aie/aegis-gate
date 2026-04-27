# Aegis-Gate Deployment Guide

This guide covers deploying Aegis-Gate from local development through staging to production.

---

## Prerequisites

- **Rust toolchain**: 1.75+ (`rustup update stable`)
- **Docker & Docker Compose**: v2.20+
- **OS**: Linux (production), macOS (development)

## 1. Local Development

### 1.1 Build

```sh
# Debug build (fast compile, slow runtime)
cargo build --workspace

# Release build (slow compile, optimized)
cargo build --workspace --release
```

### 1.2 Start Infrastructure

```sh
# Start control plane (etcd, Prometheus, Jaeger) + data plane (Redis, httpbin)
docker compose -f deploy/docker-compose.dev.yml up -d

# Verify services are healthy
docker exec aegis-etcd etcdctl endpoint health
curl -sf http://localhost:9090/-/ready         # Prometheus
curl -sf http://localhost:16686/               # Jaeger UI
```

### 1.3 Seed Config

```sh
# Bootstrap etcd with dev config (idempotent)
./deploy/etcd/bootstrap.sh

# Or use a local YAML file
./target/debug/waf validate --config config/waf.yaml
```

### 1.4 Run the Gateway

```sh
# From source (dev)
cargo run -p aegis-bin -- run --config config/waf.yaml

# From binary
./target/release/waf run --config config/waf.yaml
```

### 1.5 Verify

```sh
# Health checks
curl -sf http://localhost:9443/healthz/ready   # Admin ready probe
curl -sf http://localhost:9443/healthz/live     # Admin live probe
curl -sf http://localhost:9100/metrics          # Prometheus metrics

# Send test traffic through the WAF
curl -k https://localhost:8443/ -H "Host: example.com"
```

### 1.6 Tear Down

```sh
docker compose -f deploy/docker-compose.dev.yml down -v
```

---

## 2. Admin Setup

### 2.1 Set Admin Password

```sh
# Interactive
./target/release/waf admin set-password
# Enter password, receive argon2id hash

# Scripted (pipe from stdin)
echo "my-strong-password" | ./target/release/waf admin set-password
```

Store the printed PHC hash in your config's `admin.password_hash` field or in etcd.

### 2.2 Enroll TOTP

```sh
./target/release/waf admin enroll-totp --issuer "Aegis-Gate" --account "admin@corp.com"
```

This outputs:
1. **Base32 secret** — enter into your authenticator app
2. **Provisioning URI** — scan as QR code
3. **Recovery codes** — store securely offline (each usable once)

### 2.3 Verify Audit Chain

```sh
# Verify integrity of an exported audit chain
./target/release/waf audit verify --from /var/log/aegis/audit.ndjson

# Exit code 0 = clean, 1 = tampered/parse error
```

---

## 3. Configuration

### 3.1 Config File

The primary config is YAML. Minimal example:

```yaml
listeners:
  data:
    - bind: "0.0.0.0:8443"
      tls:
        cert: /etc/aegis/tls/server.crt
        key: /etc/aegis/tls/server.key
  admin:
    bind: "127.0.0.1:9443"

routes:
  - id: api
    host: "api.example.com"
    path: "/v1/*"
    upstream: api-pool
  - id: catch-all
    path: "/"
    upstream: default

upstreams:
  api-pool:
    members:
      - addr: "10.0.1.10:8080"
      - addr: "10.0.1.11:8080"
    lb: round_robin
    health_check:
      interval: 10s
      path: /healthz
  default:
    members:
      - addr: "10.0.2.10:3000"

state:
  backend: in_memory    # or "redis" with redis.url

audit:
  chain:
    enabled: true
  retention: 90d
  sinks:
    - type: jsonl
      path: /var/log/aegis/audit.ndjson
    - type: syslog
      target: udp://siem.corp.com:514

# Optional compliance profiles
compliance:
  modes: [pci, soc2]
```

### 3.2 Validate Before Deploy

```sh
./target/release/waf validate --config config/waf.yaml
# Outputs: config OK + compliance profiles applied
```

### 3.3 Compliance Profiles

| Profile | Effect |
|---------|--------|
| `fips` | Force aws-lc-rs TLS provider; reject RC4/DES/3DES/MD5; TLS ≥ 1.2 |
| `pci` | TLS ≥ 1.2; PAN masking in DLP; audit retention ≥ 90 days |
| `soc2` | Require audit hash chain + admin trail + SLO alerts |
| `gdpr` | PII pseudonymization; data residency pin required |
| `hipaa` | PHI-safe log mode (PHI fields masked before sink write) |

---

## 4. Staging Deployment

### 4.1 Docker Image

```dockerfile
FROM rust:1.75-slim AS builder
WORKDIR /src
COPY . .
RUN cargo build --workspace --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/waf /usr/local/bin/waf
EXPOSE 8443 9443 9100
ENTRYPOINT ["waf"]
CMD ["run", "--config", "/etc/aegis/waf.yaml"]
```

### 4.2 Docker Compose (Staging)

```yaml
services:
  waf:
    build: .
    ports:
      - "8443:8443"
      - "9443:9443"
      - "9100:9100"
    volumes:
      - ./config:/etc/aegis:ro
      - ./tls:/etc/aegis/tls:ro
    depends_on:
      etcd:
        condition: service_healthy
    environment:
      WAF_LOG_FORMAT: json
      WAF_LOG_LEVEL: info
```

---

## 5. Production Deployment

### 5.1 Checklist

- [ ] **TLS certificates** provisioned (ACME or manual)
- [ ] **Admin password** hashed with `waf admin set-password`
- [ ] **TOTP enrolled** with `waf admin enroll-totp`
- [ ] **Config validated** with `waf validate --config ...`
- [ ] **Compliance profiles** set (e.g., `modes: [pci, soc2, hipaa]`)
- [ ] **Audit sinks** configured (JSONL + at least one SIEM sink)
- [ ] **IP allowlist** set for admin dashboard
- [ ] **etcd** deployed with TLS + RBAC (not `ALLOW_NONE_AUTHENTICATION`)
- [ ] **Prometheus** scraping both planes
- [ ] **SLO objectives** configured with alerting receivers

### 5.2 Systemd Service

```ini
[Unit]
Description=Aegis-Gate WAF
After=network-online.target etcd.service
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/waf run --config /etc/aegis/waf.yaml --ready-fd 3
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
NotifyAccess=main

[Install]
WantedBy=multi-user.target
```

### 5.3 Health Monitoring

| Endpoint | Purpose | Expected |
|----------|---------|----------|
| `GET /healthz/live` | Liveness probe | `200 OK` |
| `GET /healthz/ready` | Readiness probe | `200 OK` when config loaded + upstreams healthy |
| `GET /healthz/startup` | Startup probe | `200 OK` after initial boot |
| `GET /metrics` | Prometheus metrics | Prometheus text format |

### 5.4 Log Rotation

Aegis writes audit logs as NDJSON. Use logrotate or a similar tool:

```
/var/log/aegis/audit.ndjson {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

### 5.5 Graceful Shutdown

- `SIGTERM` → graceful drain (connections finish, then exit 0)
- `SIGUSR2` → hot binary reload (new process, drain old)

---

## 6. Ports Reference

| Port | Plane | Purpose |
|------|-------|---------|
| 8443 | Data | TLS data plane (client traffic) |
| 8080 | Data | Plaintext data plane (dev only) |
| 9443 | Control | Admin dashboard + API |
| 9100 | Data | Prometheus `/metrics` |
| 2379 | Control | etcd (config source of truth) |
| 6379 | Data | Redis (optional counter store) |

---

## 7. Troubleshooting

| Symptom | Check |
|---------|-------|
| Config validation fails | Run `waf validate --config ...` and fix reported errors |
| Compliance conflict | Check if `min_tls_version` or `disallow_algorithms` conflicts with profile requirements |
| Audit chain tampered | Run `waf audit verify --from <path>` — reports exact tampered line |
| Admin login locked out | Wait for lockout TTL (default 15min) or restart to clear in-memory state |
| TOTP rejected | Check clock sync (NTP); TOTP allows ±1 time step (30s) |
| Health probe failing | Check `/healthz/ready` — requires config loaded + at least one healthy upstream |
