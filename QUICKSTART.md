# Aegis-Gate — Developer Quick Start

Step-by-step guide to get Aegis-Gate running locally for development.

---

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Rust | 1.75+ | `rustc --version` |
| Docker + Compose | v2.20+ | `docker compose version` |
| curl | any | `curl --version` |

> **Docker must be running.** On macOS, open Docker Desktop before running compose commands. If you see `Cannot connect to the Docker daemon`, start Docker Desktop first.

---

## Step 1: Build

```sh
cd /path/to/aegis-gate

# Debug build (fast compile, slower runtime — use for dev)
cargo build --workspace

# Release build (slow compile, optimized — use for benchmarks/staging)
cargo build --workspace --release
```

## Step 2: Start Infrastructure

```sh
docker compose -f deploy/docker-compose.dev.yml up -d
```

This starts:

| Service | Port | Purpose |
|---------|------|---------|
| etcd | 2379 | Config store |
| Prometheus | 9090 | Metrics + alerting |
| Jaeger | 16686 | Distributed tracing |
| Redis | 6379 | Optional counter store |
| httpbin | 8081 | Mock upstream for testing |

Verify services are healthy:

```sh
docker exec aegis-etcd etcdctl endpoint health
curl -sf http://localhost:9090/-/ready
curl -sf http://localhost:16686/
```

> **No Docker?** You can skip this step entirely. The WAF will run with `state: { backend: in_memory }` and local config files. You just won't have Prometheus, Jaeger, or Redis.

## Step 3: Seed Config (Optional)

```sh
# Seed etcd with dev config
./deploy/etcd/bootstrap.sh
```

Or just use a local YAML config file (Step 4).

## Step 4: Validate Config

```sh
./target/debug/waf validate --config config/waf.yaml
```

Expected output:
```
config OK: config/waf.yaml
```

If compliance profiles are set, you'll also see:
```
compliance profiles applied: [Pci, Soc2]
```

## Step 5: Run the Gateway

```sh
# From debug build
cargo run -p aegis-bin -- run --config config/waf.yaml

# Or from release build
./target/release/waf run --config config/waf.yaml
```

## Step 6: Verify

```sh
# Health probes
curl -sf http://localhost:9443/healthz/live     # → 200
curl -sf http://localhost:9443/healthz/ready     # → 200

# Prometheus metrics
curl -sf http://localhost:9100/metrics | head

# Test traffic through the WAF
curl -k https://localhost:8443/ -H "Host: example.com"

# Jaeger UI (if Docker is running)
open http://localhost:16686
```

## Step 7: Teardown

```sh
# Stop infrastructure
docker compose -f deploy/docker-compose.dev.yml down -v

# Stop the WAF
# Ctrl+C (graceful drain) or kill -TERM <pid>
```

---

## Admin Setup (Optional)

Admin setup is **not required** for development. Here's what happens with and without it:

### Without Admin Setup

| Feature | Behavior |
|---------|----------|
| **Data plane** (port 8443) | Fully functional — routes traffic, applies security rules |
| **Health probes** | Fully functional — `/healthz/live`, `/healthz/ready`, `/healthz/startup` |
| **Prometheus metrics** (port 9100) | Fully functional — all metrics exported |
| **Security pipeline** | Fully functional — all OWASP detectors, rules, risk scoring active |
| **Dashboard** (port 9443) | HTML shell loads, SSE streams events |
| **Audit chain** | Writes and verifies normally |
| **Compliance profiles** | Applied at startup via `waf validate` |
| **Dashboard login** | No password set → cannot authenticate to protected admin endpoints |
| **TOTP 2FA** | Not enrolled → skipped |
| **Admin API mutations** | Unprotected unless password + TOTP configured |

**In short:** the WAF runs fully without admin auth. Admin auth only protects the dashboard and admin API — the data plane, security pipeline, metrics, and health probes all work without it.

### Setting Up Admin Auth (When Ready)

```sh
# 1. Hash a password (argon2id)
./target/debug/waf admin set-password
# Type password → get PHC hash string
# Store it in config: admin.password_hash

# 2. Enroll TOTP (optional, recommended for production)
./target/debug/waf admin enroll-totp --issuer "Aegis-Gate" --account "you@company.com"
# Get: base32 secret, QR provisioning URI, 8 recovery codes
# Add secret to your authenticator app (Google Authenticator, Authy, etc.)

# 3. Verify audit chain integrity (anytime)
./target/debug/waf audit verify --from /path/to/audit.ndjson
```

---

## Ports Reference

| Port | Plane | What |
|------|-------|------|
| 8443 | Data | TLS data plane (client traffic) |
| 8080 | Data | Plaintext data plane (dev only) |
| 9443 | Control | Admin dashboard + API |
| 9100 | Data | Prometheus `/metrics` |
| 2379 | Control | etcd |
| 6379 | Data | Redis (optional) |
| 9090 | Control | Prometheus UI |
| 16686 | Control | Jaeger UI |
| 8081 | Data | httpbin (mock upstream) |

---

## CLI Cheat Sheet

```sh
waf run       --config <path>         # Start gateway
waf validate  --config <path>         # Validate config (no listeners)
waf audit     verify --from <path>    # Verify audit chain
waf admin     set-password            # Hash admin password
waf admin     enroll-totp             # Generate TOTP secret
waf version                           # Build info
waf help                              # Help
```

---

## Running Tests

```sh
# All tests (813 tests across all crates)
cargo test --workspace

# Single crate
cargo test -p aegis-control
cargo test -p aegis-security
cargo test -p aegis-proxy

# Clippy (must be zero warnings)
cargo clippy --workspace -- -D warnings
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Cannot connect to Docker daemon` | Start Docker Desktop, then retry |
| `config error: ...` | Run `waf validate --config ...` to see the specific error |
| Port already in use | Check `lsof -i :8443` and kill conflicting process |
| etcd connection refused | Ensure Docker is running: `docker ps \| grep etcd` |
| Tests fail after changes | Run `cargo test -p <crate>` for the crate you changed |
| Clippy warnings | Fix all warnings — CI enforces `-D warnings` |

---

## Further Reading

| Doc | What |
|-----|------|
| [deploy/GUIDE.md](../deploy/GUIDE.md) | Full deployment guide (dev → staging → production) |
| [docs/USAGE.md](USAGE.md) | Operations & usage guide |
| [docs/cli.md](cli.md) | Full CLI reference |
| [Architecture.md](../Architecture.md) | System architecture |
| [Implement-Progress.md](../Implement-Progress.md) | Implementation log |
