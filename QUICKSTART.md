# Aegis-Gate — Developer Quick Start

Get the WAF running locally. Two paths: **fast** (one make command)
and **manual** (every step explicit). For production deployment see
[`deploy/GUIDE.md`](deploy/GUIDE.md). For the full YAML reference see
[`config/README.md`](config/README.md).

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Rust | 1.82+ | `rustc --version` |
| `openssl` | 1.1+ | `openssl version` (used by the dev-cert script) |
| `make` | any | `make --version` |
| Docker + Compose | v2.20+ (optional) | `docker compose version` |
| `curl` | any | `curl --version` |

Docker is only needed for the optional dev infra (etcd, Prometheus,
Jaeger, Redis, httpbin). The WAF boots standalone with
`state.backend: in_memory` and a local YAML config — no Docker
required.

---

## Fast path

```sh
make setup    # generate dev cert + release build (~2 min cold, ~10 s warm)
make run      # boot against config/prod.yaml
make smoke    # in another terminal: curl data + admin endpoints
```

Run `make help` to see every available target. Override defaults via env:

```sh
CONFIG=config/dev.yaml make run                          # boot dev config
FEATURES="redis alerts geoip taxii http3" make build     # custom feature set
```

That's enough to get a green health probe and serve TLS on `:8443`
with a self-signed dev cert. The 502s on `:8080` / `:8443` you'll see
in `make smoke` are expected — the placeholder upstreams in
`prod.yaml` (ports 3001-3004) aren't running. Replace them with
your real backends when wiring an app.

---

## Manual path

If you'd rather drive every step yourself:

### 1. Generate a self-signed dev cert

```sh
bash config/gen-cert.sh
# Output: config/certs/dev.crt + config/certs/dev.key
```

The cert has SANs for `localhost`, `127.0.0.1`, `::1`, and
`aegis-gate.local`. **Self-signed — not for production.** Replace
the `tls.certificates:` block in `prod.yaml` with real certs (or
wire `tls.acme:`) before exposing the WAF to the internet.

### 2. Build

```sh
# Debug — fast compile, slower runtime
cargo build --workspace

# Release with cluster support — for benchmarking / HA fixtures
cargo build -p aegis-bin --release --features redis

# Release with CPU pinning — for runtime-tuning experiments
cargo build -p aegis-bin --release --features "redis affinity"
```

### 3. (Optional) Start dev infrastructure

```sh
docker compose -f deploy/docker-compose.dev.yml up -d
```

Spins up etcd, Prometheus, Jaeger, Redis, httpbin. Skip for a
single-node in-memory WAF. Service catalogue + ports:
[`deploy/README.md`](deploy/README.md).

### 4. Validate the config

```sh
./target/release/waf validate --config config/prod.yaml
```

Expected: `config OK: config/prod.yaml`.

### 5. Run the gateway

```sh
# Debug
cargo run -p aegis-bin -- run --config config/prod.yaml

# Release
./target/release/waf run --config config/prod.yaml
```

Boot log shows the runtime sizing it picked up:

```
tokio runtime workers=12 blocking_threads=512 stack_size_kb=2048 cpu_affinity=false
data-plane listening on 0.0.0.0:8443 (tls=true)
data-plane listening on 0.0.0.0:8080 (tls=false)
admin-plane listening on 127.0.0.1:9443
```

### 6. Verify

```sh
# Health probes (admin port)
curl -sf http://localhost:9443/healthz/live
curl -sf http://localhost:9443/healthz/ready

# Runtime sizing the binary picked up at boot
curl -s http://localhost:9443/api/runtime

# Prometheus metrics
curl -sf http://localhost:9443/metrics | head

# Smoke through the data plane
curl -k https://localhost:8443/        # TLS (self-signed cert → -k)
curl -i  http://localhost:8080/        # plaintext
```

Stop with **Ctrl-C** or `kill -TERM <pid>` — both trigger the
graceful drain (HA-T5): readiness flips to 503, then the listeners
abort after `AEGIS_DRAIN_GRACE_MS` (default 5 s).

---

## Tuning Layer-1 workers

The `runtime:` block in [`config/prod.yaml`](config/prod.yaml) is
the in-process scaling knob:

```yaml
runtime:
  workers: auto             # or integer in [2, 512]
  blocking_threads: 512
  cpu_affinity: false       # only honoured with `--features affinity`
  stack_size_kb: 2048
```

Restart-only — change YAML, restart the process. Sizing recipes,
verification, and OS-specific affinity notes live in
[`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md).

---

## Admin auth

Skip for first-light dev. Set up when you're ready to expose the
admin dashboard:

```sh
# Argon2id password hash — paste into admin.password_hash_ref
./target/release/waf admin set-password

# TOTP secret + recovery codes
./target/release/waf admin enroll-totp \
    --issuer "Aegis-Gate" --account "you@company.com"

# Audit-chain integrity check
./target/release/waf audit verify --from /var/log/aegis/audit.ndjson
```

Without admin auth: data plane, security pipeline, metrics, and
health probes all work — only the admin API mutations are
unprotected and the dashboard login screen rejects all attempts.

---

## CLI cheat sheet

```sh
make help                              # List every make target
make setup                             # Cert + release build
make run                               # Boot against $(CONFIG)
make validate                          # Config dry-run
make smoke                             # Curl data + admin endpoints
make test                              # cargo test --workspace
make clippy                            # cargo clippy -- -D warnings

waf run       --config <path>          # Start gateway
waf validate  --config <path>          # Validate config (no listeners)
waf audit     verify --from <path>     # Verify audit chain
waf admin     set-password             # Hash admin password (argon2id)
waf admin     enroll-totp              # Generate TOTP secret + recovery codes
waf snapshot  --out <path>             # Export config + rules + integrity envelope
waf restore   --from <path>            # Restore an exported snapshot
waf version                            # Build info
waf help                               # Built-in help
```

## Tests

```sh
make test                                                 # full workspace
cargo test --workspace --features aegis-proxy/redis       # with redis feature
make clippy                                               # lint (zero warnings)
```

The cluster smoke + LB tests live under
[`tests/cluster/`](tests/cluster/); load tests under
[`tests/load/`](tests/load/); dashboard acceptance under
[`tests/dashboard/`](tests/dashboard/).

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `make: cargo: command not found` | The Makefile auto-adds `~/.cargo/bin` to PATH; if rustup is installed elsewhere, override `CARGO=/path/to/cargo make build` |
| `make: openssl: command not found` | Install via `brew install openssl` (macOS) or your distro's package manager |
| TLS handshake fails with self-signed cert | Use `curl -k` (or your client's "ignore cert" flag) — replace with a real cert before going live |
| Config validation fails | Run `make validate` — error shows file + field with line number |
| Port already in use | `lsof -i :8443` (or :8080 / :9443), kill the conflict |
| `etcd connection refused` | Optional dep — either start it (`docker compose up -d`) or set `state.backend: in_memory` |
| `/api/runtime` shows fewer workers than CPUs | The host is reporting CPU quota (k8s, cgroups). `num_cpus::get()` honours that — pin `runtime.workers: <int>` to override |
| Tests fail on a clean checkout | `cargo test -p <crate>` for the failing crate; full suite output is in `target/debug/deps/<crate>*.log` |
| Clippy warnings | CI enforces `-D warnings`. Fix locally with `cargo clippy --fix`. |
| Cert expired (after 1 year) | `make reset-cert` to regenerate |

---

## Further reading

| Doc | What |
|-----|------|
| [`docs/operator/soc-runbook.md`](docs/operator/soc-runbook.md) | SOC team cheat sheet (config → deploy → monitor + incident playbooks) |
| [`config/README.md`](config/README.md) | Pick-one config + fork-prod recipe |
| [`deploy/GUIDE.md`](deploy/GUIDE.md) | Production deployment (image, systemd, cluster) |
| [`deploy/README.md`](deploy/README.md) | Dev infra catalogue + HA-cluster fixture |
| [`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md) | Layer-1 worker sizing |
| [`docs/operations/ha-clustering.md`](docs/operations/ha-clustering.md) | Layer-2 cross-node HA |
| [`Architecture.md`](Architecture.md) | System design + three-layer scaling model |
| [`Implement-Progress.md`](Implement-Progress.md) | Implementation log |
