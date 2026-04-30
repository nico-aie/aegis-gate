# Aegis-Gate — Developer Quick Start

Get the WAF running locally in five steps. For production setup
see [`deploy/GUIDE.md`](deploy/GUIDE.md). For the full YAML
reference see [`config/README.md`](config/README.md).

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Rust | 1.82+ | `rustc --version` |
| Docker + Compose | v2.20+ | `docker compose version` |
| `curl` | any | `curl --version` |

Docker must be running for the optional services (etcd,
Prometheus, Jaeger, Redis, httpbin). The WAF *can* boot without
them — `state.backend: in_memory` and a local YAML config are
enough for first-light.

## 1. Build

```sh
# Debug — fast compile, slower runtime
cargo build --workspace

# Release with cluster support — for benchmarking or HA fixtures
cargo build -p aegis-bin --release --features redis

# Release with CPU pinning enabled too — for runtime-tuning experiments
cargo build -p aegis-bin --release --features "redis affinity"
```

## 2. (Optional) Start infrastructure

```sh
docker compose -f deploy/docker-compose.dev.yml up -d
```

Spins up etcd, Prometheus, Jaeger, Redis, httpbin. Skip this
step if you just want a single-node in-memory WAF — point the
config at `state.backend: in_memory` and the gateway runs
standalone. Service catalogue + ports:
[`deploy/README.md`](deploy/README.md).

## 3. Validate the config

```sh
./target/debug/waf validate --config config/waf.yaml
```

Expected: `config OK: config/waf.yaml`. The YAML reference
([`config/README.md`](config/README.md)) walks every section
including the new `runtime:` block (Layer-1 worker scaling).

## 4. Run the gateway

```sh
# Debug
cargo run -p aegis-bin -- run --config config/waf.yaml

# Release (with redis features compiled in)
./target/release/waf run --config config/waf.yaml
```

The boot log shows the runtime sizing it picked up:

```
tokio runtime workers=12 blocking_threads=512 stack_size_kb=2048 cpu_affinity=false
```

## 5. Verify

```sh
# Health probes (admin port)
curl -sf http://localhost:9443/healthz/live
curl -sf http://localhost:9443/healthz/ready

# Runtime sizing the binary picked up at boot
curl -s http://localhost:9443/api/runtime

# Cluster + leader info (only meaningful in HA fixtures)
curl -s http://localhost:9443/api/cluster

# Prometheus metrics
curl -sf http://localhost:9100/metrics | head

# Smoke through the data plane (plaintext)
curl -i http://localhost:8080/
```

Stop with **Ctrl-C** or `kill -TERM <pid>` — both trigger the
graceful drain (HA-T5): readiness flips to 503, then the listeners
abort after `AEGIS_DRAIN_GRACE_MS` (default 5 s).

---

## Tuning Layer-1 workers

The `runtime:` block in [`config/waf.yaml`](config/waf.yaml) is
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

## Admin auth (optional)

Skip for first-light dev. Set up when you're ready to expose the
admin dashboard:

```sh
# Argon2id password hash — paste into admin.password_hash
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
waf run       --config <path>         # Start gateway
waf validate  --config <path>         # Validate config (no listeners)
waf audit     verify --from <path>    # Verify audit chain
waf admin     set-password            # Hash admin password (argon2id)
waf admin     enroll-totp             # Generate TOTP secret + recovery codes
waf snapshot  --out <path>            # Export config + rules + integrity envelope
waf restore   --from <path>           # Restore an exported snapshot
waf version                           # Build info
waf help                              # Help
```

## Tests

```sh
cargo test --workspace                                    # full suite
cargo test --workspace --features aegis-proxy/redis       # with redis feature
cargo clippy --workspace -- -D warnings                   # lint (zero warnings)
```

The cluster smoke + LB tests live under
[`tests/cluster/`](tests/cluster/); load tests under
[`tests/load/`](tests/load/).

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Cannot connect to Docker daemon` | Start Docker Desktop, retry |
| Config validation fails | Run `waf validate --config ...` — error shows file + field |
| Port already in use | `lsof -i :8443` (or relevant port), kill the conflict |
| `etcd connection refused` | Optional dep — either start it (`docker compose up -d`) or set `state.backend: in_memory` |
| `/api/runtime` shows fewer workers than CPUs | The host is reporting CPU quota (k8s, cgroups). `num_cpus::get()` honours that — pin `runtime.workers: <int>` to override |
| Tests fail on a clean checkout | `cargo test -p <crate>` for the failing crate; full suite output is in `target/debug/deps/<crate>*.log` |
| Clippy warnings | CI enforces `-D warnings`. Fix locally with `cargo clippy --fix`. |

---

## Further reading

| Doc | What |
|-----|------|
| [`config/README.md`](config/README.md) | Full YAML reference, section by section |
| [`deploy/GUIDE.md`](deploy/GUIDE.md) | Production deployment (image, systemd, cluster) |
| [`deploy/README.md`](deploy/README.md) | Dev infra catalogue + HA-cluster fixture |
| [`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md) | Layer-1 worker sizing |
| [`docs/operations/ha-clustering.md`](docs/operations/ha-clustering.md) | Layer-2 cross-node HA |
| [`Architecture.md`](Architecture.md) | System design + three-layer scaling model |
| [`Implement-Progress.md`](Implement-Progress.md) | Implementation log |
