# Aegis-Gate — Developer Quick Start

Get the WAF running locally. Two paths: **fast** (one make command)
and **manual** (every step explicit). For production deployment see
[`deploy/GUIDE.md`](deploy/GUIDE.md). For the full YAML reference see
[`config/README.md`](config/README.md).

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Rust | 1.91+ | `rustc --version` |
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
make setup       # generate dev cert + release build (~2 min cold, ~10 s warm)
make run-dev     # first-light: in-memory state, no Redis required
make smoke       # in another terminal: curl data + admin endpoints
```

`make run-dev` boots `config/dev.yaml` — same detector mask + risk
shape as the recommended **prod-balanced** profile, but with
in-memory state and inline test credentials so it works on a fresh
clone with zero infrastructure.

For the production profile (the actual recommended starting point):

```sh
make redis-up    # start the local dev Redis (one-time)
make run         # boots config/profiles/prod-balanced.yaml
```

Run `make help` to see every available target. The four profiles:

| Target | Config | When |
|---|---|---|
| `make run-dev` | `config/dev.yaml` | First-light, tests, in-memory |
| `make run` | `config/profiles/prod-balanced.yaml` | **Production default** (Redis state, 7-day audit) |
| `make run-strict` | `config/profiles/prod-strict.yaml` | Compliance-driven (PCI/HIPAA/SOC2/GDPR) |
| `make run-throughput` | `config/profiles/prod-high-throughput.yaml` | CDN front-door, > 5 k RPS |

Decision tree + empirical comparison:
[`docs/operator/profiles.md`](docs/operator/profiles.md).

Override the default config with env, e.g.:

```sh
CONFIG=config/prod.yaml make run                         # legacy template
FEATURES="redis alerts geoip taxii http3" make build     # custom feature set
```

That's enough to get a green health probe and serve TLS on `:8443`
with a self-signed dev cert. The 502s on `:8080` / `:8443` you'll see
in `make smoke` are expected — the placeholder upstreams (ports
3001-3004 / 9999) aren't running. Replace them with your real
backends when wiring an app.

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
# Default — prod-balanced
./target/release/waf validate --config config/profiles/prod-balanced.yaml

# Or validate every profile in one shot
make validate-all
```

Expected: `config OK: <path>`.

### 5. Run the gateway

```sh
# Dev (no Redis)
cargo run -p aegis-bin -- run --config config/dev.yaml

# Production default (Redis required — `make redis-up` first)
./target/release/waf run --config config/profiles/prod-balanced.yaml
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

The `runtime:` block (commented in
[`config/prod.yaml`](config/prod.yaml); add to any profile under
`config/profiles/`) is the in-process scaling knob:

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
make run-dev                           # Boot config/dev.yaml (in-memory)
make run                               # Boot prod-balanced (default; Redis req)
make run-strict                        # Boot prod-strict (compliance)
make run-throughput                    # Boot prod-high-throughput (CDN)
make redis-up | redis-down             # Start / stop the dev Redis sidecar
make validate                          # Dry-run $(CONFIG)
make validate-all                      # Dry-run dev + all 3 prod profiles
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
[`tests/dashboard/`](tests/dashboard/); the v2.3 contract gate
under [`tests/contract/`](tests/contract/); and the Round-1
Hackathon stress-test harness under
[`tests/hackathon/`](tests/hackathon/) (15-min mixed-traffic
run with mock upstream + k6 + post-run summary —
`bash tests/hackathon/run.sh`).

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
| [`docs/operator/profiles.md`](docs/operator/profiles.md) | Profile decision tree (balanced / strict / high-throughput) + empirical comparison |
| [`docs/operator/soc-runbook.md`](docs/operator/soc-runbook.md) | SOC team cheat sheet (config → deploy → monitor + incident playbooks) |
| [`config/README.md`](config/README.md) | Pick-one config + fork-prod recipe |
| [`deploy/GUIDE.md`](deploy/GUIDE.md) | Production deployment (image, systemd, cluster) |
| [`deploy/README.md`](deploy/README.md) | Dev infra catalogue + HA-cluster fixture |
| [`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md) | Layer-1 worker sizing |
| [`docs/operations/ha-clustering.md`](docs/operations/ha-clustering.md) | Layer-2 cross-node HA |
| [`Architecture.md`](Architecture.md) | System design + three-layer scaling model |
| [`Implement-Progress.md`](Implement-Progress.md) | Implementation log |
| [`plans/README.md`](plans/README.md) | Live status board for every track (Active / Queued / Closed) |
| [`plans/hackathon-stress-test.md`](plans/hackathon-stress-test.md) | Round-1 stress-test harness runbook + open questions |
