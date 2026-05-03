# Aegis-Gate — Developer Quick Start

Get the WAF running locally. Two paths: **fast** (one make command)
and **manual** (every step explicit). For production deployment see
[`deploy/GUIDE.md`](deploy/GUIDE.md). For the full YAML reference see
[`config/README.md`](config/README.md).

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Rust | 1.91+ | `rustc --version` |
| `openssl` | 1.1+ | `openssl version` |
| `make` | any | `make --version` |
| Docker + Compose | v2.20+ | `docker compose version` |
| `curl` | any | `curl --version` |

Docker is **required** — every config (dev, prod, all 3 profiles) uses
Redis for shared rate-limit counters + leader leases. The Makefile
spins the dev Redis up automatically when you `make run`; no manual
plumbing.

---

## Fast path — three commands

```sh
make setup       # generate dev cert + release build (~2 min cold, ~10 s warm)
make run-dev     # boot WAF (Redis auto-starts via the run-dev dep)
make smoke       # in another terminal: curl data + admin endpoints
make urls        # print every URL + log-file path
```

That's it. `make run-dev` boots `config/dev.yaml` against a Redis
sidecar (started for you on `127.0.0.1:6379`); the WAF binds:

- `:8080` (HTTP data plane)
- `:9443` (admin / dashboard / `/metrics` / `/healthz`)

The 502s you see on `make smoke` are expected — the placeholder
upstream on `:9999` isn't running. Wire your real backend in
`config/dev.yaml` `upstreams:` when ready.

### Profile picker

`make run-dev` is for first-light. For real workloads pick one of
the production profiles (each auto-starts Redis):

| Target | Config | When |
|---|---|---|
| `make run-dev` | `config/dev.yaml` | Local dev (inline test creds) |
| `make run` | `config/profiles/prod-balanced.yaml` | **Production default** |
| `make run-strict` | `config/profiles/prod-strict.yaml` | Compliance-driven (PCI/HIPAA/SOC2/GDPR) |
| `make run-throughput` | `config/profiles/prod-high-throughput.yaml` | CDN front-door, > 5 k RPS |

Decision tree + empirical comparison:
[`docs/operator/profiles.md`](docs/operator/profiles.md).

Override the default config with env, e.g.:

```sh
CONFIG=config/prod.yaml make run                         # legacy template
FEATURES="redis alerts geoip taxii http3" make build     # custom feature set
```

---

## Where to find things — UIs, metrics, logs

```sh
make urls         # one-shot reference card
make obs-up       # bring up Prometheus + Grafana + Jaeger
make mock-load    # drive synthetic traffic so the dashboard has data to show
```

### Mock load — see the dashboard come alive

Three traffic shapes (each defaults to 60s; override with `DURATION=2m`):

```sh
make mock-load           # ~50 RPS legit + crawler + attacker mix
make mock-load-attacks   # attack-only flood — detectors fire, audit chain fills
make mock-load-mix       # high-volume mix (~5 k RPS) — stress the WAF
```

While these run, refresh the dashboard / Grafana to watch live activity.

| What | Where | Notes |
|------|-------|-------|
| Data plane (HTTP) | `http://localhost:8080/` | every request flows through detectors |
| Data plane (HTTPS) | `https://localhost:8443/` | self-signed; use `curl -k` |
| Admin / dashboard | `http://localhost:9443/` | login: `admin` / `aegis-test-1234` |
| Health (ready) | `http://localhost:9443/healthz/ready` | `state_backend_up: true` once Redis hydrates |
| Prometheus scrape | `http://localhost:9443/metrics` | OpenMetrics; ~70 series |
| Runtime sizing | `http://localhost:9443/api/runtime` | tokio worker count + flags |
| **Prometheus UI** | `http://localhost:9090/` | `make obs-up` |
| **Grafana UI** | `http://localhost:3000/` | `admin/admin`; 3 boards pre-loaded |
| **Jaeger UI** (traces) | `http://localhost:16686/` | OTel spans per request |
| Redis | `redis://localhost:6379` | `docker exec aegis-redis redis-cli` |

Pre-loaded Grafana boards (under `deploy/grafana/dashboards/`):
- **Aegis WAF Overview** — RPS, per-tier mix, top blocked detectors
- **Aegis Runtime** — tokio worker / blocking-pool / I/O driver gauges
- **Aegis Redis** — pool size, op latency, error rate

### Logs

| Source | Path | Notes |
|--------|------|-------|
| WAF stdout | the terminal running `make run` | structured `tracing` (subscribe via `RUST_LOG`) |
| Audit chain (NDJSON) | `/tmp/aegis-dev-audit.jsonl` | hash-chained — `waf audit verify --from <path>` |
| Interop contract audit | `./waf_audit.log` | mode toggles + control-plane mutations |
| Redis container | `docker logs -f aegis-redis` | |
| Prometheus container | `docker logs -f aegis-prometheus` | |
| Grafana container | `docker logs -f aegis-grafana` | |

For SOC-team incident workflows: [`docs/operator/soc-runbook.md`](docs/operator/soc-runbook.md).

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

Spins up etcd, Prometheus, Jaeger, Redis, httpbin. The `make obs-up`
target is a thinner alternative that only boots Prometheus + Grafana
+ Jaeger (no etcd). Service catalogue + ports:
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
# Dev (Redis-backed; `make redis-up` if you haven't already)
cargo run -p aegis-bin -- run --config config/dev.yaml

# Production default
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

## Pointing at a real upstream

`config/dev.yaml` ships with a stub upstream on `127.0.0.1:9999`
(the Go mock under `tests/hackathon/upstream/`). To proxy your own
backend, edit `upstreams:` in the YAML and bring the WAF back up.

### Your own backend (single-vhost or IP-addressed)

```yaml
# config/dev.yaml — replace the stub-pool block
upstreams:
  stub-pool:
    members:
      - addr: "203.0.113.45:443"   # your VPS / staging IP
    lb: round_robin
    connection:
      scheme: https                # or `http` for plain :80
```

```sh
pkill aegis-bin || true
make run-dev
curl -i http://localhost:8080/some/path
curl -ik https://localhost:8443/some/path
make logs                          # audit chain shows the forward
curl -s http://localhost:9443/api/upstreams | jq '.pools[].members'
```

### A public hostname (resolve first — `addr:` is `SocketAddr`)

```sh
dig +short example.com             # → 23.215.0.136 (or similar)
```

```yaml
upstreams:
  stub-pool:
    members:
      - addr: "23.215.0.136:443"
    lb: round_robin
    connection:
      scheme: https
```

### Multi-vhost backends — `host_header:` override

Some upstreams dispatch on the `Host:` header (Cloudflare-fronted
sites, GitHub Pages, any nginx with multiple `server_name` blocks,
shared hosts behind a reverse proxy). By default the WAF rewrites
`Host:` to the member's IP:port — those backends then return 404
or the wrong vhost. Pin the right Host with `host_header:` on
the member:

```yaml
upstreams:
  github-pages:
    members:
      - addr: "185.199.108.153:443"   # dig +short your-org.github.io
        host_header: "your-org.github.io"
    lb: round_robin
    connection:
      scheme: https
```

The upstream now sees `Host: your-org.github.io` regardless of
which TCP target the WAF lands on. The original client `Host` is
preserved in `X-Forwarded-Host`.

**TLS / SNI handling.** When the upstream is `scheme: https` AND
`host_header:` is set, the WAF builds the request URL using the
override hostname so SNI + cert validation match the public name
(`Host: your-org.github.io`, SNI `your-org.github.io`, cert
validates against `your-org.github.io`). A process-global pinned
DNS resolver (`crates/aegis-proxy/src/upstream/pinned_resolver.rs`)
then routes that hostname's TCP connection back to the configured
`addr` IP — bypassing system DNS, so the resolver isn't fighting
your `addr` pinning. Plain HTTP upstreams keep the legacy
addr-as-host shape since SNI doesn't apply.

That means **public-TLS multi-vhost backends now work directly** —
point the WAF at `httpbin.org`, GitHub Pages, Cloudflare, etc.
without a sidecar.

### Live verification

```sh
# Are we proxying?
curl -s -o /dev/null -w "status=%{http_code} size=%{size_download}\n" \
  http://localhost:8080/

# Audit chain — what did the WAF allow / block / forward?
tail -f /tmp/aegis-dev-audit.jsonl | jq \
  'select(.action == "allow") | {ts, ip: .client_ip, path: .fields.path, status: .fields.status}'

# Pool health
curl -s http://localhost:9443/api/upstreams \
  | jq '.pools[].members[] | {addr, healthy}'
```

---

## Validating the recent fixes (manual scripts)

`tests/manual/` is a small set of hand-runnable shell scripts so you
can poke at the recently shipped console fixes without spinning up
the full CI rig. They build on `tests/api/_common.sh` (login /
CSRF / cookie jar) and assume `make run-dev` is up.

```sh
export ADMIN_USER=admin
export ADMIN_PASS=admin
export AEGIS_ADMIN=http://127.0.0.1:9443
export AEGIS_DATA=http://127.0.0.1:8080
```

| Script | What it covers |
|---|---|
| `tests/manual/access-list-roundtrip.sh` | Add / probe / remove blacklist + whitelist entries (`kind: ip`, `cidr`, `whitelist`). Asserts the runtime matcher reads the same `Arc` the dashboard CRUD writes to. |
| `tests/manual/fake-country-ips.sh` | Drops a `kind: country` blacklist entry, drives the data plane with one known IP per country (US / CN / RU / DE / JP / BR / GB). Needs `make geoip-link`. |
| `tests/manual/csrf-cookie-flow.sh` | Login → mutation → missing-token → wrong-token paths. Confirms the global fetch interceptor's redirect targets. |
| `tests/manual/websocket-bridge.sh` | Drives a real `ws://` session through the WAF to a local echo backend with `websocat` / `wscat`. |
| `tests/manual/viptalk-alert-test.sh` | Posts to `/api/alert-receivers/<id>/test` and inspects `delivered / skipped_feature_off / failed`. |

The fake-country trick: loopback is a trusted proxy in the default
config, so `curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:8080/`
is treated as a request from `8.8.8.8` — the strike gate, blacklist
matcher, GeoIP lookup, and audit log all see the spoofed IP. No
real cross-country source needed.

For the country-code path you also need MaxMind data:

```sh
make geoip-link COUNTRY_DB=/path/to/GeoLite2-Country.mmdb
make geoip-status                                # confirm symlink
make run-dev                                     # restart so the reader picks up
tests/manual/fake-country-ips.sh
```

Full reference: [`tests/manual/README.md`](tests/manual/README.md).

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
make setup                             # Cert + release build (one-shot)
make run-dev                           # Boot config/dev.yaml (Redis auto-starts)
make run                               # Boot prod-balanced (default)
make run-strict                        # Boot prod-strict (compliance)
make run-throughput                    # Boot prod-high-throughput (CDN)
make obs-up | obs-down                 # Start / stop Prometheus + Grafana + Jaeger
make redis-up | redis-down             # Start / stop the dev Redis (auto by run-*)
make urls                              # Print every URL + log-file path
make logs                              # Tail the audit chain + redis container
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

Three layers — automated, contract / smoke, hand-driven.

### Automated (CI-equivalent)

```sh
make test                                                 # full workspace (~1500 tests)
make clippy                                               # lint — zero warnings on libs
cargo test --workspace --features aegis-proxy/redis       # with redis feature
cargo test -p <crate>                                     # focused
```

### Contract + smoke (assumes `make run-dev` is up)

```sh
make smoke                # curl data + admin healthz
make protocols-test       # h1 / h2 / h3 / WS / gRPC
make openapi-test         # OpenAPI shape contract
make ci-local             # everything GitHub Actions runs
```

### Stress + security

```sh
make mock-load            # ~50 RPS legit + crawler + attacker mix
make mock-load-attacks    # attack-only flood — drives detector hits
make mock-load-mix        # ~5 k RPS — stress the WAF
bash tests/hackathon/run.sh    # 15-min Round-1 mixed-traffic harness
k6 run tests/load/baseline.js
nuclei -u http://localhost:8080/ -tags sqli,xss,traversal -duc
```

### Test catalogue

| Path | What |
|---|---|
| [`tests/api/`](tests/api/) | curl + jq smoke (16 scripts: openapi-shape, upstreams-crud, alert-receivers-crud, …) |
| [`tests/manual/`](tests/manual/) | hand-driven validation of recent fixes — see § "Validating the recent fixes" above |
| [`tests/contract/`](tests/contract/) | v2.3 contract regression gate (40 numbered §X.Y checks) |
| [`tests/cluster/`](tests/cluster/) | HA cluster smoke + leader-failover fixtures |
| [`tests/dashboard/`](tests/dashboard/) | Round-1 acceptance + Playwright per-page screenshots |
| [`tests/protocols/`](tests/protocols/) | h1 / h2 / h3 / WS / gRPC mix |
| [`tests/load/`](tests/load/) | k6 scripts (baseline, rate-limit, ddos-burst, risk-strikes, loadmode-degradation) |
| [`tests/hackathon/`](tests/hackathon/) | 15-min mixed-traffic harness with mock upstream + k6 + post-run summary |
| [`tests/security/`](tests/security/) | corpus + nuclei + zap runners |
| [`tests/results/`](tests/results/) | dated run reports (logs + screenshots + REPORT.md) |

---

## Deploy

Production path is **build → image → orchestrate**. Full walkthrough
with cluster topology, secrets management, and rollout discipline:
[`deploy/GUIDE.md`](deploy/GUIDE.md).

### Local reproduction of production-like env

```sh
docker compose -f deploy/docker-compose.dev.yml up -d
# Spins up: etcd, prometheus, grafana, jaeger, redis, httpbin
make obs-up                      # if you only want observability
```

### Multi-arch container image (B6-T1)

```sh
bash deploy/docker-build.sh --tag aegis-gate:0.x         # amd64 + arm64
bash deploy/docker-build.sh --tag aegis-gate:0.x --push  # push to registry
docker run --rm -p 8080:8080 -p 8443:8443 -p 9443:9443 \
  -v $(pwd)/config/profiles/prod-balanced.yaml:/etc/aegis/waf.yaml \
  aegis-gate:0.x run --config /etc/aegis/waf.yaml
```

The base is **distroless** + non-root + multi-stage so the runtime
layer carries only the binary + libgcc/libssl. Image size: ~70 MB
release / ~80 MB with `production` features.

### Helm chart (B6-T2)

```sh
make helm-lint                           # helm lint + kube-linter
make helm-render                         # render with placeholder values
helm upgrade --install aegis deploy/helm/aegis-gate \
  --namespace aegis --create-namespace \
  --set image.repository=ghcr.io/your-org/aegis-gate \
  --set image.tag=0.x \
  --set redis.url=redis://prod-redis:6379 \
  --set replicas=3
```

Defaults: 3-replica StatefulSet, PodDisruptionBudget=1, anti-
affinity per zone, Service ClusterIP for the data plane + LoadBalancer
hook for the admin port (gate behind a VPN / private LB in
production).

### Hot-reload from etcd (preferred for cluster deployments)

```sh
bash deploy/etcd/bootstrap.sh \
  --endpoints=http://etcd-cluster:2379 \
  --config=config/profiles/prod-balanced.yaml
# Pushes the YAML to /aegis/config/waf and prints the verification curl

# Each WAF replica boots with:
AEGIS_CONFIG_SOURCE=etcd \
AEGIS_ETCD_ENDPOINTS=http://etcd-cluster:2379 \
  /usr/local/bin/waf run
```

`etcdctl put` / `helmfile apply` against the same key triggers an
atomic reload across every replica within ~5 s. Six surfaces hot-
reload — see the README's "Hot-reload story" table.

### Production checklist

- [ ] Real CA-issued TLS certs (replace `tls.certificates:` block; or use `tls.acme:`)
- [ ] Argon2id admin password (`waf admin set-password` → paste hash into `dashboard_auth.password_hash_ref`)
- [ ] Strong CSRF secret (`dashboard_auth.csrf_secret_ref` ≥ 32 bytes; pull from secret manager via `${secret:vault:...}`)
- [ ] TOTP enrolled (`waf admin enroll-totp`)
- [ ] Redis pinned + persistent (RDB + AOF), behind Sentinel or Cluster
- [ ] Audit chain durable sink (`audit.sinks: jsonl` + retention TTL) — DURABLE-T1
- [ ] Compliance profile picked (`compliance.modes: pci|hipaa|soc2|gdpr`) — clamp prevents accidental detector disables
- [ ] Prometheus + Grafana wired against `/metrics` on every node
- [ ] OTel exporter pointed at your collector if you have one (`--features otel`)
- [ ] `make ci-local` green before each release

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `make: cargo: command not found` | The Makefile auto-adds `~/.cargo/bin` to PATH; if rustup is installed elsewhere, override `CARGO=/path/to/cargo make build` |
| `make: openssl: command not found` | Install via `brew install openssl` (macOS) or your distro's package manager |
| TLS handshake fails with self-signed cert | Use `curl -k` (or your client's "ignore cert" flag) — replace with a real cert before going live |
| Config validation fails | Run `make validate` — error shows file + field with line number |
| Port already in use | `lsof -i :8443` (or :8080 / :9443), kill the conflict |
| `redis connection refused` | The Makefile auto-starts Redis via `make redis-up`. If it's down: `docker ps --filter name=aegis-redis`; if missing entirely, `make redis-up` recreates it. |
| `state.backend = redis but this binary was built without the redis feature` | Rebuild: `FEATURES=redis make build` (the Makefile default) — old release binaries from before the Redis-default switch need this once. |
| Grafana login fails | Default creds on first login: `admin` / `admin` (Grafana then prompts you to change). Boards live at `deploy/grafana/dashboards/`. |
| `etcd connection refused` | Optional — `docker compose -f deploy/docker-compose.dev.yml up -d etcd` or omit if you use file-based config (default). |
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
