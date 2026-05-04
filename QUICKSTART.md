# Aegis-Gate — Developer Quick Start

Get the WAF running locally and watch it work — from `git clone`
to a live dashboard with traffic flowing through it. This file is
the **happy path**. Everything else (per-protocol upstream
recipes, runtime tuning, production deploy, troubleshooting) lives
in dedicated docs linked at the bottom.

---

## 1 · Prereqs

| Tool | Version | Check |
|---|---|---|
| Rust | 1.91+ | `rustc --version` |
| `openssl` | 1.1+ | `openssl version` |
| `make`, `curl`, `jq` | any | `make --version` |
| Docker + Compose | v2.20+ | `docker compose version` |

Docker is **required** — every config (dev, all 3 production
profiles) uses Redis for shared rate-limit counters and leader
leases. The Makefile boots the dev Redis for you the first time
you `make run-dev`.

---

## 2 · Three commands

```sh
make setup       # dev cert + release build (cold ~2 min, warm ~10 s)
make run-dev     # boots WAF + Redis + mock upstream
make urls        # prints every URL + log path
```

`make run-dev` includes the `ai`, `redis`, `geoip`, and `alerts`
features by default. The first boot pulls Redis (`docker pull
redis:7-alpine`). Subsequent boots take ~3 s.

After a successful boot you'll see:

```
data-plane listening on 0.0.0.0:8443 (tls=true)
data-plane listening on 0.0.0.0:8080 (tls=false)
admin-plane listening on 127.0.0.1:9443
AI detector wired into the chain  model_path=…/waf_model.onnx
```

---

## 3 · Open the dashboard

Browse to **<https://127.0.0.1:9443/>** (self-signed cert — accept
the warning, or use `--insecure` on curl).

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `aegis-test-1234` |

> Both come from `config/dev.yaml`. Rotate before exposing the
> admin port: `echo "<new>" \| ./target/release/waf admin set-password`.

### What to look at first

| Page | Why visit |
|---|---|
| **Overview** | KPIs (RPS, block rate, active threats, upstream health). The "Upstream" tile reflects the live `/api/upstreams` aggregate — should read "1 of 1 members up" right after boot. |
| **Live Feed** | Every audit event in real time. Empty after boot until traffic arrives. Pill on each row tells you the protocol (`http` / `ws-open` / `ws-close` / `tcp-open`). |
| **Detectors** | Merged AI observability + class mask. Top section: AI predictions / attack rate / fallbacks. Bottom: per-class on/off (sqli / xss / path-traversal / …) with per-tier overrides. Audit-mutated. |
| **Routing & Upstreams** | Routes table on top + upstream pools below. **+ Add route** and **+ Add pool** buttons live here — both audit-mutated, both hot-swap (no restart). |
| **Audit Trail** | Hash-chained NDJSON. Verify integrity at runtime via `Verify chain` button. |

---

## 4 · Drive synthetic traffic

Open a second terminal and pick a workload — each defaults to 60 s
(override with `DURATION=2m`):

```sh
make mock-load           # ~50 RPS legit + crawler + attacker mix
make mock-load-attacks   # attack-only — detectors fire, audit fills
make mock-load-mix       # ~5 k RPS — stress the WAF
```

Refresh the dashboard. Live Feed scrolls; Overview RPS climbs;
Detectors page shows AI predictions ticking up. The audit chain
at `/tmp/aegis-dev-audit.jsonl` grows in lockstep:

```sh
tail -f /tmp/aegis-dev-audit.jsonl | jq '{ts, action, detectors: .fields.detectors}'
```

---

## 5 · Point at your real upstream

`config/dev.yaml` ships with a stub on `127.0.0.1:9999`. Two ways
to swap it for your own backend:

### From the dashboard (easier)

**Routing & Upstreams** → `+ Add pool` → fill in:

| Field | Example |
|---|---|
| Pool name | `my-backend` |
| Scheme | `https` |
| Address | `203.0.113.45:443` |
| Host header | `api.example.com` *(only for multi-vhost / public TLS)* |

Save. Then `+ Add route` → `path: /` → upstream `my-backend` →
save. Hot-swap, no restart. Both go through the audit-mutated
`PUT /api/upstreams/pool/{id}` and `PUT /api/routes/{id}`
endpoints.

### From YAML

```yaml
# config/dev.yaml
routes:
  - id: my-backend
    path: "/"
    match_type: prefix
    upstream: my-backend

upstreams:
  my-backend:
    members:
      - addr: "203.0.113.45:443"
        host_header: "api.example.com"   # only for multi-vhost
    connection:
      scheme: https                       # http | https | h2c | grpc | auto | tcp
      keep_alive: true
```

Restart with `make run-dev`. Verify:

```sh
curl -i  http://localhost:8080/         # plaintext
curl -ki https://localhost:8443/        # TLS (self-signed)
curl -s  http://localhost:9443/api/upstreams | jq '.pools[].members'
```

Per-protocol recipes (h2c, gRPC, raw TCP, WebSocket) — full
copy-paste blocks: [`docs/operator/upstream-cookbook.md`](docs/operator/upstream-cookbook.md).

---

## 6 · Profile picker (when you're past dev)

| Make target | Config | When |
|---|---|---|
| `make run-dev` | `config/dev.yaml` | local dev (inline creds, loose limits) |
| `make run` | `config/profiles/prod-balanced.yaml` | **production default** |
| `make run-strict` | `config/profiles/prod-strict.yaml` | PCI / HIPAA / SOC 2 / GDPR |
| `make run-throughput` | `config/profiles/prod-high-throughput.yaml` | CDN front-door, > 5 k RPS |

Decision tree + measured perf comparison: [`docs/operator/profiles.md`](docs/operator/profiles.md).

---

## 7 · Observability stack (optional)

```sh
make obs-up      # Prometheus + Grafana + Jaeger
make obs-down    # tear down
```

| URL | What |
|---|---|
| <http://localhost:9090/> | Prometheus |
| <http://localhost:3000/> | Grafana (`admin` / `admin` first login). 3 boards pre-loaded: WAF Overview · Runtime · Redis. |
| <http://localhost:16686/> | Jaeger (per-request OTel spans — needs `make build FEATURES="redis ai otel"`) |

---

## CLI cheat sheet

```sh
make help                    # every make target
make smoke                   # curl the data + admin endpoints
make logs                    # tail audit chain + Redis container
make test                    # cargo test --workspace (~2 800 tests)
make clippy                  # cargo clippy -- -D warnings

waf run       --config <path>     # start gateway
waf validate  --config <path>     # validate config (no listeners)
waf audit     verify --from <p>   # verify audit chain integrity
waf admin     set-password        # argon2id hash for `password_hash_ref`
waf admin     enroll-totp         # TOTP secret + recovery codes
waf snapshot  --out <path>        # export config + rules + integrity envelope
waf restore   --from <path>       # restore an exported snapshot
```

---

## Common stumbles

| Problem | Fix |
|---|---|
| `cargo: command not found` | Override `CARGO=/path/to/cargo make build` if rustup is non-standard |
| Port already in use | `lsof -i :8443` (or `:8080` / `:9443`), kill the conflict |
| `redis connection refused` | Auto-started by `make run-dev`; if missing: `make redis-up` |
| `state.backend = redis but binary built without redis feature` | `make build` (the Makefile default now includes `redis`) |
| `ai.enabled = true but binary built without --features ai` | `make build` (default features include `ai` too) |
| TLS handshake fails | Self-signed in dev — use `curl -k`. Replace cert before exposing the WAF. |
| Cert expired (after 1 year) | `make reset-cert` regenerates |
| Login page rejects everything | The `dev.yaml` password hash matches `aegis-test-1234`. Rotate via `waf admin set-password` and paste the new hash. |
| Dashboard shows "fetch failed" | Fixed 2026-05-04 — rebuild the bundle: `bash crates/aegis-control/assets/dashboard/build.sh && make build` |

Full troubleshooting: [`docs/operator/usage.md`](docs/operator/usage.md).

---

## Where to go next

| You want to … | Doc |
|---|---|
| **Verify every feature works** (QC playbook · one row per feature) | [`docs/FEATURES.md`](docs/FEATURES.md) |
| Wire a real upstream (per-protocol recipes) | [`docs/operator/upstream-cookbook.md`](docs/operator/upstream-cookbook.md) |
| Pick a production profile | [`docs/operator/profiles.md`](docs/operator/profiles.md) |
| Read every config field | [`config/README.md`](config/README.md) |
| Tune tokio workers / blocking pool / CPU pinning | [`docs/operations/runtime-tuning.md`](docs/operations/runtime-tuning.md) |
| Cluster across nodes (HA) | [`docs/operations/ha-clustering.md`](docs/operations/ha-clustering.md) |
| Deploy to production (image, Helm, etcd hot-reload) | [`deploy/GUIDE.md`](deploy/GUIDE.md) |
| Run incident response from the dashboard | [`docs/operator/soc-runbook.md`](docs/operator/soc-runbook.md) |
| Understand AI Detector perf vs the regex chain | [`docs/security/detectors/ai-detector.md`](docs/security/detectors/ai-detector.md) |
| Browse the admin REST contract | [`docs/control-plane/api.openapi.yaml`](docs/control-plane/api.openapi.yaml) |
| See what's implemented vs designed | [`plans/implementation-matrix.md`](plans/implementation-matrix.md) |
| Run the contract / smoke / load tests | [`tests/`](tests/) — every subfolder has its own README |
