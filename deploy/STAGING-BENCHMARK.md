# Aegis-Gate — Linux Staging Deploy (Benchmark)

Single-Linux-machine staging deployment guide. **Infra (Redis, Prometheus,
Grafana) runs on the same machine via Docker; the WAF runs as a native binary
on the host** so benchmark numbers measure the proxy itself, not Docker
overhead.

This document is **deliberately mechanical** — every step has a command, a
Verify, and an Expected output. An AI assistant (Claude Code, Cursor, etc.)
can drive it end-to-end without judgement calls.

> Local laptop dev → [`../QUICKSTART.md`](../QUICKSTART.md).
> Multi-node production → [`./GUIDE.md`](./GUIDE.md).
> Architectural picture → [`../Architecture.md`](../Architecture.md).
> Verify each feature works → [`../docs/FEATURES.md`](../docs/FEATURES.md).

---

## 0.0 · What this revision actually covers

> **Tested on the host that produced this document — 2026-05-20.** Every
> command in here has been run end-to-end on a single AWS EC2 instance.
> Versions below are the ones we shipped:
>
> | Tool | Version | Notes |
> |---|---|---|
> | OS | **RHEL 9.7** | Ubuntu 22.04+ also supported; package names differ — see §0 |
> | Rust | **1.95.0** | `rustc 1.91+` works; 2024 edition expected |
> | Cargo | **1.95.0** | |
> | Docker Engine | **29.4.2** | Compose v2 required |
> | k6 | **v1.7.1** | optional; only for §8 load tests |
> | Go | **1.25.9** | needed for the bundled `tests/hackathon/upstream/fast-upstream.go` mock |
> | ONNX Runtime | **1.24.4** | Microsoft prebuilt, see §2.1 |
> | WAF commit | `514a19a` (post-`origin/develop` 2026-05-20) | |
> | Interop contract | **v2.5** (`Hackathon_Doc/EN_waf_interop_contract_v2.5.md`) | |
>
> **Key codebase patches baked into this build** (don't strip these on upgrades):
> - `instant-acme = 0.8.5` (workspace dep). The 0.7.x line fails to deserialize
>   the new `dns-persist-01` challenge type that Let's Encrypt now returns.
>   See `crates/aegis-proxy/src/acme_instant.rs` — migrated to the 0.8 builder
>   API (`Account::builder()`, `Order::poll_ready`, etc.).
> - `ort = "=2.0.0-rc.12"` with `default-features = false, features =
>   ["load-dynamic", "ndarray", "std", "tracing", "api-24"]`. The crate's
>   `download-binaries` default pulls a glibc-2.38-linked prebuilt that
>   doesn't link on RHEL 9 (glibc 2.34). See §2.1 for why this exact set.
>
> **v2.5 contract behaviours wired in this build:**
> - `/__waf_control/*` is **loopback-only** on both admin and data planes
>   (`admin_dispatch.rs:108`'s `peer.ip().is_loopback()` gate). External
>   benchmarkers reach it via SSH local-forward.
> - `/challenge/verify` is a **public** data-plane endpoint (not under
>   `/__waf_control/*`).
> - Challenge JSON shape: `challenge_token` / `submit_url` / `submit_method`
>   (replaces v2.3's `nonce` / `submit_to`).
> - `behavior_burst` signal **retired** — it tripped on every loopback request
>   and made single-source-IP benchmarks unusable. Removed in `e50ab79`.

---

## What you'll have at the end

- WAF binary running on the staging host, listening on `:8080` (HTTP data
  plane), `:443` (HTTPS data plane), `:80` (HTTP-01 + force-https redirect),
  `:9443` (admin / dashboard / loopback-only).
- Redis on `:6379` (shared rate-limit counters, leader leases).
- Prometheus on `:9090` scraping the WAF (`/metrics` on admin plane).
- Grafana on `:3000` with the bundled dashboards.
- **AI detector wired in** with the OnnxMLTools tree-classifier model at
  `data/ai_model/waf_model.onnx` (~20 MB), confidence threshold 0.90.
- v2.5 minimal audit chain at `./waf_audit.log` (relative to the WAF cwd) +
  the hash-chained NDJSON sink at `/var/log/aegis/audit-YYYY-MM-DD.ndjson`.
- Either a real upstream wired in, or the bundled mock fast-upstream on
  `:9999` for synthetic benchmark traffic.

End-to-end smoke test takes ~10 minutes on a clean RHEL 9 / Ubuntu 22.04 box,
plus a one-time **~2 minutes** for the ONNX Runtime download (no source
build — see §2.1).

---

## 0 · Prerequisites

### 0.1 · Required packages

**RHEL 9 / RHEL 10 / Fedora (this is the tested path):**

```sh
sudo dnf install -y \
  gcc gcc-c++ libstdc++-devel \
  pkgconf-pkg-config openssl-devel openssl \
  curl jq git \
  cmake python3-devel \
  iproute lsof
```

**Ubuntu 22.04 / 24.04 / Debian 12:**

```sh
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config libssl-dev openssl \
  curl jq git \
  cmake python3-dev \
  iproute2 lsof
```

> **Notes for RHEL 9 in particular:**
> - The `protobuf-compiler` / `protobuf-devel` packages **are not** in the
>   default RHEL 9 repos. You don't need them — the only place protobuf would
>   matter (ONNX Runtime source build) is **avoided** in §2.1 via the
>   Microsoft prebuilt.
> - You'll also need `libstdc++-devel` explicitly — the dynamic linker on
>   RHEL 9 needs the C++ runtime headers to satisfy ONNX Runtime's
>   `-lstdc++` link.

### 0.2 · Rust toolchain

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup default stable
rustup update
rustc --version  # → rustc 1.91 or later
```

### 0.3 · Docker Engine + Compose v2

**RHEL 9:**

```sh
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"  # log out / back in for group to take effect
```

**Ubuntu / Debian:**

```sh
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
```

### 0.4 · k6 (optional — only for §8 load tests)

The k6 RPM/DEB repos sometimes return 404. The pre-built tarball is the most
reliable install:

```sh
url=$(curl -fsSL https://api.github.com/repos/grafana/k6/releases/latest \
  | grep -oE 'https://[^"]+linux-amd64\.tar\.gz' | head -1)
curl -fsSL -o /tmp/k6.tar.gz "$url"
mkdir -p /tmp/k6 && tar -xzf /tmp/k6.tar.gz -C /tmp/k6 --strip-components=1
sudo install -m 0755 /tmp/k6/k6 /usr/local/bin/k6
k6 version  # → k6 v1.7.x
```

### 0.5 · Go (needed only for the bundled mock upstream)

```sh
# RHEL 9
sudo dnf install -y golang

# Ubuntu
sudo apt-get install -y golang-go

go version  # → go1.21+ acceptable
```

### 0.6 · Verify

```sh
docker --version          # → Docker version 24.x+
docker compose version    # → Docker Compose version v2.x+
rustc --version           # → rustc 1.91+
cargo --version           # → cargo 1.91+
openssl version           # → OpenSSL 3.x
go version                # → go1.21+
k6 version                # → k6 v1.7.x (if installed)
```

### 0.7 · Ports

The WAF and infra hold:

`80`, `443`, `8080`, `9443` (WAF), `6379` (Redis), `9090` (Prometheus),
`3000` (Grafana), `9999` (mock upstream), `9121` (Redis exporter).

```sh
for p in 80 443 8080 9443 6379 9090 3000 9999 9121; do
  sudo ss -tlnp | grep -q ":$p " && echo "PORT $p IN USE" || echo "port $p free"
done
```

Every line must say `port N free`.

---

## 1 · Get the code

```sh
sudo mkdir -p /opt && sudo chown "$USER" /opt
cd /opt
git clone https://github.com/<your-org>/aegis-gate.git
cd aegis-gate
git rev-parse HEAD     # → record the commit you're building from
```

> Working directory in this guide is `/opt/aegis-gate`. Sub-paths in commands
> are relative to that.

---

## 2 · Build the release binary

### 2.1 · ONNX Runtime — install the matched prebuilt

**This is the key prerequisite for the `ai` feature.** RHEL 9 has glibc 2.34;
the `ort` Rust crate's `download-binaries` default fetches a prebuilt linked
against glibc 2.38 — **it will not link**. The fix is to use Microsoft's
official ORT release tarball and `load-dynamic` mode.

> **Version pin:** ORT **1.24.4** — chosen because it matches the `ort` crate's
> `api-24` binding (see §2.2). ORT 1.20.x has compatible glibc but the
> `api-24` binding causes a futex deadlock during AI model load
> (`OrtApi` field layout mismatch). 1.24.4 is the lowest version that
> satisfies both constraints. Higher patch releases (1.24.5+) are likely
> compatible but untested.

```sh
# Download + verify glibc compat
cd /tmp
curl -fsSL -o ort.tgz \
  "https://github.com/microsoft/onnxruntime/releases/download/v1.24.4/onnxruntime-linux-x64-1.24.4.tgz"
mkdir -p ort && tar -xzf ort.tgz -C ort --strip-components=1

# Verify: must show NO __isoc23_* symbols (those require glibc 2.38)
objdump -T /tmp/ort/lib/libonnxruntime.so | grep __isoc23 | head -1
# Expected: empty output (no isoc23 symbols)

# Install + register
sudo install -m 0755 /tmp/ort/lib/libonnxruntime.so.1.24.4 /usr/local/lib/
sudo ln -sf libonnxruntime.so.1.24.4 /usr/local/lib/libonnxruntime.so
sudo ln -sf libonnxruntime.so.1.24.4 /usr/local/lib/libonnxruntime.so.1
sudo ldconfig

ls -la /usr/local/lib/libonnxruntime.so*
# Expected: three symlinks/files pointing at the 1.24.4 .so
```

### 2.2 · Cargo.toml — `ort` workspace dep

Confirm the workspace dep in `/opt/aegis-gate/Cargo.toml` matches this
exact line:

> **Optional — remote AI (`aegis-infer`).** To offload ML inference to
> the standalone gRPC batch server instead of (or as a fallback to)
> in-process ONNX, add the `ai-remote` feature:
> `FEATURES="redis geoip alerts ai ai-remote taxii otel" make build`.
> This also builds the `aegis-infer` server crate. Set it up in
> [§ 6.5](#65--optional-remote-ai-inference-aegis-infer) below. Skip this
> if you are benchmarking the in-process AI path.

```toml
ort = { version = "=2.0.0-rc.12", default-features = false, features = ["load-dynamic", "ndarray", "std", "tracing", "api-24"] }
```

Why each token matters:

| token | purpose |
|---|---|
| `=2.0.0-rc.12` | pinned — newer release-candidates may shift the binding |
| `default-features = false` | drops `download-binaries` (the failure path) |
| `load-dynamic` | dlopen libonnxruntime.so at runtime |
| `ndarray` | tensor type used by `aegis-security`'s features module |
| `std` + `tracing` | dropped by `default-features = false`; needed by callers |
| `api-24` | matches ORT 1.24.x binding layout |

> **Gotcha:** with `load-dynamic` alone (no `api-24`), every execution-provider
> module compiles its call site but the `OrtApi` binding doesn't include the
> EP fields → `error[E0609]: no field 'SessionOptionsAppendExecutionProvider_VitisAI'`.
> `api-24` resolves this.

### 2.3 · Build the WAF

```sh
cd /opt/aegis-gate

# default Makefile FEATURES; explicit string for clarity:
FEATURES="redis geoip alerts ai taxii otel" make build

ls -la target/release/waf            # → ~30 MB
./target/release/waf version         # → aegis-gate 0.1.0 (aegis-bin)
```

If you see `error: linker 'cc' not found` → `sudo dnf install gcc-c++` (RHEL) or
`sudo apt-get install build-essential` (Ubuntu).

If you see `error: undefined symbol: __isoc23_strtoll` → step 2.1 was skipped
or `ort` is still on `download-binaries`. Re-do step 2.1 and re-check the
`Cargo.toml` line.

### 2.4 · CAP_NET_BIND_SERVICE (for binding `:80` / `:443`)

```sh
sudo setcap 'cap_net_bind_service=+ep' /opt/aegis-gate/target/release/waf
getcap /opt/aegis-gate/target/release/waf
# Expected: cap_net_bind_service=ep
```

> **Reapply after every `make build`** — file capabilities are lost on
> binary replacement. The systemd unit's `AmbientCapabilities` covers this
> too, but the explicit setcap lets you also run the binary directly.

### 2.5 · Stage the v2.5 binary contract

The OC's benchmarker (`waf_interop_contract_v2.5 §8`) invokes `./waf run`
from the working directory and reads `./waf.yaml` + `./waf_audit.log`. We
keep the canonical config at `config/staging.yaml` and present it via a
symlink:

```sh
cd /opt/aegis-gate
ln -sf target/release/waf ./waf
ln -sf config/staging.yaml ./waf.yaml
ls -la ./waf ./waf.yaml
```

Both are git-ignored at the repo root (`.gitignore`: `/waf`, `/waf.yaml`,
`/waf_audit.log`). Re-create after every `git clean`.

---

## 3 · TLS certificate

Pick **one** track.

### Track A — self-signed (fastest, offline-friendly)

```sh
make cert
ls config/certs/
# Expected: dev.crt + dev.key
```

SANs default to `localhost, 127.0.0.1, ::1, aegis-gate.local`. Edit
`config/gen-cert.sh` if you need a different hostname.

### Track B — Let's Encrypt (ACME, public CA)

The WAF ships a leader-gated ACME manager backed by `instant-acme = 0.8.5`.
Prereqs the host must satisfy:

| Prereq | HTTP-01 (default) | TLS-ALPN-01 | DNS-01 |
|---|---|---|---|
| Public DNS A record → this host | required | required | required |
| Inbound :80 reachable from the public internet | **required** | not needed | not needed |
| Inbound :443 reachable from the public internet | not needed | required | not needed |
| DNS provider API credentials | not needed | not needed | required |
| Wildcard cert support | no | no | yes |

> **AWS SG gotcha:** if inbound :80 is scoped to "your team's IP only", LE's
> validator (rotating worldwide IPs) cannot reach you. Inbound `:80` must
> be open from `0.0.0.0/0` (and `::/0`) for the duration of issuance.
> The doc-default `tls.acme.challenge: http01` requires this.

**ACME config block — substitute into `config/staging.yaml` § `tls:`:**

```yaml
tls:
  min_version: "1.2"
  certificates:
    # Bootstrap cert — required at config time. Replaced live by ACME
    # once issuance succeeds (cert hot-swap log line confirms).
    - cert_path: "config/certs/dev.crt"
      key_ref:   "config/certs/dev.key"
      hosts:     ["staging-waf.example.com", "localhost", "127.0.0.1"]

  acme:
    # ⚠️ START on STAGING; flip to prod only after one clean staging round trip
    directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
    contacts:        ["mailto:ops@example.com"]              # REPLACE
    domains:         ["staging-waf.example.com"]             # REPLACE
    account_key_path: "/var/lib/aegis/acme/account-staging.json"
    cert_dir:         "/var/lib/aegis/certs"
    renew_before:     30d
    terms_of_service_agreed: true
    challenge:        http01   # http01 | tls_alpn01 | dns01
```

After step 6 boots the WAF, watch `journalctl -u aegis-gate -f | grep acme`
for the issuance sequence. Switch `directory_url` to
`https://acme-v02.api.letsencrypt.org/directory` after one clean staging
round-trip; rotate `account_key_path` to a separate filename (e.g.
`account-prod.json`) since LE staging and prod accounts are separate.

State dirs:

```sh
sudo mkdir -p /var/lib/aegis/acme /var/lib/aegis/certs
sudo chown -R "$USER" /var/lib/aegis
```

---

## 4 · Bring up the infra stack

```sh
cd /opt/aegis-gate
docker compose -f deploy/docker-compose.dev.yml up -d \
  redis prometheus grafana redis-exporter
docker compose -f deploy/docker-compose.dev.yml ps
```

Expected: `aegis-redis`, `aegis-prometheus`, `aegis-grafana`,
`aegis-redis-exporter` all `Up` and (where applicable) `healthy`.

Smoke each:

```sh
docker exec aegis-redis redis-cli ping           # → PONG
curl -fsS http://127.0.0.1:9090/-/ready          # → 200 Prometheus Server is Ready.
curl -fsS http://127.0.0.1:3000/api/health | jq  # → {"database": "ok", ...}
curl -fsS http://127.0.0.1:9121/metrics | head -3  # → Prometheus exposition (redis_*)
```

### Build + run the mock upstream

The bundled fast-upstream is needed for synthetic benchmarks.

```sh
cd /opt/aegis-gate
make upstream-build      # → /tmp/aegis-fast-upstream (Go binary, ~10 MB)
```

Start it as a transient systemd unit so it survives shell exits and is
restartable:

```sh
sudo systemd-run --unit=aegis-bench-upstream \
  --description="Aegis-Gate mock upstream (fast-upstream)" \
  --uid="$USER" --gid="$USER" \
  /tmp/aegis-fast-upstream
sleep 1
curl -fsS http://127.0.0.1:9999/health    # → {"status":"ok"}
```

---

## 5 · Configure the WAF for staging

`config/staging.yaml` is what `./waf.yaml` points at. Below is the template
in full, then a table mapping every operator decision.

### 5.1 · Template (gitignored — operator-local)

```yaml
listeners:
  data:
    # Public TLS — uses LE-issued cert from tls.acme (or bootstrap cert)
    - bind: "0.0.0.0:443"
      tls: true
    # Loopback plaintext — for the local k6 benchmark harness
    - bind: "127.0.0.1:8080"
      tls: false
  # Loopback-only admin / dashboard
  admin:
    bind: "127.0.0.1:9443"
  # ACME HTTP-01 + force-https redirect
  force_https:
    bind: "0.0.0.0:80"
    status: 308

# § 3 above provides this block on Track B; remove on Track A
tls:
  min_version: "1.2"
  hsts:
    max_age: 31536000
    include_subdomains: true
    preload: false
  certificates:
    - cert_path: "config/certs/dev.crt"
      key_ref:   "config/certs/dev.key"
      hosts:     ["YOUR_PUBLIC_HOST", "localhost", "127.0.0.1"]
  # acme block from § 3 Track B (optional)

routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: app-pool

upstreams:
  app-pool:
    members:
      - addr: "127.0.0.1:9999"   # REPLACE for real benchmarks
    lb: round_robin

state:
  backend: redis
  redis:
    urls: ["redis://127.0.0.1:6379"]
    pool_size: 32
    timeout: "100ms"

# Risk scoring — prod-balanced defaults with a benchmark override
risk:
  weights:
    bad_asn: 15
    bad_ja4: 10
    failed_auth: 20
    detector_hit: 25
    bot_unknown: 10
    repeat_offender: 15
  decay_half_life: "5m"
  thresholds:
    challenge_at: 40
    block_at:     85   # bumped 80 → 85 (2026-05-18) to reduce detector-stack FPs
  strikes:
    # v2.5 §5.5 — disable lifetime strike-block during benchmarks so a
    # single FP can't cascade across one phase. Real production: 50.
    block_at: 1000000

load_mode:
  elevated_rps:    1500
  critical_rps:    4000
  sample_interval: 1s

audit:
  sinks:
    - jsonl:
        path: "/var/log/aegis/audit.ndjson"
  chain:
    enabled: true
  retention: "7d"
  pseudonymize_ip: false

# Rate limit — bumped 6000 → 10000 (2026-05-20) per operator request
rate_limit:
  buckets:
    - id: global-ip
      scope: global
      key: ip
      algo: sliding_window
      limit: 10000
      window: "1m"

# DDoS gate — disabled for single-source-IP benchmarks. Production: enable.
ddos:
  enabled: false

rules:
  paths: []
  max_rule_count: 10000
  strict_compile: false

detectors:
  sqli:             { enabled: true }
  xss:              { enabled: true }
  path_traversal:   { enabled: true }
  ssrf:             { enabled: true }
  header_injection: { enabled: true }
  body_abuse:       { enabled: true }
  recon:            { enabled: true }
  brute_force:      { enabled: true }

# AI detector — needs --features ai in the build (default for this profile)
ai:
  enabled: true
  model_path: /opt/aegis-gate/data/ai_model/waf_model.onnx
  confidence_threshold: 0.90   # bumped 0.85 → 0.90 to reduce aggregator FPs

observability:
  prometheus:
    bind: "127.0.0.1:9100"     # 9090 owned by docker prom; use 9100
    enabled: true

geoip:
  country_db: "data/geoip/GeoLite2-Country.mmdb"
  asn_db:     "data/geoip/GeoLite2-ASN.mmdb"

admin:
  bind: "127.0.0.1:9443"
  environment: staging
  dashboard_auth:
    password_hash_ref: "$argon2id$v=19$m=19456,t=2,p=1$REPLACE_WITH_REAL_HASH$REPLACE"
    csrf_secret_ref:   "REPLACE_WITH_32B_RANDOM"
    session_ttl_idle:     "30m"
    session_ttl_absolute: "8h"
    ip_allowlist:
      - "127.0.0.1/32"
      - "::1/128"

# v2.5 §2.5 — OC benchmarker reads ./waf_audit.log + uses this secret
interop:
  enabled: true
  audit_path: "./waf_audit.log"               # ⚠️ RELATIVE per v2.5 §8
  control_secret: "waf-hackathon-2026-ctrl"   # v2.5 §2.2 well-known default
```

### 5.2 · Decisions table (each row is operator-tuned, not a default)

| Field | Staging value | Why |
|---|---|---|
| `interop.audit_path` | `"./waf_audit.log"` | v2.5 §8 contract — relative to WAF cwd. Putting it under `/var/log/aegis/` breaks the OC harness lookup. |
| `interop.control_secret` | `"waf-hackathon-2026-ctrl"` | v2.5 §2.2 well-known literal — avoids out-of-band coordination with OC. Replace with a fresh random for non-OC deployments. |
| `ai.enabled` | `true` | Default for this profile after the ORT 1.24.4 + load-dynamic recipe in §2.1 |
| `ai.confidence_threshold` | `0.90` | Raised from 0.85 — the aggregator + first-fire chain otherwise causes FPs even at low AI confidence. Verify FPR against `data/ai_model/WAF_DATASET_REPORT.md`. |
| `rate_limit.buckets[0].limit` | `10000` | Bumped from 6000 (2026-05-20). Single-source benchmarks need headroom. |
| `risk.thresholds.block_at` | `85` | 80 → 85 to reduce detector-stack FPs (a single request hitting 6 detectors at 15-20 each crosses 80). |
| `risk.strikes.block_at` | `1000000` | v2.5 §5.5 — lifetime strike block disabled for benchmarks. |
| `ddos.enabled` | `false` | Single-source IP would always trip the per-IP burst gate. Hot-flippable via `PUT /api/gates/ddos`. |
| `observability.prometheus.bind` | `"127.0.0.1:9100"` | `:9090` is owned by the docker Prometheus container. |

### 5.3 · Mint the admin password + CSRF secret

```sh
cd /opt/aegis-gate

# Admin password
printf 'YourStrongPassword\n' | ./target/release/waf admin set-password
# Copy the printed $argon2id$... and paste into
# admin.dashboard_auth.password_hash_ref (single-quoted YAML string)

# CSRF secret
openssl rand -base64 32
# Paste into admin.dashboard_auth.csrf_secret_ref

./waf validate --config ./waf.yaml
# Expected: config OK: ./waf.yaml
```

### 5.4 · Audit log directory

```sh
sudo mkdir -p /var/log/aegis
sudo chown "$USER" /var/log/aegis
```

---

## 6 · Boot the WAF

### Option A — systemd (recommended; survives reboots, captures stdout to journald)

```sh
sudo tee /etc/systemd/system/aegis-gate.service > /dev/null <<EOF
[Unit]
Description=Aegis-Gate WAF (staging benchmark)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/aegis-gate
ExecStart=/opt/aegis-gate/target/release/waf run --config /opt/aegis-gate/config/staging.yaml
ExecStop=/bin/kill -TERM \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Environment=RUST_LOG=info
Environment=AEGIS_DRAIN_GRACE_MS=10000
EnvironmentFile=/etc/aegis-gate.env

[Install]
WantedBy=multi-user.target
EOF

# Env file with secrets + ORT path
sudo tee /etc/aegis-gate.env > /dev/null <<EOF
AEGIS_CSRF_SECRET=$(openssl rand -base64 32)
AEGIS_BENCHMARK_SECRET=waf-hackathon-2026-ctrl
ORT_DYLIB_PATH=/usr/local/lib/libonnxruntime.so
EOF
sudo chmod 600 /etc/aegis-gate.env

sudo systemctl daemon-reload
sudo systemctl enable --now aegis-gate
sudo systemctl status aegis-gate --no-pager | head -10
```

> **Notes:**
> - `Type=simple` (not `notify`) — the WAF doesn't `sd_notify(READY=1)`;
>   `notify` causes a 90-s startup timeout.
> - `ORT_DYLIB_PATH` env is **required** when the binary is built with
>   `--features ai`; without it the WAF panics during AI detector load.
> - `enable --now` makes the WAF auto-start after reboots. The default is
>   `disabled` for staging — flip it on with this command.

Expected boot log:

```
INFO waf: state backend = redis @ redis://127.0.0.1:6379 (...)
INFO aegis_proxy::run: ddos: runtime installed; enabled is hot-flippable ...
INFO aegis_proxy::run: AI detector loaded; runtime toggle wired
       model_path=.../data/ai_model/waf_model.onnx threshold=0.9 initial_enabled=true
INFO ort: Loaded ONNX Runtime dylib from "/usr/local/lib/libonnxruntime.so"; version '1.24.4'
INFO aegis_proxy::run: external interop contract enabled — control plane on
       /__waf_control audit_path=./waf_audit.log
INFO data-plane listening on 0.0.0.0:443 (tls=true)
INFO data-plane listening on 127.0.0.1:8080 (tls=false)
INFO force-https redirect listening on 0.0.0.0:80
INFO admin-plane listening on 127.0.0.1:9443 (http)
INFO aegis_proxy::accept: geoip reader wired into AttacksHandler ...
```

### Option B — foreground (development / debugging)

```sh
cd /opt/aegis-gate
AEGIS_CSRF_SECRET=$(openssl rand -base64 32) \
ORT_DYLIB_PATH=/usr/local/lib/libonnxruntime.so \
RUST_LOG=info \
  ./target/release/waf run --config config/staging.yaml
```

Ctrl-C triggers a graceful drain — readiness flips to 503, listeners close
after `AEGIS_DRAIN_GRACE_MS` (default 5 s).

---

## 6.5 · (Optional) Remote AI inference (`aegis-infer`)

Skip this section unless you built with `ai-remote` (§ 2) and want ML
inference offloaded to the batch serving server. Full reference:
[`GUIDE.md` § 8](GUIDE.md#8-remote-ai-inference-aegis-infer) and
[`../data/serving-server/INTEGRATION.md`](../data/serving-server/INTEGRATION.md).
Co-located over a Unix socket is the staging-recommended topology.

```sh
# 1 — build the serving-server binary alongside the WAF
cd ~/aegis-gate/data/serving-server
~/.cargo/bin/cargo build --release --bin aegis-infer
sudo install -m 0755 target/release/aegis-infer /usr/local/bin/aegis-infer

# 2 — stage the model artifact (operator-supplied; never in git)
sudo mkdir -p /etc/aegis/ai_model
sudo cp /path/to/waf_model.onnx /etc/aegis/ai_model/waf_model.onnx

# 3 — install + start the serving server (UDS at /run/aegis-infer/infer.sock)
sudo tee /etc/systemd/system/aegis-infer.service > /dev/null <<'EOF'
[Unit]
Description=Aegis WAF AI Inference Server
After=network.target
# Order ahead of the WAF (optional; the WAF fail-soft if absent)
Before=aegis-gate.service

[Service]
Type=simple
User=YOUR_USER
RuntimeDirectory=aegis-infer
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/aegis-infer \
    --model-path /etc/aegis/ai_model/waf_model.onnx \
    --workers 2 --max-batch 128 --delay-ms 2 \
    --bind-uds /run/aegis-infer/infer.sock \
    --log-level info
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
sudo sed -i "s/YOUR_USER/$USER/" /etc/systemd/system/aegis-infer.service
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-infer
sudo systemctl status aegis-infer --no-pager     # expect: active, mode=onnx
```

Then point the WAF config (`config/staging.yaml`) at the socket and
restart the WAF:

```yaml
ai:
  enabled: true
  confidence_threshold: 0.85
  remote_endpoint: unix:///run/aegis-infer/infer.sock
```

```sh
./waf validate --config config/staging.yaml
sudo systemctl restart aegis-gate
# Confirm the WAF picked up the remote detector:
journalctl -u aegis-gate | grep -i "remote AI detector connected"
```

**Sizing for the 3–5k RPS benchmark target:** `--workers 2 --max-batch
128 --delay-ms 2` is a good start; bump `--workers` toward physical core
count if the `aegis-infer` `Stats` show `avg_batch_size` pinned near 1
(under-batching) or inference latency climbing. **Fail-open** is
unconditional: if `aegis-infer` is stopped mid-run the WAF keeps serving
on the regex chain (AI signals just stop) — verify with
`sudo systemctl stop aegis-infer` and confirm traffic still flows + a
`remote ai inference error` line appears at TRACE.

---

## 7 · Smoke test

```sh
SECRET="waf-hackathon-2026-ctrl"

# Liveness + readiness
curl -fsS http://127.0.0.1:9443/healthz/ready | jq -c .
# Expected: {"status":"ok", "checks":{...all true...}, "mode":"enforce", ...}

# Data plane (loopback HTTP)
curl -i http://127.0.0.1:8080/                  # → 200 / forwarded JSON

# TLS handshake (self-signed → -k)
curl -ki https://127.0.0.1:443/                 # → 200 / forwarded

# Admin metrics
curl -fsS http://127.0.0.1:9443/metrics | head -10   # → openmetrics format
```

### Attack probes

```sh
curl -i 'http://127.0.0.1:8080/?q=1%27%20OR%20%271%27%3D%271'        # → 403 (sqli)
curl -i 'http://127.0.0.1:8080/files?p=../../../../etc/passwd'        # → 403 (path_traversal)
curl -i 'http://127.0.0.1:8080/?x=%3Cscript%3Ealert(1)%3C/script%3E'  # → 403 (xss)

# Check rule_id stamping (should include `ai` on SQLi requests if AI fires)
curl -ksi 'http://127.0.0.1:8080/?q=1%27%20OR%20%271%27%3D%271' \
  | grep -i 'x-waf-rule-id'
# Expected: "x-waf-rule-id: sqli,ai" (or similar — AI co-fires)
```

### Audit chain

```sh
ls -la ./waf_audit.log                            # grows on every request
tail -3 ./waf_audit.log | jq '{action, rule_id, risk_score}'
ls -la /var/log/aegis/audit-$(date +%Y-%m-%d).ndjson   # hash-chain sink
```

### Open the dashboard

`http://<host>:9443/dashboard` (admin port; loopback-only by default — SSH-tunnel
`-L 9443:127.0.0.1:9443` from your laptop). Sign in at `/admin/login` with the
password you set in §5.3.

> **Gotcha — session is in-memory.** Every WAF restart wipes the session
> store. After a restart you'll get 401 `admin_unauthenticated` on any
> `/api/*` call — log in again. The Reports page caps the audit ring at
> 200 events (`crates/aegis-control/src/api/audit.rs`'s `DEFAULT_CAP = 200`);
> use the on-disk audit file for long-window analysis.

---

## 7.5 · v2.5 interop contract conformance

The OC's benchmarker (`waf_interop_contract_v2.5`) exercises a small control
plane + response-header surface. **Verify every requirement before running
the perf harness** — contract failures surface deterministically here.

> **v2.5 topology assumption:** the benchmarker runs on a separate host
> (not the WAF host). It reaches the WAF data plane (`:443`/`:8080`) over
> the public network. Control endpoints are loopback-only — the
> benchmarker tunnels via SSH (`ssh -L 8080:127.0.0.1:8080 ...`).

### 7.5.1 · Four required control endpoints (§ 2.1)

```sh
SECRET="waf-hackathon-2026-ctrl"
H="http://127.0.0.1:8080"

curl -ks -H "X-Benchmark-Secret: $SECRET" "$H/__waf_control/capabilities" | jq
# Expected: ok:true, features={access_control, rules_engine, rate_limit, risk_engine},
#           active.default_mode:"enforce", active.overrides:{}

LINES_BEFORE=$(wc -l < ./waf_audit.log)
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" "$H/__waf_control/reset_state" | jq
LINES_AFTER=$(wc -l < ./waf_audit.log)
echo "audit lines:  before=$LINES_BEFORE  after=$LINES_AFTER"
# Expected: ok:true, audit_log_preserved:true, lines_after >= lines_before

curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["sqli"]}' \
  "$H/__waf_control/set_profile" | jq
# Expected: ok:true, active.overrides:{"rules_engine.sqli":"log_only"}

curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" "$H/__waf_control/flush_cache" | jq
# Expected: ok:true, action:"flush_cache", supported:false  (graceful no-op)
```

### 7.5.2 · Auth gate (§ 2.2) — wrong/missing → 403

```sh
curl -ksi "$H/__waf_control/capabilities" | head -1                            # → 403
curl -ksi -H "X-Benchmark-Secret: wrong" "$H/__waf_control/capabilities" | head -1   # → 403
```

### 7.5.3 · Loopback gate (§ 4) — non-loopback caller sees 404

The control plane is **invisible** from non-loopback peers (the gate is
in `crates/aegis-proxy/src/admin_dispatch.rs:108`).
Quick proof — same call over the public `:443` listener instead of
loopback `:8080` returns 404 / login redirect:

```sh
curl -ksi -H "X-Benchmark-Secret: $SECRET" \
  https://127.0.0.1:443/__waf_control/capabilities | head -3
# Expected: 404  (the WAF treats the public bind as non-loopback for the gate)
```

### 7.5.4 · Six required X-WAF-* response headers (§ 5.1)

```sh
echo "--- benign ---"
curl -ksi "$H/" | grep -i '^x-waf-' | sort
# Expected 6+ lines:
#   x-waf-action: allow
#   x-waf-cache: BYPASS
#   x-waf-mode: enforce
#   x-waf-overhead-latency: <ms>
#   x-waf-request-id: <uuid>
#   x-waf-risk-score: 0
#   x-waf-rule-id: none

echo "--- sqli attempt ---"
curl -ksi "$H/?q=1%27%20OR%20%271%27%3D%271" | grep -i '^x-waf-' | sort
# Expected: action: block, rule-id: sqli (and ai if AI co-fires), risk-score > 0
```

### 7.5.5 · `log_only` enforcement skip (§ 5.3)

```sh
# Put sqli into log_only
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["sqli"]}' \
  "$H/__waf_control/set_profile" > /dev/null

# Probe — should now be 200 (upstream body), with audit/headers saying block
curl -ksi "$H/?q=1%27%20OR%20%271%27%3D%271"
# Expected first line: HTTP/1.1 200 OK
# Expected headers:    x-waf-action: block, x-waf-mode: log_only, x-waf-rule-id: sqli
# Expected body:       from upstream (e.g. fast-upstream's JSON)

# Restore enforce
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"all","mode":"enforce"}' \
  "$H/__waf_control/set_profile" > /dev/null
```

### 7.5.6 · Audit log shape (§ 6)

```sh
tail -1 ./waf_audit.log | jq 'keys'
# Expected (sorted): ["action","ip","method","mode","path","request_id",
#                     "risk_score","rule_id","tier","ts_ms"]
# (8 required + rule_id + tier as bonus fields)

# X-WAF-Request-Id matches audit request_id on the same request:
RID=$(curl -ksi "$H/" | grep -i '^x-waf-request-id:' | awk '{print $2}' | tr -d '\r')
grep "\"request_id\":\"$RID\"" ./waf_audit.log | jq .
# Expected: exactly one row
```

### 7.5.7 · `/challenge/verify` public on the data plane (§ 4)

```sh
curl -ksi -X POST -H 'content-type: application/json' -d '{}' "$H/challenge/verify" | head -3
# Expected: HTTP/1.1 400 Bad Request  (handler reached; rejects empty body)
# NOT: 404 — that would indicate the endpoint isn't wired
```

---

## 8 · Run the benchmark

The repo ships harnesses under `tests/`. Pick one:

| Harness | What it measures | Run |
|---|---|---|
| `tests/hackathon/run-prod-balanced-5k.sh` | sustained 5k+ RPS on prod-balanced | `bash tests/hackathon/run-prod-balanced-5k.sh` |
| `tests/perf/ai-compare.sh` | AI on/off/chained perf comparison | `bash tests/perf/ai-compare.sh` |
| `tests/hackathon/run.sh` | 15-min mixed-traffic round | `bash tests/hackathon/run.sh` |
| `tests/load/baseline.js` | Plain k6 baseline | `k6 run tests/load/baseline.js` |

**For long unattended runs, use systemd-run** so the bench survives shell
exits and Claude Code sandboxing:

```sh
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="/opt/aegis-gate/tests/results/run-load-${TS}"
mkdir -p "$RUN_DIR/artifacts" "$RUN_DIR/logs"

# Capture before-state
curl -ksS http://127.0.0.1:9443/metrics > "$RUN_DIR/artifacts/metrics-before.txt"
wc -l ./waf_audit.log | tee "$RUN_DIR/artifacts/audit-before.txt"
date -u +%Y-%m-%dT%H:%M:%SZ | tee "$RUN_DIR/artifacts/start-time.txt"

# Launch k6 as a transient unit
sudo systemd-run --unit=aegis-bench-k6 \
  --description="Aegis-Gate load test" \
  --working-directory=/opt/aegis-gate \
  --uid="$USER" --gid="$USER" \
  -p Environment="DURATION=2h" \
  -p Environment="WAF_TARGET=http://127.0.0.1:8080" \
  -p Environment="LEGIT_VUS=16" \
  -p Environment="CRAWLER_VUS=2" \
  -p Environment="ATTACKER_VUS=2" \
  /usr/local/bin/k6 run \
    --summary-export="$RUN_DIR/artifacts/k6-summary.json" \
    --log-output="file=$RUN_DIR/logs/k6.log" \
    tests/hackathon/k6/prod-balanced-5k.js

# Monitor in another shell
sudo journalctl -u aegis-bench-k6.service -f
```

> **VU sizing rule of thumb on this host (8-core, 15 GB RAM):**
> - **5 VUs total → ~500 RPS, ~1 ms p99** — sustainable indefinitely
> - **20 VUs → ~2k RPS** — also sustainable; **WAS** the rate that hung the
>   host before §12 kernel tuning was applied
> - **400 VUs → ~5k RPS** — saturates the WAF in ~17 min (CLOSE_WAIT leak;
>   admin plane starves). Don't use for runs > 15 min.

Outputs land under `tests/results/<run-dir>/`:

- `RUN-SUMMARY.md` — headline numbers (write this yourself when the run ends)
- `artifacts/k6-summary.json` — raw k6 output (only on clean exit)
- `artifacts/metrics-before.txt` / `metrics-after.txt` — Prometheus snapshots
- `logs/k6.log` / `logs/waf.log` — stdout

---

## 9 · Observability while benchmarking

| Surface | URL | Useful for |
|---|---|---|
| Prometheus | `http://<host>:9090/` | `rate(waf_requests_total[1m])`, `histogram_quantile(0.99, ...)` |
| Grafana | `http://<host>:3000/` (`admin/admin`) | bundled dashboards (WAF Overview, Runtime, Redis) |
| Dashboard Live Feed | `http://<host>:9443/dashboard#/live` | per-request stream |
| Audit chain | `tail -f ./waf_audit.log \| jq` | full per-request detail |

---

## 10 · Iterating on config without restarts

Most surfaces hot-reload via `/api/*` admin endpoints. Anything else is YAML
+ `sudo systemctl restart aegis-gate` (graceful drain).

| Surface | Hot-swap path |
|---|---|
| DDoS gate on/off | `PUT /api/gates/ddos` (also dashboard Traffic Gates card) |
| Detector mask | `PUT /api/detectors` (Detectors & Tiers page) |
| AI on/off | `PUT /api/ai/enabled` (Detectors page → AI row) |
| Mode (enforce/log_only) | `POST /__waf_control/set_profile` (v2.5 contract) |
| Routes / upstreams | Routing & Upstreams page |
| Rate-limit / DDoS thresholds | Settings → Rate-limit / DDoS card |
| Tier thresholds | Detectors → Edit Tier modal |
| Surgical risk reset (composite key) | `POST /api/risk/reset_key` |
| Per-IP risk reset | `PUT /api/risk/{ip}/reset` |

---

## 11 · Teardown

```sh
sudo systemctl stop aegis-bench-k6.service aegis-bench-monitor.service aegis-bench-upstream.service 2>/dev/null
sudo systemctl reset-failed aegis-bench-k6.service aegis-bench-monitor.service aegis-bench-upstream.service 2>/dev/null
sudo systemctl stop aegis-gate.service
docker compose -f deploy/docker-compose.dev.yml down

# Optional — drop benchmark output + audit chain
rm -rf tests/results/run-*
truncate -s 0 ./waf_audit.log
sudo rm -f /var/log/aegis/audit-*.ndjson
```

> **Audit chain truncation safety:** `./waf_audit.log` is opened with
> `O_APPEND` by the WAF; `truncate -s 0` is safe while the service is
> running and the next write resumes cleanly from offset 0.

---

## 12 · Kernel / host tuning (run once per machine)

These are **required** for sustained loads above ~500 RPS. The first 2k RPS
benchmark on this host hung at the 3 h mark with `nf_conntrack` table
exhaustion (default ceiling 262 144; at ~1,400 conns/sec × 120 s TIME_WAIT we
were close to the limit and any spike pushed over).

```sh
sudo tee /etc/sysctl.d/99-aegis-bench.conf > /dev/null <<EOF
# conntrack ceiling — bumped 4× for sustained benchmarks. Default 262144 is
# very thin at ~2k RPS; new SYN packets get silently dropped at the firewall
# when the table fills, including SSH from outside the host.
net.netfilter.nf_conntrack_max = 1048576

# TIME_WAIT timeout — shortened so short-lived connections free their
# conntrack entry faster.
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
EOF

sudo sysctl --system

# Verify
cat /proc/sys/net/netfilter/nf_conntrack_max                    # → 1048576
cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait  # → 30
```

> **Persistent journald** — RHEL 9's default `Storage=auto` falls back to
> `volatile` (`/run/log/journal/...`) when `/var/log/journal/` doesn't exist.
> All unit logs are wiped on every reboot, making post-mortem debugging hard.
> Fix once per host:
>
> ```sh
> sudo mkdir -p /var/log/journal
> sudo systemd-tmpfiles --create --prefix /var/log/journal
> sudo systemctl restart systemd-journald
> ```

---

## 13 · Monitoring sidecar (long-run safety net)

For runs longer than ~30 min, start this monitor alongside k6 so you have a
post-mortem trace if the host goes down:

```sh
cat > /tmp/aegis-bench-monitor.sh <<'EOF'
#!/usr/bin/env bash
OUT="${1:?out csv path}"
WAF_PID=$(systemctl show -p MainPID --value aegis-gate)
echo "ts_utc,conntrack,waf_cpu_pct,waf_rss_kb,sock_8080_est,sock_8080_cw,load1,mem_avail_kb" > "$OUT"
while true; do
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
  read cpu rss < <(ps -o pcpu,rss -p "$WAF_PID" --no-headers 2>/dev/null || echo "0 0")
  est=$(ss -tan state established sport = :8080 2>/dev/null | wc -l)
  cw=$(ss -tan state close-wait sport = :8080 2>/dev/null | wc -l)
  load=$(awk '{print $1}' /proc/loadavg)
  avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
  echo "$ts,$ct,$cpu,$rss,$est,$cw,$load,$avail" >> "$OUT"
  sleep 10
done
EOF
chmod +x /tmp/aegis-bench-monitor.sh

sudo systemd-run --unit=aegis-bench-monitor \
  --description="Aegis-Gate bench sysstat sidecar (10s sample CSV)" \
  --uid="$USER" --gid="$USER" \
  /tmp/aegis-bench-monitor.sh "$RUN_DIR/artifacts/sysstat.csv"
```

Then in the RUN-SUMMARY, aggregate with:

```sh
awk -F, 'NR>1 { for(i=2;i<=NF;i++){ if(min[i]==""||$i<min[i])min[i]=$i;
  if(max[i]==""||$i>max[i])max[i]=$i; sum[i]+=$i; cnt[i]++ } }
END { for(i=2;i<=8;i++) printf "col%d: min=%s avg=%.1f max=%s\n", i, min[i], sum[i]/cnt[i], max[i] }' \
  "$RUN_DIR/artifacts/sysstat.csv"
```

---

## 14 · Common gotchas (operator-discovered, learn from these)

| Symptom | Root cause | Fix |
|---|---|---|
| `error: undefined symbol: __isoc23_strtoll` at link time | `ort` crate's `download-binaries` mode pulled a glibc-2.38 prebuilt; RHEL 9 has 2.34 | Use the §2.1 recipe (Microsoft prebuilt + `load-dynamic`) |
| `error[E0609]: no field 'SessionOptionsAppendExecutionProvider_VitisAI' on OrtApi` | `default-features = false` dropped `api-24`, but EP modules still compile under `load-dynamic` | Add `api-24` to the feature list — § 2.2 has the exact line |
| WAF boots, RSS ~57 MB, hangs at `futex_wait_queue` immediately after `libonnxruntime.so` mmap | ORT 1.20.x .so used with `api-24` binding → `OrtApi` field layout mismatch → deadlock during `commit_from_file` | Use **ORT 1.24.4**, not 1.20.x — § 2.1 |
| WAF refuses to start with `config: ai.enabled = true but the binary was built without --features ai` | Rebuilt without the `ai` feature | `FEATURES="redis geoip alerts ai taxii otel" make build` |
| `acme: missing field 'token'` parse error during issuance | `instant-acme` 0.7.x can't deserialize LE's new `dns-persist-01` challenge | Bumped to 0.8.5 in this build (see §0.0); confirm the workspace dep |
| `acme: timed out waiting for an order update` | Inbound `:80` not reachable from the public internet (LE rotates IPs; team-IP-scoped SG drops the probe) | Open SG to `0.0.0.0/0` on TCP 80 (and 443); see § 3 Track B |
| Dashboard 401 "API unreachable" after WAF restart | Session store is in-memory; restart wipes every session cookie | Re-login at `/admin/login` |
| Dashboard "Detectors & Tiers" / "Upstreams" shows empty / "no tiers" | Same 401 — fetch failed, fell back to empty state | Re-login |
| `audit.log` shows "only some rows" via UI | Reports page caps the in-memory ring at 200 events (`DEFAULT_CAP = 200`) | Read the on-disk file directly; cold-tier export is a deferred feature |
| Sustained 2k+ RPS for hours → host goes unreachable mid-run, eventually watchdog-reboots; audit still grows on disk | `nf_conntrack` table exhaustion; SSH dropped at firewall but loopback unaffected | Apply § 12 kernel tuning **before** the run; sidecar monitor catches it |
| k6 stops writing `--log-output=file=...` after ~2-3 h while still running | k6 1.7.x bug — file logger goroutine wedges (grafana/k6#4657) | Use stdout via systemd (`StandardOutput=...`) or `tee`; switch to `--log-output=stderr` |
| Single-source-IP benchmarks block every legit request (`x-waf-rule-id: behavior_burst`) | `behavior_burst` signal would fire on every per-IP repeat | **Retired in `e50ab79`** — no longer an issue on current code |
| Build fails: `npx: command not found` running `make build` | Makefile's dashboard JSX bundler dependency; the bundle (`app.js`) is committed | `touch crates/aegis-control/assets/dashboard/app.js && make build` — make sees the bundle as fresh and skips the JSX rebundle. Or install Node. |
| Strikes / risk blocks pile up at 127.0.0.1 during local testing | Shared-IP risk accumulation in single-source synthetic load | `docker exec aegis-redis redis-cli FLUSHDB` + `sudo systemctl restart aegis-gate` |
| WAF audit file grows ~3.4 GB / h at 2k RPS sustained | No logrotate rule for `./waf_audit.log` / `/var/log/aegis/*.ndjson` | Add a logrotate config — pending follow-up |

---

## 15 · For an AI assistant driving this end-to-end

**Briefing prompt to drop into an AI assistant session:**

```
You are deploying Aegis-Gate to a Linux staging host. Follow
deploy/STAGING-BENCHMARK.md top to bottom. After each numbered step, run
the Verify command(s) and confirm the output matches Expected before
moving on. If a Verify fails, do NOT continue — report the discrepancy
with: (a) the exact command run, (b) the expected output, (c) the actual
output, (d) `uname -a` + `cat /etc/os-release`. Do not edit config files
in place — always make backups (`cp file file.bak`) before sed/yq edits
so the operator can roll back.

Critical invariants:
- ORT 1.24.4 prebuilt is required (NOT 1.20.x — see §14 gotcha)
- Cargo.toml's `ort` line MUST include both `load-dynamic` AND `api-24`
- `./waf_audit.log` MUST be RELATIVE (v2.5 §8) — not an absolute path
- `interop.control_secret: "waf-hackathon-2026-ctrl"` is the v2.5
  well-known literal; the OC harness defaults to this
- DDoS gate stays disabled for single-source-IP benchmarks
- `ai.confidence_threshold: 0.90`, NOT 0.85
- `rate_limit.buckets[0].limit: 10000`, NOT 6000

If any step requires a decision the document doesn't cover (distro-specific
package name, an unfamiliar error), surface it to the operator with the
same "(a) (b) (c) (d)" shape as a failed Verify rather than guessing.
```

**Index of where to look first when something breaks:**

| Class of failure | First place to look |
|---|---|
| Build (link errors, missing symbols) | §2.1 + §14 gotchas table |
| ACME issuance fails | §3 Track B + §14 gotchas |
| WAF won't boot | §6 boot log — check for `ai.enabled=true but binary lacks --features ai`; check `ORT_DYLIB_PATH` in `/etc/aegis-gate.env` |
| v2.5 contract checks fail | §7.5 — each sub-step has the exact expected output |
| Benchmark hangs the host | §12 kernel tuning — was it applied? §13 sidecar — what does the CSV show? |
| Dashboard "API unreachable" / "No tiers" | §14 — session expired; re-login |

---

## Cross-references

- [`./GUIDE.md`](./GUIDE.md) — production deploy (multi-node + Helm + cluster).
- [`./README.md`](./README.md) — what's in `deploy/`.
- [`../QUICKSTART.md`](../QUICKSTART.md) — laptop dev path.
- [`../config/REFERENCE.md`](../config/REFERENCE.md) — per-block waf.yaml reference.
- [`../docs/FEATURES.md`](../docs/FEATURES.md) — feature playbook (verify each gate).
- [`../Hackathon_Doc/EN_waf_interop_contract_v2.5.md`](../Hackathon_Doc/EN_waf_interop_contract_v2.5.md) — v2.5 contract spec.
- [`../docs/security/security-engine.md`](../docs/security/security-engine.md) — request → decision walkthrough.
- [`../docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md) — Layer-1 worker sizing for the bench host.
- [`../tests/results/README.md`](../tests/results/README.md) — current benchmark baselines to compare against.
- [`../data/ai_model/WAF_DATASET_REPORT.md`](../data/ai_model/WAF_DATASET_REPORT.md) — AI model FPR / detection numbers.
