# Aegis-Gate — Linux Staging Deploy (Benchmark)

Single-Linux-machine staging deployment guide. **Infra (Redis,
Prometheus, Grafana) runs on the same machine via Docker; the WAF
runs as a native binary on the host** so benchmark numbers measure the
proxy itself, not Docker overhead.

This document is **deliberately mechanical** — every step has a
command, a Verify, and an Expected output. An AI assistant (Claude
Code, Cursor, etc.) can drive it end-to-end without judgement calls.

> Local laptop dev → [`../QUICKSTART.md`](../QUICKSTART.md).
> Multi-node production → [`./GUIDE.md`](./GUIDE.md).
> Architectural picture → [`../Architecture.md`](../Architecture.md).
> Verify each feature works → [`../docs/FEATURES.md`](../docs/FEATURES.md).

---

## What you'll have at the end

- WAF binary running on the staging host, listening on `:8080` (HTTP
  data plane), `:8443` (HTTPS), `:9443` (admin / dashboard / metrics).
- Redis on `:6379` (shared rate-limit counters, leader leases).
- Prometheus on `:9090` scraping the WAF.
- Grafana on `:3000` with three pre-loaded dashboards (WAF Overview,
  Runtime, Redis).
- Audit chain at `/var/log/aegis/audit.ndjson` (NDJSON, hash-chained).
- Either a real upstream wired in, or the bundled mock httpbin on
  `:8081` for synthetic benchmark traffic.

End-to-end smoke test takes ~10 minutes on a clean Ubuntu 22.04 box.

---

## 0 · Prerequisites

| Tool | Version | Install (Ubuntu / Debian) |
|---|---|---|
| OS | Ubuntu 22.04 LTS / Debian 12 / RHEL 9 | — |
| Docker Engine + Compose v2 | 24+ | `curl -fsSL https://get.docker.com \| sh && sudo usermod -aG docker $USER` then log out / back in |
| Rust toolchain | 1.91+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh -s -- -y` |
| Build deps | — | `sudo apt-get install -y build-essential pkg-config libssl-dev openssl curl jq git` |
| `k6` (load gen, optional) | latest | `sudo gpg -k; sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69; echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \| sudo tee /etc/apt/sources.list.d/k6.list; sudo apt-get update && sudo apt-get install -y k6` |

### Verify

```sh
docker --version          # → Docker version 24.x or later
docker compose version    # → Docker Compose version v2.x or later
rustc --version           # → rustc 1.91 or later
cargo --version           # → cargo 1.91 or later
openssl version           # → OpenSSL 3.x
```

### Ports the WAF and infra will hold

`8080`, `8443`, `9443` (WAF), `6379` (Redis), `9090` (Prometheus),
`3000` (Grafana), `8081` (httpbin mock upstream), `9121` (Redis exporter).

```sh
# Confirm no conflicts
for p in 8080 8443 9443 6379 9090 3000 8081 9121; do
  ss -tlnp | grep -q ":$p " && echo "PORT $p IN USE" || echo "port $p free"
done
```

Expected: every line says `port N free`. If anything is held, kill
the holder or change the WAF / compose port mapping before going on.

### Track B (Let's Encrypt cert) extras

If your bench team requires a public-CA cert (Let's Encrypt) instead
of the self-signed dev cert, add these prereqs — see §3 Track B for
the full ACME flow:

- **Public DNS A/AAAA record** pointing the staging host's hostname
  at the bench host's public IP (e.g. `staging-waf.example.com →
  203.0.113.45`). LE refuses to issue for IP literals, `.local`, or
  unresolvable names.
- **Inbound port 80 reachable** from the public internet (HTTP-01
  challenge default), **or** inbound 443 (TLS-ALPN-01), **or** API
  credentials for your DNS provider (DNS-01).
- **TOS agreed** — the operator must read and accept the LE
  Subscriber Agreement (`tls.acme.terms_of_service_agreed: true` in
  the config is the legal acknowledgement).

Add port 80 to the free-port check loop above when running Track B.

---

## 1 · Get the code

```sh
sudo mkdir -p /opt && sudo chown $USER /opt
cd /opt
git clone https://github.com/<your-org>/aegis-gate.git
cd aegis-gate
git rev-parse HEAD     # record the commit you're building from
```

Replace the URL with the actual repo. Record the commit in the
benchmark report so re-runs can be compared.

---

## 2 · Build the release binary

```sh
# The default Makefile target now includes ai, redis, geoip, alerts.
# For staging benchmark we also want taxii (threat-intel feed) and otel
# (so we can wire Jaeger if needed).
FEATURES="redis geoip alerts ai taxii otel" make build

# Verify
ls -la target/release/waf
./target/release/waf version
```

**Expected**: `target/release/waf` ≈ 50–60 MB. `version` prints a
build banner with the commit hash, Rust version, and feature flags.

If the build fails:

| Error | Fix |
|---|---|
| `error: linker 'cc' not found` | `sudo apt-get install -y build-essential` |
| `error: failed to run custom build command for openssl-sys` | `sudo apt-get install -y pkg-config libssl-dev` |
| `error[E0463]: can't find crate for std` | rustup toolchain bad — `rustup default stable && rustup update` |

---

## 3 · TLS certificate

Pick **one** track. Track A is offline-friendly (self-signed); Track
B satisfies "cert must be issued by a public CA" rules (Let's
Encrypt, via the WAF's built-in ACME manager).

### Track A — self-signed (fastest, offline-friendly)

```sh
make cert
ls config/certs/
```

**Expected**: `dev.crt` and `dev.key` exist. SANs are `localhost,
127.0.0.1, ::1, aegis-gate.local` — fine for staging from `127.0.0.1`
or the box's hostname. For benchmark from another machine, regenerate
with that hostname in the SAN list (edit `config/gen-cert.sh`).

### Track B — Let's Encrypt (public CA, ACME-issued)

The WAF ships a leader-gated ACME manager (`tls.acme` config block,
`crates/aegis-proxy/src/acme.rs`). Issuance + renewal happen in
process — no certbot, no acme.sh. Cert hot-swap on rotation.

**Prereqs that the bench host must satisfy:**

| Prereq | HTTP-01 (default) | TLS-ALPN-01 | DNS-01 |
|---|---|---|---|
| Public DNS name resolving to this host | **Required** (e.g. `staging-waf.example.com`) | Required | Required |
| Inbound port 80 reachable from internet | **Required** | not needed | not needed |
| Inbound port 443 reachable from internet | not needed | **Required** | not needed |
| DNS provider API credentials | not needed | not needed | **Required** |
| Wildcard cert (`*.example.com`) supported | no | no | yes |

`make cert` (the Track A target) is **not** run for Track B — the
ACME manager produces the cert. Skip it.

#### B.1 — pre-flight: confirm reachability

```sh
# Replace STAGING_HOST with the public DNS name. Run from another machine.
STAGING_HOST="staging-waf.example.com"

# DNS resolves to the bench host
dig +short "$STAGING_HOST"

# (HTTP-01 only) port 80 is reachable
curl -fsS -o /dev/null -w '%{http_code}\n' "http://$STAGING_HOST/.well-known/acme-challenge/probe"
# → 200 / 404 / 308 are all fine — what matters is that the connection succeeds
# → "Connection refused" / "timed out" means the firewall / port-forward isn't open
```

If port 80 must remain firewalled, switch `tls.acme.challenge` to
`tls_alpn01` (probe :443 instead) or `dns01` (no inbound ports
required, but you'll need API creds for your DNS provider).

#### B.2 — set up the ACME state directories

```sh
sudo mkdir -p /var/lib/aegis/acme /var/lib/aegis/certs
sudo chown -R $USER /var/lib/aegis
```

`account_key_path` (`/var/lib/aegis/acme/account.json`, written
`0600`) persists the LE account so re-issuance doesn't churn the
account. `cert_dir` (`/var/lib/aegis/certs/`) is where issued certs
land — one sub-dir per domain.

#### B.3 — pick the directory URL (staging first!)

| Use | URL |
|---|---|
| **Bring-up & smoke (always start here)** | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| Production benchmark | `https://acme-v02.api.letsencrypt.org/directory` |

LE prod has hard rate limits (50 certs/registered-domain/week, 5
duplicates/week); the staging endpoint has none and issues from a
fake CA root your tools won't trust by default — that's the
expected behaviour for the smoke step. Flip to prod only after a
clean staging round trip.

#### B.4 — config block

In step 5 (`config/staging.yaml`), use this `listeners` + `tls`
shape instead of the default. Substitute `STAGING_HOST` for your
real public DNS name.

```yaml
listeners:
  data:
    - bind: "0.0.0.0:8443"
      tls: true
    - bind: "0.0.0.0:8080"
      tls: false
  admin:
    bind: "127.0.0.1:9443"
  # HTTP-01 challenge listener — also serves the force-https
  # redirect for non-challenge paths.
  force_https:
    bind: "0.0.0.0:80"
    status: 308

tls:
  min_version: "1.2"
  hsts:
    max_age: 31536000
    include_subdomains: true
    preload: false

  # No `certificates:` block — the acme block below provides the
  # cert. (You CAN ship both for fallback; the manual cert is used
  # until ACME issuance succeeds.)

  acme:
    # ⚠️ Start on STAGING; flip to prod only after a clean round trip.
    directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
    contacts:        ["mailto:ops@example.com"]   # REPLACE
    domains:         ["staging-waf.example.com"]   # REPLACE
    account_key_path: "/var/lib/aegis/acme/account.json"
    cert_dir:         "/var/lib/aegis/certs"
    renew_before:     30d
    terms_of_service_agreed: true
    challenge: http01      # http01 | tls_alpn01 | dns01
```

#### B.5 — verify after boot

After §6 boots the WAF, watch the issuance:

```sh
journalctl -u aegis-gate -f | grep -i acme
# Expected sequence over ~30 s:
#   acme: registered account against https://acme-staging-v02.api.letsencrypt.org/directory
#   acme: order placed for domains=[staging-waf.example.com]
#   acme: HTTP-01 challenge published token=...
#   acme: challenge validated by directory
#   acme: cert issued and persisted to disk path=/var/lib/aegis/certs/staging-waf.example.com/
#   acme: cert hot-swapped into live store

ls -la /var/lib/aegis/certs/staging-waf.example.com/
# → cert.pem, key.pem (mode 0600)

# From another machine — confirm the served cert is LE-issued:
echo | openssl s_client -connect "$STAGING_HOST:8443" -servername "$STAGING_HOST" 2>/dev/null \
  | openssl x509 -noout -issuer -dates
# Expected (staging endpoint):
#   issuer=CN=(STAGING) Pretend Pear X1, O=(STAGING) Let's Encrypt, C=US
# Expected (prod endpoint):
#   issuer=CN=R3, O=Let's Encrypt, C=US     (or current LE intermediate)
```

#### B.6 — flip to prod LE

After Track B staging works end-to-end, in `config/staging.yaml`:

1. `directory_url:` → `https://acme-v02.api.letsencrypt.org/directory`
2. `account_key_path:` → a **different** file (e.g. `account-prod.json`) — staging and prod accounts are separate
3. Restart: `sudo systemctl restart aegis-gate` (graceful drain; in-flight requests finish)
4. Re-run the openssl verify in B.5 — issuer should now be the real LE intermediate

---

## 4 · Bring up the infra stack

```sh
cd /opt/aegis-gate
docker compose -f deploy/docker-compose.dev.yml up -d redis prometheus grafana redis-exporter

# Verify each container is up + healthy
docker compose -f deploy/docker-compose.dev.yml ps
```

**Expected**: `aegis-redis`, `aegis-prometheus`, `aegis-grafana`,
`aegis-redis-exporter` all show `Up` and (where applicable) `healthy`.

```sh
# Smoke each
curl -fsS http://127.0.0.1:6379                      # ← gets junk back, that's fine; it proves the port is open
curl -fsS http://127.0.0.1:9090/-/ready              # → 200 'Prometheus Server is Ready.'
curl -fsS http://127.0.0.1:3000/api/health | jq      # → {"database": "ok", ...}
curl -fsS http://127.0.0.1:9121/metrics | head -3    # → Prometheus exposition (redis_*)
```

**Note** — for staging you don't need `etcd` or `jaeger`. The compose
file declares them; they'll start with `up` (no `-d redis prom grafana
redis-exporter` filter) but consume RAM. Stick to the explicit service
list above.

### Mock upstream (optional — skip if you have a real backend)

```sh
docker compose -f deploy/docker-compose.dev.yml up -d httpbin
curl -fsS http://127.0.0.1:8081/get | jq .url        # → "http://127.0.0.1:8081/get"
```

---

## 5 · Configure the WAF for staging

Pick one — fork an existing profile, then tighten:

```sh
cp config/profiles/prod-balanced.yaml config/staging.yaml
```

Edit `config/staging.yaml`:

| Field | Staging value | Why |
|---|---|---|
| `state.backend` | `redis` | uses the Docker Redis above |
| `state.redis.urls` | `["redis://127.0.0.1:6379"]` | Docker forwarded the port to host |
| `tls.certificates[0].cert_path` | `/opt/aegis-gate/config/certs/dev.crt` (Track A only) | absolute path required; **Track B uses `tls.acme:` instead — see §3.B.4** |
| `tls.certificates[0].key_ref` | `/opt/aegis-gate/config/certs/dev.key` (Track A only) | same |
| `tls.acme` | populated **only on Track B** — block from §3.B.4 | leader-gated ACME issuance + renewal |
| `listeners.force_https` | `{ bind: "0.0.0.0:80", status: 308 }` **only on Track B + HTTP-01** | serves `/.well-known/acme-challenge/` |
| `admin.bind` | `127.0.0.1:9443` | dashboard not exposed to the internet |
| `admin.dashboard_auth.password_hash` | output of `./target/release/waf admin set-password` | fresh password, NOT the dev hash |
| `admin.dashboard_auth.csrf_secret_ref` | `${secret:env:AEGIS_CSRF_SECRET}` (32+ random bytes) | env-injected, not in YAML |
| `audit.sinks` | add `{kind: jsonl, path: /var/log/aegis/audit.ndjson}` | persistent audit log |
| `routes` + `upstreams` | edit to point at your real backend OR keep the stub for synthetic | benchmarks need a real-shape upstream |
| `ai.enabled` | `true` (if you want AI in the chain) or `false` | controlled separately |
| `runtime.workers` | `auto` on bare metal, or pin a fixed integer in cgroup-quota envs | see [`../docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md) |

```sh
# Generate a CSRF secret + admin password
export AEGIS_CSRF_SECRET=$(openssl rand -base64 32)

# Hash a password and paste the output into admin.dashboard_auth.password_hash
./target/release/waf admin set-password
# Type your password twice, copy the printed hash, paste into config/staging.yaml

# Validate the config — no listeners are bound, just a parse + clamp check
./target/release/waf validate --config config/staging.yaml
```

**Expected**: the `validate` command prints `config OK:
config/staging.yaml`. If it errors, the message names the file + field
+ line.

### Audit log directory

```sh
sudo mkdir -p /var/log/aegis
sudo chown $USER /var/log/aegis
```

---

## 6 · Boot the WAF

### Option A — foreground (development / debugging)

```sh
RUST_LOG=info AEGIS_CSRF_SECRET=$AEGIS_CSRF_SECRET \
  ./target/release/waf run --config config/staging.yaml
```

Expected boot log (last few lines):

```
INFO waf: state backend = redis @ redis://127.0.0.1:6379 (...)
INFO aegis_proxy::run: AI detector wired into the chain ...   ← only if cfg.ai.enabled
INFO data-plane listening on 0.0.0.0:8443 (tls=true)
INFO data-plane listening on 0.0.0.0:8080 (tls=false)
INFO admin-plane listening on 127.0.0.1:9443
```

**Ctrl-C** triggers a graceful drain — readiness flips to 503,
listeners close after `AEGIS_DRAIN_GRACE_MS` (default 5 s).

### Option B — systemd (long-lived staging service)

```sh
sudo tee /etc/systemd/system/aegis-gate.service > /dev/null <<'EOF'
[Unit]
Description=Aegis-Gate WAF (staging)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=notify
User=YOUR_USER
ExecStart=/opt/aegis-gate/target/release/waf run --config /opt/aegis-gate/config/staging.yaml
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
NotifyAccess=main
Environment=RUST_LOG=info
Environment=AEGIS_DRAIN_GRACE_MS=10000
EnvironmentFile=/etc/aegis-gate.env

[Install]
WantedBy=multi-user.target
EOF

# Replace YOUR_USER above
sudo sed -i "s/YOUR_USER/$USER/" /etc/systemd/system/aegis-gate.service

# Inject the CSRF secret + any other env via /etc/aegis-gate.env
sudo tee /etc/aegis-gate.env > /dev/null <<EOF
AEGIS_CSRF_SECRET=$AEGIS_CSRF_SECRET
EOF
sudo chmod 600 /etc/aegis-gate.env

sudo systemctl daemon-reload
sudo systemctl enable --now aegis-gate
sudo systemctl status aegis-gate --no-pager
```

**Expected**: `active (running)` in the status output. `journalctl -u
aegis-gate -f` tails the WAF logs.

---

## 7 · Smoke test

```sh
# Liveness + readiness
curl -fsS http://127.0.0.1:9443/healthz/live    # → 200 ok
curl -fsS http://127.0.0.1:9443/healthz/ready   # → 200 with state_backend_up: true

# Data plane responds
curl -i http://127.0.0.1:8080/                  # → 200 / 502 / forwarded response

# TLS handshake works
curl -ki https://127.0.0.1:8443/                # → 200 / forwarded (self-signed cert → -k)

# Prometheus scrape
curl -fsS http://127.0.0.1:9443/metrics | head -10   # → openmetrics format

# Audit chain growing
ls -la /var/log/aegis/audit.ndjson              # → file exists, non-empty after a few requests
```

### Drive a few attacks to confirm detectors fire

```sh
# SQLi — should 403
curl -i 'http://127.0.0.1:8080/?q=1%27%20OR%20%271%27%3D%271'   # → HTTP/1.1 403

# Path traversal — should 403
curl -i 'http://127.0.0.1:8080/files?p=../../../../etc/passwd'   # → HTTP/1.1 403

# Audit chain shows the hits
tail -3 /var/log/aegis/audit.ndjson | jq '{action, detectors: .fields.detectors, status: .fields.status}'
```

### Open the dashboard

`https://<staging-host>:9443/` (admin port; loopback-only by default —
SSH-tunnel `-L 9443:127.0.0.1:9443` from your laptop, or temporarily
flip `admin.bind` to `0.0.0.0:9443` with a tight `dashboard_auth.ip_allowlist`).

Login with `admin` + the password you set in step 5. The Overview page
should show real RPS, the Live Feed scrolls as you fire curl, and the
Detectors page reflects the active mask.

---

## 8 · Run the benchmark

The repo ships several harnesses under `tests/`:

| Harness | What it measures | Run |
|---|---|---|
| `tests/perf/ai-compare.sh` | AI on / off / chained — perf + detection per case | `bash tests/perf/ai-compare.sh` |
| `tests/hackathon/run.sh` | 15-min mixed-traffic round (legit + crawlers + attackers) | `bash tests/hackathon/run.sh` |
| `tests/hackathon/run-prod-balanced-5k.sh` | Sustained 5 k+ RPS on the prod-balanced profile | `bash tests/hackathon/run-prod-balanced-5k.sh` |
| `tests/load/baseline.js` | Plain k6 baseline | `k6 run tests/load/baseline.js` |

Pick one. For the **prod-balanced 5k harness**:

```sh
DURATION=5m \
WAF_CONFIG=/opt/aegis-gate/config/staging.yaml \
  bash tests/hackathon/run-prod-balanced-5k.sh
```

Outputs land under `tests/results/run-perf-5krps-prod-balanced-<UTC>/`:

- `RUN-SUMMARY.md` — headline numbers (throughput, p50/p95/p99, detection rate, OK %)
- `artifacts/k6-summary.json` — raw k6 output
- `artifacts/waf-stats-{before,after}.json` — `/api/stats` snapshots
- `artifacts/metrics-{before,after}.txt` — Prometheus snapshots
- `logs/waf.log`, `logs/k6.log`, `logs/upstream.log`

### Compare runs

Each run dir has a `RUN-SUMMARY.md`. Diff two runs with:

```sh
diff -u tests/results/run-A/RUN-SUMMARY.md tests/results/run-B/RUN-SUMMARY.md
```

Index of all current baselines: [`../tests/results/README.md`](../tests/results/README.md).

---

## 9 · Observability while benchmarking

While the benchmark is running, watch:

| Surface | URL | Useful for |
|---|---|---|
| Prometheus UI | `http://<host>:9090/` | ad-hoc PromQL — try `rate(waf_requests_total[1m])`, `histogram_quantile(0.99, sum(rate(waf_request_duration_ms_bucket[1m])) by (le))` |
| Grafana | `http://<host>:3000/` (`admin/admin`) | the three pre-loaded dashboards: **WAF Overview**, **Runtime**, **Redis** |
| WAF dashboard Live Feed | `https://<host>:9443/#/live` | per-request audit stream — verify the harness traffic shape |
| WAF dashboard Performance | `https://<host>:9443/#/performance` | per-stage and per-route p50/p95/p99 |
| Audit chain | `tail -f /var/log/aegis/audit.ndjson \| jq` | full per-request detail |

---

## 10 · Iterating on config without restarts

| Surface | Hot-swap path |
|---|---|
| Routes (add / edit / delete) | Routing & Upstreams page (audit-mutated `PUT /api/routes/{id}`) |
| Upstream pools | Same page |
| Detector mask | Detectors page (audit-mutated `PUT /api/detectors`) |
| AI detector on/off | Detectors page → AI row Enable/Disable (audit-mutated `PUT /api/ai/enabled`) |
| Tier thresholds | Detectors page → Edit tier |
| Custom rules | Rule Manager page |
| Access lists (blacklist / whitelist) | Access Lists page |
| Mode (enforce / log_only) | Settings page |

Anything else is YAML + restart. `systemctl restart aegis-gate`
triggers the same graceful drain as Ctrl-C; in-flight requests finish.

---

## 11 · Teardown

```sh
sudo systemctl stop aegis-gate          # if running under systemd
docker compose -f deploy/docker-compose.dev.yml down
# Optional — drop benchmark output + audit chain
rm -rf tests/results/run-*
sudo rm -f /var/log/aegis/audit.ndjson*
```

The Redis volume + Grafana volume persist across `down` / `up` cycles.
Add `-v` to the `down` command to drop them too.

---

## 12 · Common staging-specific gotchas

| Symptom | Likely cause | Fix |
|---|---|---|
| `redis connection refused` at boot | Compose stack wasn't up first | `docker compose -f deploy/docker-compose.dev.yml ps redis` should show healthy; if not, `up -d redis` |
| `ai.enabled = true but ai.model_path is unset` | model not symlinked in | `make ai-link MODEL=/abs/path/to/waf_model.onnx`, restart |
| `bind: 0.0.0.0:9443: address already in use` | port held by an earlier WAF process | `pkill -KILL -f "target/release/waf"` then restart |
| Browser shows cert warning | self-signed cert SAN doesn't include the staging hostname | regenerate with that hostname in `config/gen-cert.sh`, `make reset-cert`, restart |
| Dashboard "fetch failed" pill on every page | admin port not bound on the right interface | confirm `admin.bind` is reachable from where the browser is; SSH tunnel works without flipping the bind |
| Benchmark stalls at low RPS | upstream is the bottleneck, not the WAF | swap to the bundled httpbin OR use the Go fast-upstream from `tests/hackathon/upstream/` |
| Audit chain not growing | sink mis-configured | `journalctl -u aegis-gate \| grep audit` should show the sink wire-up at boot |
| Prometheus shows no data for the WAF | scrape target unreachable | check `deploy/prometheus/prometheus.yml` — `host.docker.internal` resolves on Mac; on Linux use `extra_hosts: ["host.docker.internal:host-gateway"]` (already set in the compose file) |
| **Track B**: `acme: terms_of_service_agreed must be true` at boot | TOS field unset | set `tls.acme.terms_of_service_agreed: true` in the config (it is your legal acknowledgement of the LE Subscriber Agreement) |
| **Track B**: `acme: challenge validation failed` (HTTP-01) | LE couldn't reach `:80` from the public internet | confirm `listeners.force_https.bind: "0.0.0.0:80"` is set, the OS firewall allows inbound 80 (`sudo ufw allow 80/tcp` on Ubuntu), and DNS for the `domains:` entry resolves to the bench host's public IP. Re-run the §3.B.1 reachability probe |
| **Track B**: `acme: challenge validation failed` (TLS-ALPN-01) | LE couldn't reach `:443` | same as above but for port 443. Confirm `listeners.data` includes a `tls: true` listener on `0.0.0.0:443` (not `:8443`) for the duration of issuance |
| **Track B**: `acme: rate limit exceeded` from LE | hit the 5 duplicates / 50 certs per registered domain per week limit on the prod endpoint | switch `directory_url` back to `acme-staging-v02` for further iteration; the 7-day window resets automatically. Don't re-flip to prod until the staging round trip is clean |
| **Track B**: `acme: account key mismatch` after switching staging↔prod | both endpoints reused the same `account_key_path` | use **separate** `account_key_path` files for staging vs prod (e.g. `account-staging.json` and `account-prod.json`) |
| **Track B**: cert issued but browser/curl still sees old self-signed | manual `tls.certificates[]` block still present and the boot precedence kept it | remove the manual `certificates:` block (or accept the fallback behaviour — it's used only until ACME succeeds, then the live cert store hot-swaps to the LE cert; check `journalctl ... \| grep "cert hot-swapped"`) |
| **Track B**: only one node in a cluster issues a cert | by design — issuance is gated on the `leader:acme` lease so multi-node deploys don't double-issue | confirm with `grep "leader lease acquired" journalctl` on the issuing node; followers replay the cert from `cert_dir` once it lands. For staging benchmark this is a single-node deploy so it's a non-issue |

---

## 13 · For an AI assistant driving this

Drop the user / assistant the following one-line briefing:

```
You are deploying Aegis-Gate to a Linux staging host. Follow
deploy/STAGING-BENCHMARK.md top to bottom. After each numbered
step, run the Verify command(s) and confirm the output matches
Expected before moving on. If a Verify fails, do NOT continue —
report the discrepancy with: (a) the exact command run,
(b) the expected output, (c) the actual output, and (d) the host
distro + arch (`uname -a`, `cat /etc/os-release`). Do not edit
config files in place — always make backups (`cp file file.bak`)
before sed/yq edits so the operator can roll back.
```

Each section above is self-contained: prereqs (§0), get the code (§1),
build (§2), cert (§3), infra (§4), config (§5), boot (§6), smoke (§7),
benchmark (§8), watch (§9), iterate (§10), teardown (§11),
troubleshooting (§12). Linear, no loops, no judgement calls. The
Verify / Expected pairs are the contract.

If you (the AI) need to make a decision the document doesn't cover —
distro-specific package name, an unfamiliar error — surface it to the
operator with the same shape as a failed Verify rather than guessing.

---

## Cross-references

- [`./GUIDE.md`](./GUIDE.md) — production deploy (multi-node + Helm + cluster).
- [`./README.md`](./README.md) — what's in `deploy/`.
- [`../QUICKSTART.md`](../QUICKSTART.md) — laptop dev path.
- [`../docs/FEATURES.md`](../docs/FEATURES.md) — feature playbook (verify each gate).
- [`../docs/security/security-engine.md`](../docs/security/security-engine.md) — request → decision walkthrough.
- [`../docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md) — Layer-1 worker sizing for the bench host.
- [`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) — when staging needs to grow to multi-node.
- [`../tests/results/README.md`](../tests/results/README.md) — current benchmark baselines to compare against.
- [`../config/README.md`](../config/README.md) — every YAML field referenced above.
