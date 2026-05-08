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

### 2.5 · Stage the v2.3 binary contract

The OC's benchmarker (`waf_interop_contract_v2.3 §8`) expects three
things in the working directory it runs from:

| Path | Required | What it is |
|---|---|---|
| `./waf` | yes | The binary it invokes via `./waf run` |
| `./waf.yaml` (or `./waf.toml`) | yes | Config the benchmarker drops in before boot |
| `./waf_audit.log` | created on first request | The minimal-schema audit JSONL the benchmarker reads |

`make stage` sets up the first two atomically:

```sh
cd /opt/aegis-gate
make stage
# → ./waf -> target/release/waf      (symlink, atomic on update)
# → ./waf.yaml                       (copied from config/profiles/prod-balanced.yaml
#                                     if not already present — edit before boot)
```

After staging, the OC's `./waf run` from `/opt/aegis-gate/` Just Works.
The audit log gets created automatically on the first request because
`interop.enabled: true` is the default + the sink uses `O_CREAT|O_APPEND`.
**Edit `./waf.yaml`** to point `routes`/`upstreams` at your real
backend before booting — the prod-balanced template ships with a
`127.0.0.1:9999` stub.

#### Drift handling — `FORCE=1` vs `KEEP=1`

Once `./waf.yaml` exists, `make stage` and `make bench-dev` do **not**
silently overwrite operator edits. Instead, when the source profile
(`config/profiles/prod-balanced.yaml` for `stage`, `config/dev.yaml`
for `bench-dev`) is **newer** than `./waf.yaml`, the target aborts
with an explicit choice:

```text
ERROR: config/profiles/prod-balanced.yaml is newer than ./waf.yaml — drift detected.

Stale waf.yaml has caused benchmark regressions
(Run-2 SEC-C001 / Run-3 NEW-1 / Run-4 SEC-C001). Pick one:

  make stage FORCE=1      # refresh waf.yaml from prod-balanced.yaml (with .bak)
  make stage KEEP=1       # acknowledge drift; keep your edits
```

| Flag | Behavior | When to use |
|---|---|---|
| `FORCE=1` | Backup the current `./waf.yaml` to `./waf.yaml.bak`, then copy fresh from the source profile. | Standard pre-submission step — the source profile usually has fixes you want. |
| `KEEP=1` | Boot with the stale `./waf.yaml`, but print the first 20 lines of `diff` so you see what you're keeping out. | Rare — you've intentionally edited `./waf.yaml` (e.g. operator-tuned thresholds) and don't want to lose those edits. |

**Submission workflow:** always run `make stage FORCE=1` (or `make
bench-dev FORCE=1` for the dev profile) before tarballing for the
judging panel. Without `FORCE`, you ship whatever local `./waf.yaml`
happens to be on disk — which is how AI FP regressions slipped past
QA Run-2 → Run-3 → Run-4.

#### Audit log files (two sinks, two consumers)

The WAF writes **two** audit logs in parallel. They serve different
consumers and have different schemas — this is intentional dual-sink
design.

| File | Schema | Consumer |
|------|--------|----------|
| `./waf_audit.log` (configurable: `cfg.interop.audit_path`) | v2.3 §6 contract — `request_id, ts_ms, ip, method, path, action, risk_score, mode, [rule_id, tier]` | Benchmark harness / OC |
| `cfg.audit.sinks[*].path` (default `./audit.jsonl`; dev `/tmp/aegis-dev-audit.jsonl`) | Rich `AuditEvent` — `client_ip, ts (ISO 8601), class, tenant_id, fields.{...}, ...` | SOC dashboard / SIEM / cold-tier shipper |

When validating contract compliance, parse `./waf_audit.log`. The
operator audit at `cfg.audit.sinks` is for human consumption and
intentionally a different schema (richer context: XFF-resolved
`client_ip`, decoded request fields, detector-mask state).

If you re-build with new features (e.g. add `ai` after the fact),
re-run `make stage` — the symlink follows the latest `target/release/waf`
without extra steps.

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
| `risk.strikes.block_at` | **`1000000`** (benchmark) — effectively disable the lifetime-strike permanent block | not a v2.3 contract feature; bumping prevents single-FP cascades from polluting the harness false-positive tally. Production stays at default 50. See §5.5. |

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

### 5.5 · Neutralize the lifetime-strike block for benchmark runs

The WAF ships a per-IP **lifetime strike counter** that permanently
blocks a source after `risk.strikes.block_at` detector hits (default
**50** in the prod profiles). It's a real defense for actual
deployments, but for the benchmark harness it's a foot-gun:

- The v2.3 contract (`Hackathon_Doc/EN_waf_interop_contract_v2.3.md`)
  does **not** mandate or describe this mechanism — it specifies the
  six decision classes (§3) and lists `block / challenge / rate_limit`
  as acceptable actions for auth abuse (§3.1), but never prescribes
  *what* triggers them.
- A single detector false-positive on a benign request adds a strike.
  Across one benchmark phase, 50 mis-classifications cascade into
  the IP being permanently blocked — every subsequent legit request
  from that IP then 403s with `rule_id: risk-strikes`, polluting the
  harness's false-positive tally with **derived** failures rather than
  detector failures.
- `POST /__waf_control/reset_state` zeroes strikes between phases (we
  wired `risk.reset_all()` into the callback chain), but it does
  nothing for FP cascades **within** a single phase.

Add this block to `config/staging.yaml` so the strike-block is
effectively unreachable during any single benchmark phase:

```yaml
risk:
  # … (keep your existing thresholds / weights / decay) …

  # v2.3 benchmark override — the lifetime-strike block is a
  # production defense, not a contract requirement. Bump the
  # threshold so a single detector FP can't cascade. Real prod
  # deploys (`config/profiles/prod-balanced.yaml`) keep the
  # default `block_at: 50` for actual DDoS defense.
  strikes:
    block_at: 1000000        # effectively unreachable per benchmark phase
```

Verify after running a few attack waves:

```sh
# Should always be 0 — strike-block never fires:
grep -c '"rule_id":"risk-strikes"' /var/log/aegis/waf_audit.log
# → 0

# And as a positive check, ensure detectors are still firing
# (i.e. you didn't accidentally turn the security pipeline off):
grep -c '"rule_id":"sqli"\|"rule_id":"xss"\|"rule_id":"path_traversal"' /var/log/aegis/waf_audit.log
# → > 0 after sending some SQLi / XSS / traversal probes
```

If `risk-strikes` appears even once, the bump didn't take — either the
config wasn't reloaded (re-run `./waf validate --config ./waf.yaml`
to confirm the loaded value), or the operator is editing the wrong
file (`config/profiles/prod-balanced.yaml` ≠ the staging config).

### 5.6 · Hand the benchmark team the control secret

The `X-Benchmark-Secret` value the OC's harness needs is resolved by
the WAF in this order — first hit wins:

1. `interop.control_secret` in your live YAML (literal **or**
   `${secret:env:NAME}` env-ref)
2. Fallback default: **`waf-hackathon-2026-ctrl`** (hardcoded
   constant in `crates/aegis-control/src/interop/mod.rs:33`,
   matches the v2.3 contract §2.2 example exactly)

Retrieve from your staging box, by path:

```sh
ssh waf.hk-aegis-gate.com   # or wherever staging is
cd /opt/aegis-gate

# Path 1 — config has a literal:
grep -E 'control_secret' ./waf.yaml
#   control_secret: "waf-hackathon-2026-ctrl"     ← that's the secret

# Path 2 — config uses an env reference:
grep -E 'control_secret' ./waf.yaml
#   control_secret: "${secret:env:AEGIS_BENCHMARK_SECRET}"
sudo systemctl show aegis-gate -p Environment | grep -o 'AEGIS_BENCHMARK_SECRET=[^ ]*'
# or:
sudo grep AEGIS_BENCHMARK_SECRET /etc/aegis-gate.env

# Path 3 — config has no control_secret line at all → default applies:
echo "X-Benchmark-Secret: waf-hackathon-2026-ctrl"
```

**Verify the value is live before handing over** (catches typos
+ "config wasn't reloaded" issues):

```sh
SECRET="<the value you retrieved>"
curl -ksi -H "X-Benchmark-Secret: $SECRET" \
  https://waf.hk-aegis-gate.com/__waf_control/capabilities | head -3

# Expected: HTTP/2 200 + JSON body with `ok: true`
# If 403: wrong secret or `interop.enabled: false`
```

### Recommended hygiene for actual benchmark runs

**Don't ship the hard-coded default to the OC.** Generate a fresh
secret at deploy time and pin it via env-ref so the secret never
lands in source control:

```sh
SECRET=$(openssl rand -base64 32 | tr -d '=+/' | head -c 40)
echo "AEGIS_BENCHMARK_SECRET=$SECRET" | sudo tee -a /etc/aegis-gate.env
sudo chmod 600 /etc/aegis-gate.env
sudo systemctl restart aegis-gate
echo "Hand to benchmark team: $SECRET"
```

In `./waf.yaml`:

```yaml
interop:
  enabled: true
  control_secret: "${secret:env:AEGIS_BENCHMARK_SECRET}"
```

Trade-off: rotation now requires a restart (env vars are read once
at boot). For a benchmark window that's fine; the alternative
(reading from a file the WAF watches) adds complexity without value
for a one-shot deploy.

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

## 7.5 · v2.3 interop contract conformance

The OC's benchmarker (`waf_interop_contract_v2.3`) exercises a small
control plane + response-header surface. Verify every requirement
**before** running the perf harness so contract failures surface
deterministically.

### Configure the interop control secret

The control plane is gated by `X-Benchmark-Secret`. Set the value in
`config/staging.yaml`:

```yaml
interop:
  enabled: true
  audit_path: /var/log/aegis/waf_audit.log    # § 6 — minimal JSONL log
  control_secret: "${secret:env:AEGIS_BENCHMARK_SECRET}"
```

```sh
export AEGIS_BENCHMARK_SECRET="$(openssl rand -base64 32 | tr -d '=+/' | head -c 40)"
echo "AEGIS_BENCHMARK_SECRET=$AEGIS_BENCHMARK_SECRET" | sudo tee -a /etc/aegis-gate.env
sudo systemctl restart aegis-gate
```

### Verify the four required control endpoints (§ 2.1)

```sh
SECRET="$AEGIS_BENCHMARK_SECRET"
HOST="https://staging-waf.example.com"        # use your staging URL

# 1. Capabilities — discover supported features + active modes
curl -ks -H "X-Benchmark-Secret: $SECRET" "$HOST/__waf_control/capabilities" | jq

# Expected: ok:true, features={access_control, rules_engine, rate_limit, risk_engine},
# active.default_mode:"enforce", active.overrides:{}

# 2. Reset — synchronous, atomic, audit log NOT touched
LINES_BEFORE=$(wc -l < /var/log/aegis/waf_audit.log)
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" "$HOST/__waf_control/reset_state" | jq
LINES_AFTER=$(wc -l < /var/log/aegis/waf_audit.log)
echo "audit lines:  before=$LINES_BEFORE  after=$LINES_AFTER"
# Expected: ok:true, action:"reset_state", audit_log_preserved:true,
#           lines_after >= lines_before (NEVER lower — append-only)

# 3. Set profile — toggle `rules_engine.sqli` to log_only
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["sqli"]}' \
  "$HOST/__waf_control/set_profile" | jq
# Expected: ok:true, applied={...}, active.overrides={"rules_engine.sqli":"log_only"}

# 4. Flush cache — no content cache today, returns supported:false
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" "$HOST/__waf_control/flush_cache" | jq
# Expected: ok:true, action:"flush_cache", supported:false (graceful no-op)

# 5. Auth gate — missing/wrong secret returns 403 Forbidden
curl -ksi "$HOST/__waf_control/capabilities" | head -1
# Expected: HTTP/2 403
curl -ksi -H "X-Benchmark-Secret: wrong" "$HOST/__waf_control/capabilities" | head -1
# Expected: HTTP/2 403
```

### Verify the six required response headers (§ 5.1)

Every proxied response must carry `X-WAF-Request-Id`, `X-WAF-Risk-Score`,
`X-WAF-Action`, `X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`. Send a
benign request and a SQLi attempt; count the headers.

```sh
echo "--- benign request ---"
curl -ksi "$HOST/" | grep -i '^x-waf-' | sort

echo "--- SQLi attempt ---"
curl -ksi "$HOST/?q=1%27%20OR%20%271%27%3D%271" | grep -i '^x-waf-' | sort
```

Expected: 6 `x-waf-*` lines on each response. Missing any of them fails
the v2.3 contract observability gate.

### Bonus: per-request WAF latency (`X-WAF-Overhead-Latency`)

Added 2026-05-08. Reports the per-request WAF processing time in
milliseconds with microsecond precision (e.g. `1.234`). Captured at
the listener's `service_fn` entry; covers detector chain + rule
engine + risk gate + upstream forward + the response stamper itself.

Not part of the v2.3 §5 mandatory list — an extra observability hint
for operators analyzing per-route WAF cost from a single curl probe.

```sh
curl -ksi "$HOST/" | grep -i '^x-waf-overhead-latency'
# x-waf-overhead-latency: 0.823
```

For a fleet-wide latency view, the dashboard's Performance page (or
`GET /api/analytics/latency`) reads from the same per-stage histograms
that drive this header.

### Verify the log_only enforcement skip (§ 5.3)

This is the trickiest contract requirement: when a policy is in
`log_only`, the WAF MUST detect + audit the violation but allow the
request to reach upstream. The headers say "block"; the body comes from
upstream.

```sh
# 1. Switch SQLi to log_only
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["sqli"]}' \
  "$HOST/__waf_control/set_profile" > /dev/null

# 2. Send a SQLi probe
curl -ksi "$HOST/?q=1%27%20OR%20%271%27%3D%271"
# Expected:
#   HTTP/2 200                            ← upstream response, NOT 403
#   x-waf-action: block                   ← intended action
#   x-waf-mode: log_only                  ← honest about mode
#   x-waf-rule-id: sqli                   ← which detector fired
#   ... + body from upstream

# 3. Confirm audit chain DID record it
tail -1 /var/log/aegis/waf_audit.log | jq '{action, rule_id, mode, ip, path}'
# Expected: action="block", rule_id="sqli", mode="log_only"

# 4. Restore enforce
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"all","mode":"enforce"}' \
  "$HOST/__waf_control/set_profile" > /dev/null
```

If step 2 returns `HTTP/2 403`, log_only is broken — the WAF is still
enforcing despite the toggle. Check that `interop.enabled: true` is in
the live config and that the WAF was restarted after setting the env
var.

### Verify the audit log shape (§ 6)

Eight required fields (`request_id`, `ts_ms`, `ip`, `method`, `path`,
`action`, `risk_score`, `mode`); IP must be the TCP peer (not XFF).

```sh
tail -1 /var/log/aegis/waf_audit.log | jq 'keys'
# Expected (sorted): ["action","ip","method","mode","path","request_id",
#                     "risk_score","rule_id","tier","ts_ms"]
# `rule_id` and `tier` are bonus fields per § 6 ("MAY add extra JSON fields").

# X-WAF-Request-Id matches audit request_id on the same request:
RID=$(curl -ksi "$HOST/" | grep -i '^x-waf-request-id:' | awk '{print $2}' | tr -d '\r')
grep "\"request_id\":\"$RID\"" /var/log/aegis/waf_audit.log | jq .
# Expected: exactly one row, fully populated.
```

### Verify the binary contract (§ 8)

```sh
# Default config lookup follows ./waf.yaml → ./waf.toml → config/prod.yaml
ls /opt/aegis-gate/waf.yaml 2>/dev/null && \
  echo "  ./waf.yaml present — `./waf run` will pick it up automatically"

# Default audit path
grep '"audit_path"' /opt/aegis-gate/config/staging.yaml || \
  echo "  audit_path not pinned — defaults to ./waf_audit.log per spec"

# Health endpoint must respond before startup timeout
time curl -ks -o /dev/null -w "boot probe: status=%{http_code} time=%{time_total}s\n" \
  "$HOST/healthz/live"
# Expected: status=200 within ~2s on a re-boot
```

### Pass / fail summary

```sh
# Quick automated check — runs all of the above and exits 0 only if
# every assertion holds. Useful to wire into a CI pipeline.
bash deploy/v23-conformance.sh "$HOST" "$SECRET"   # if you've vendored the helper
```

If any of the verifications above fails, **do not run the perf harness**
— the OC's benchmarker will reject the run on contract grounds before
ever measuring throughput. Fix conformance first; perf is downstream.

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
| **v2.3**: `/__waf_control/*` returns 404 | `interop.enabled: false` in config | flip to `true`, restart |
| **v2.3**: every control call returns 403 | `X-Benchmark-Secret` header value mismatches `interop.control_secret` | env var unset before boot? Check `journalctl -u aegis-gate \| grep "control plane"` — the boot log lists the secret source (env vs YAML literal vs default) |
| **v2.3**: control endpoints return 200 but headers are missing | response stamper not installed on the listener | confirm `interop.enabled: true` AND `interop.audit_path` is writable — the runtime won't come up if it can't open the audit sink, and the stamper is part of that runtime |
| **v2.3**: `set_profile` accepted but log_only requests still get 403 | proxy was running BEFORE the modes refactor landed | rebuild from the post-PR1+PR2+PR3 + v2.3 fix commit (`grep "log_only_intent" target/release/waf` should show the symbol; if missing, the binary predates the fix) |
| **v2.3**: `X-WAF-Mode: enforce` shown even after setting `log_only` | response stamper still hardcoded to `rules_engine` lookup | rebuild — the stamper at `admin_dispatch.rs` was patched to use `rule_map::mode_for_rule`. Confirm the binary's commit is post-2026-05-05 |
| **v2.3**: audit log truncated after `reset_state` | sink mis-wired or operator manually rotated mid-run | the spec REQUIRES append-only across resets. Check the file is opened with `OpenOptions::append(true)` (it is by default in `MinimalJsonlSink::open`) |
| **v2.3**: `X-WAF-Request-Id` doesn't match audit `request_id` | likely two parallel writers — the dashboard's hash-chain audit AND the interop minimal sink emit independently | the OC contract MUST match the **interop** sink's id (the one in `./waf_audit.log`). The hash-chain at `audit.sinks` is separate; both run in parallel |
| **v2.3 §8**: OC's `./waf run` exits with `command not found` | binary lives at `target/release/waf`, not `./waf` | `make stage` (creates the `./waf` symlink). Operators sometimes skip §2.5 and just run from `/opt/aegis-gate/` expecting cargo's path layout — the OC harness uses cwd-relative invocation |
| **v2.3 §8**: OC's startup probe times out | `./waf run` is reading from `config/prod.yaml` (legacy fallback) which doesn't bind on the OC's expected port | `make stage` drops `./waf.yaml` in cwd; the binary's lookup chain (`--config` → `./waf.yaml` → `./waf.toml` → `config/prod.yaml`) picks it up first. Edit ports in `./waf.yaml`, not `config/prod.yaml` |
| **v2.3 §8**: `./waf_audit.log` not created | `interop.enabled: false` somewhere in the YAML you booted | default is `true`; check the loaded config: `./waf validate --config ./waf.yaml \| grep interop`. If `enabled: false` appears, remove it (or set true). |
| Benchmark "false positive rate" looks artificially high; many late-phase legit requests show `rule_id: risk-strikes` | lifetime-strike permanent block tripped mid-phase from accumulated detector hits (real and FP) | bump `risk.strikes.block_at` per §5.5. The OC's `reset_state` between phases doesn't undo strikes that landed mid-phase. |
| Benchmark team reports every `/__waf_control/*` returns 403 with the secret you handed them | secret you retrieved doesn't match the value the running WAF actually loaded — common after a config edit without restart, or copy-pasted with trailing whitespace | re-run §5.6's verify-curl from the staging box itself; if that 403s, the WAF didn't pick up your change. `sudo systemctl restart aegis-gate` and re-verify. If it 200s but the remote curl 403s, copy-paste added whitespace — `echo -n "$SECRET" \| wc -c` should match the byte count you sent. |
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
