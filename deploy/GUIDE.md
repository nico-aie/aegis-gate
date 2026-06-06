# Aegis-Gate Deployment Guide

Production deployment guide. Local dev is in
[`../QUICKSTART.md`](../QUICKSTART.md); the dev-infra catalogue is
in [`./README.md`](./README.md). This guide covers what changes
when you move from `cargo run` on a laptop to a multi-node
deployment behind a load balancer.

> **Just need a single Linux box for benchmarking?** Use
> [`./STAGING-BENCHMARK.md`](./STAGING-BENCHMARK.md) instead — it
> runs infra (Redis + Prometheus + Grafana) under Docker on the
> same host while the WAF runs as a native binary, and is written
> as a mechanical step-by-step that an AI assistant can drive.
> This guide is for multi-node production with image / Helm /
> etcd hot-reload.

---

## Production checklist

Run through this before the first prod deploy.

- [ ] **Build** — release binary with the features you need:
      `cargo build -p aegis-bin --release --features "redis affinity"`.
- [ ] **TLS certificates** provisioned (ACME or manual). Point
      `tls.certificates[]` at the PEM paths.
- [ ] **Admin password** hashed with `waf admin set-password`;
      hash placed in `admin.password_hash` (or via secret ref).
- [ ] **TOTP enrolled** with `waf admin enroll-totp`. Recovery
      codes stored offline.
- [ ] **Compliance profiles** set if applicable
      (`compliance.modes: [pci, soc2, ...]`).
- [ ] **Audit sinks** configured — JSONL on disk **plus** at least
      one SIEM sink.
- [ ] **IP allowlist** set on the admin listener.
- [ ] **Redis** deployed with TLS + auth if `state.backend: redis`.
- [ ] **Prometheus** scraping both planes; SLO objectives wired
      to alert receivers.
- [ ] **Runtime sizing** picked deliberately — see
      [`../docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md).
      `workers: auto` is fine on bare metal; under k8s CPU quotas,
      pin a fixed integer.
- [ ] **Cluster identity** stable — set `node.id` to a
      durable per-pod name (e.g. `${POD_NAME}` from k8s downward
      API), not the hostname-pid fallback.
- [ ] **`waf validate --config <path>`** prints `config OK` for
      the *exact* file the prod binary will read.

---

## 1. Container image

The official multi-stage `deploy/Dockerfile` (B6-T1) lands the
production image — Rust 1.91-slim builder + distroless `cc`
runtime, signed-friendly, ~51 MiB compressed for arm64
(under the 100 MiB budget). Build with:

```sh
# Build for the host arch + load into the local Docker daemon
AEGIS_TAG=1.4.2 \
AEGIS_PLATFORMS="linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
    bash deploy/docker-build.sh

# Or: multi-arch (manifest in buildx cache; add AEGIS_PUSH=1 to push)
AEGIS_TAG=1.4.2 bash deploy/docker-build.sh
```

The image bakes in the `production` feature umbrella (redis,
alerts, geoip, taxii, http3, vault, aws, gcp, azure, consul,
etcd, k8s). Operators who want a slimmer image can fork the
Dockerfile and replace `--features production` with the subset
they actually use.

### Running

```sh
# Operator config + certs bind-mounted; admin must bind 0.0.0.0
# (see "Container networking caveat" below)
docker run --rm \
    -p 8080:8080 -p 8443:8443 -p 9443:9443 \
    -v /etc/aegis:/etc/aegis:ro \
    -v /var/lib/aegis:/var/lib/aegis \
    aegis-gate:1.4.2

# One-shot subcommands (no listener)
docker run --rm aegis-gate:1.4.2 version
docker run --rm -v /etc/aegis:/etc/aegis:ro \
    aegis-gate:1.4.2 validate --config /etc/aegis/waf.yaml
```

### Container networking caveat

The shipped `config/dev.yaml` and `config/prod.yaml` bind
`admin.bind: "127.0.0.1:9443"` — that's the **container's**
loopback inside Docker, not the host's. Two fixes:

1. **Recommended** — fork your config and bind admin to the
   container's external interface, leave the IP allowlist
   tight:

   ```yaml
   admin:
     bind: "0.0.0.0:9443"
     dashboard_auth:
       ip_allowlist:
         - "10.0.0.0/8"
         - "172.16.0.0/12"
   ```

2. **Quick** — `docker run --network host` so the container
   shares the host's networking stack. Not portable to k8s, but
   fine for single-node Linux deployments.

### Image-size budget

`tests/api/dockerfile.sh` builds the image and asserts size ≤
100 MiB. Run after every Dockerfile / Cargo.toml feature change:

```sh
bash tests/api/dockerfile.sh
```

Pin Rust + base-image versions to digests in CI (the Dockerfile's
`ARG RUST_VERSION` defaults to `1.91`; bump in lockstep with
Cargo.toml's `rust-version`).

---

## 2. Single-node systemd

```ini
[Unit]
Description=Aegis-Gate WAF
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/waf run --config /etc/aegis/waf.yaml
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
NotifyAccess=main
Environment=AEGIS_DRAIN_GRACE_MS=10000

[Install]
WantedBy=multi-user.target
```

`SIGTERM` triggers the graceful drain (HA-T5): readiness flips
to 503, external LBs notice within their probe interval, then
the listeners abort after `AEGIS_DRAIN_GRACE_MS`.

---

## 3. Multi-node cluster behind a load balancer

This is the production topology — one VIP, N WAF nodes, Redis
for shared state, an LB doing health-checked round-robin (or
leastconn for keep-alive workloads).

Topology + LB recipes (HAProxy / Nginx / k8s Ingress):
[`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md).

The reference HAProxy config lives at
[`./haproxy/haproxy.cfg`](./haproxy/haproxy.cfg). Copy it as a
starting point — production setups want PROXY-protocol, stricter
timeouts, and (probably) frontend-side rate limiting of their own.

Operationally:

1. Each node runs the same binary against a per-node config (or
   the same etcd path with `node.id` overridden via env).
2. Health probes hit the **admin** port (`/healthz/ready`),
   while traffic flows to the **data** port. HAProxy expresses
   this via `port 9443` on each `server` line.
3. Drain pattern (per node):
   ```sh
   curl -X POST http://<node>:9443/admin/drain   # readiness flips to 503
   sleep 5                                        # LB notices via probe
   systemctl stop aegis-gate                      # SIGTERM, grace, abort
   ```

### Config plane (console edits propagate fleet-wide)

With `state.backend: redis`, a console edit on **any** node (detector mask,
tier thresholds, rule CRUD, upstream pools, AI on/off, response-filter rungs)
is written to a shared, versioned config document and converges on every node
within one watcher poll (~3 s), surviving restart + leader failover. Each
node's applied version is visible at `GET /api/config` (drift view).

Operationally this means: **don't hand-edit each node's `waf.yaml` and reload
in lockstep** — make the edit once through the dashboard / admin API and let
the plane converge. Bulk/GitOps changes go through `PUT /api/config` (full-doc,
optimistic-concurrency); `POST /api/config/rollback` reverts to an earlier
version. New config this introduced: durable `rules.inline[]` and the now-live
`detectors.per_tier`.

Full mechanical, AI-drivable deploy + operate steps:
[`./CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md). Design + key/endpoint
reference: [`../docs/operations/cluster-config-distribution.md`](../docs/operations/cluster-config-distribution.md).

Also `redis`-only: **cluster-wide metrics** — `/api/analytics/route-activity`
and `/api/{blacklist,whitelist}/hits` return a fleet-wide sum instead of one
node's slice (automatic; no config knob).

---

## 4. Health monitoring

| Endpoint | Purpose | Expected |
|---|---|---|
| `GET /healthz/live` | Liveness probe | `200 OK` (only 503 when draining) |
| `GET /healthz/ready` | LB health check | `200 OK` when ready and not draining |
| `GET /healthz/ready?strict=1` | Active/standby — only the cluster leader returns 200 | 503 on followers |
| `GET /healthz/startup` | k8s startup probe | `200 OK` after first config load |
| `GET /metrics` | Prometheus metrics (data-plane port) | Prometheus text format |
| `GET /api/cluster` | Peers + leader info | JSON with `peers[]`, `is_leader`, `our_node` |
| `GET /api/runtime` | Runtime sizing snapshot | JSON with effective worker count |

### Metrics (Prometheus) vs traces (OTLP → SigNoz)

Two separate paths:

- **Metrics** — scraped from `GET /metrics` by Prometheus (+ Grafana
  dashboards). Local stack: `make obs-up` (Prometheus + Grafana).
- **Traces** — exported over **OTLP gRPC** to **SigNoz** (the chosen
  trace backend) when the binary is built with `--features otel`:

  ```bash
  cargo build -p aegis-bin --features "redis geoip alerts ai affinity otel"
  ```
  ```yaml
  observability:
    otel:
      endpoint: "http://<signoz-host>:4317"   # SigNoz collector OTLP gRPC
      sample_ratio: 0.1                         # 10% in prod; 1.0 in dev
      # headers: { "signoz-access-token": "${secret:signoz_token}" }  # SigNoz Cloud
  ```

  Bring SigNoz up locally with `make signoz-up` (clone SigNoz first —
  see [`signoz/README.md`](./signoz/README.md)); UI at `:3301`. For
  production, put an OTel Collector between the WAF and SigNoz to redact
  PII + fan out — config in [`otel/collector.yaml`](./otel/collector.yaml).

**All three signals in SigNoz (via the Collector).** Run
`otel/collector.yaml` and point the WAF's `otel.endpoint` at the
Collector (`:4317`):

- **Metrics** — the Collector scrapes the WAF's existing `/metrics`
  (admin `:9443`) and forwards as OTLP. No app change; Prometheus stays
  available too.
- **Logs** — the Collector tails the WAF's JSON log via `filelog`.
  Redirect stdout to a file it can read:
  `./waf run --config … >> /var/log/aegis/waf.json 2>&1`.

The Collector redacts log/span attributes before egress; keep secrets
out of log *fields* (the WAF's `dlp` handles body-level redaction).

  **Migration note (2026-06):** SigNoz supersedes the older Jaeger
  trace path. `make obs-up` no longer starts Jaeger (it's metrics-only
  now); the dev-compose Jaeger service remains for anyone who still
  wants it, but the Grafana "Jaeger" datasource is legacy. OTLP metrics
  + logs export to SigNoz are the next phases (still Prometheus-scrape
  today) — see `plans/archive/observability-otel-and-alerts.md`.

---

## 5. Log rotation

Audit logs are NDJSON. Use logrotate or a sidecar shipper:

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

Compliance profiles override the rotation window: `pci` requires
≥ 90 days, `hipaa` requires ≥ 6 years (provision your sink
accordingly — the WAF doesn't enforce sink-side retention).

---

## 6. Compliance profiles

Set `compliance.modes` to layer policy bundles on top of the
config. Validation runs at startup; conflicts (e.g. weak cipher
under `fips`) fail fast with a precise error.

| Profile | Effect |
|---------|--------|
| `fips` | Force aws-lc-rs TLS provider; reject RC4/DES/3DES/MD5; TLS ≥ 1.2 |
| `pci` | TLS ≥ 1.2; PAN masking in DLP; audit retention ≥ 90 days |
| `soc2` | Require audit hash chain + admin trail + SLO alerts |
| `gdpr` | PII pseudonymization; data residency pin required |
| `hipaa` | PHI-safe log mode (PHI fields masked before sink write) |

---

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| Config validation fails | `waf validate --config <path>` — exact line + field reported |
| Compliance conflict at boot | A `min_tls_version` / cipher / retention setting violates a profile in `compliance.modes` |
| Audit chain tampered | `waf audit verify --from <path>` — reports the broken line |
| Admin login locked out | Wait for the lockout TTL (default 15 min) or restart to clear in-memory state |
| TOTP rejected | Check NTP — TOTP allows ±1 step (30 s) |
| Health probe failing | `/healthz/ready` requires config loaded + state backend up + ≥ 1 healthy upstream + not draining |
| LB sees node down right after drain | That's the expected path. Drain flips readiness, LB pulls within `inter × fall`, then `systemctl stop` aborts after grace. See `docs/operations/ha-clustering.md`. |

---

## Upgrade notes

Behavior changes a deployer should know about, newest first.

### 2026-05-27 — config plane: console edits propagate fleet-wide

- **Console toggles + CRUD now route through a shared, versioned config
  document** (`config:waf:doc` in the `StateBackend`). On `state.backend:
  redis` an edit on any node converges on every node (~3 s) and survives
  restart/failover; the folded surfaces are detectors (base **+ per-tier**),
  tiers, rules, upstreams, AI on/off, and response-filter rungs. **Action for
  deployers:** stop hand-editing per-node `waf.yaml` + reloading in lockstep —
  edit once via the dashboard/admin API. Bulk changes go through
  `PUT /api/config`; revert via `POST /api/config/rollback`. See
  [`./CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md).
- **New config: `rules.inline[]`** — operator rules are now persistent +
  cluster-propagated (were ephemeral + node-local; lost on restart). `rules.paths`
  is unchanged (backup tooling only, not loaded into the live engine).
- **`detectors.per_tier` is now consumed** (was schema-only). The config
  document is the source of truth — a live per-tier override absent from
  `detectors.per_tier` is cleared on reload. **Action for deployers:** if you
  relied on per-tier overrides set only via the old node-local PUT (not in any
  config), re-assert them through the dashboard so they land in the doc.
- **Bugfix:** file/etcd config reloads now also re-derive the `Ai` detector-mask
  bit from `cfg.ai.enabled` (it was previously cleared on every reload).
- **Cluster-wide metrics (redis only):** `/api/analytics/route-activity` and
  `/api/{blacklist,whitelist}/hits` now return a fleet-wide sum instead of the
  serving node's slice. Automatic when `backend != in_memory`; no config knob.
  `in_memory` single-node still reads the local rings.

### 2026-05-23 — AI inference scaling (session pool + batching)

- **New `ai.sessions` (synchronous session pool) + `ai.batch_enabled`
  (dynamic batching).** `sessions: N` runs N parallel ONNX sessions for
  ~N× throughput on a fast model with low-tail latency — the recommended
  scaling lever. `batch_enabled` is for the inference-bound case
  (slow/large model). **Action for deployers:** none — both default off
  (`sessions: 1`, single in-process detector, unchanged behavior).

### 2026-05-21 — tier thresholds + detector logging

- **Default tier `risk_threshold` lowered: medium 80 → 70, low 90 → 70**
  (critical 50 / high 70 unchanged). A single clear exploit (sqli, xss,
  path_traversal, cmdi, ssti, nosql, header-CRLF = score 70) now blocks
  on **every** tier, not just critical+high. Previously a textbook SQLi
  on a low/medium-tier path (`/`, `/static`, …) was forwarded to
  upstream (200) — a false negative. **Action for deployers:** if you
  pinned custom per-tier `risk_threshold` values in `cfg.tiers.*` or via
  the dashboard, re-check them — anything above 70 on medium/low will
  let single clear exploits through. Weaker signals (recon, oversize,
  AI-fallback 60, …) still accumulate, so this should not increase
  false positives on benign traffic. Live-tunable via the dashboard
  **Detectors → Edit tier** modal or `PUT /api/tiers/{name}`.
- **Audit `rule_id` now matches `X-WAF-Rule-Id`** for detector-driven
  decisions. Blocks already stamped the detector tags on the
  `X-WAF-Rule-Id` header but logged `rule_id: null`; the audit now
  carries the same tags. An under-threshold detection that is forwarded
  as `allow` is likewise labelled with the fired detectors in both the
  header and the audit `rule_id` (action stays `allow`), so a detection
  is never silent in the log. **Action for deployers:** none required;
  if you parse the audit JSONL, `rule_id` is now populated on more rows
  (detector blocks + detected-but-allowed) — it was `null` before.

## Cross-references

- [`../QUICKSTART.md`](../QUICKSTART.md) — local dev path.
- [`./README.md`](./README.md) — what's in this folder.
- [`../config/README.md`](../config/README.md) — full YAML reference.
- [`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) — Layer-2 cluster topology.
- [`../docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md) — Layer-1 worker sizing.
- [`../docs/operations/dr-backup.md`](../docs/operations/dr-backup.md) — snapshots, restore drills.
- [`../docs/operations/compliance.md`](../docs/operations/compliance.md) — what each profile actually changes.
