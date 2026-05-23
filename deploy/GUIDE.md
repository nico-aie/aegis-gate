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
| AI never fires with `remote_endpoint` set | Binary must be built with the `ai-remote` feature; boot logs `ai.remote_endpoint set but binary built WITHOUT the ai-remote feature` otherwise. Then check `aegis-infer` is up (`systemctl status aegis-infer`) and the socket/port matches. AI is also fail-open — a down server logs `remote ai inference error` at TRACE and forwards on the regex verdict. |

---

## 8. Remote AI inference (`aegis-infer`)

The AI/ML detector can run **in-process** (ONNX loaded into the WAF,
`--features ai`) or **offloaded** to the standalone `aegis-infer` gRPC
batch server (`--features ai-remote`). The serving server accumulates a
batch across concurrent requests and runs one `[N×27]` ONNX pass, so
inference throughput scales past the ~2k RPS ceiling of the serialised
in-process `Mutex<Session>`. Source + protocol:
[`../data/serving-server/`](../data/serving-server/) and its
[`INTEGRATION.md`](../data/serving-server/INTEGRATION.md).

The two are independent build features:

| Build | Behaviour |
|-------|-----------|
| `ai` only | In-process ONNX (status quo). |
| `ai-remote` only | All AI inference offloaded to `aegis-infer`. |
| `ai` + `ai-remote` | If `ai.remote_endpoint` is set, **remote wins**; in-process ONNX is the fallback used only if the remote connect fails at boot. |
| neither | No AI detector; the regex/signature chain still runs. |

```sh
# Build the WAF with remote-AI support (add to your usual feature set)
make build FEATURES="redis geoip alerts ai-remote affinity"
```

### Topology — co-located over a Unix socket (recommended)

```
┌──────────────────────── one node ───────────────────────┐
│  ┌───────────────┐    UDS (no TLS)    ┌───────────────┐  │
│  │  aegis-gate   │◄──────────────────►│  aegis-infer  │  │
│  │  (WAF, :8443) │  /run/aegis-infer/ │  (ONNX batch) │  │
│  └───────────────┘     infer.sock     └───────────────┘  │
└──────────────────────────────────────────────────────────┘
```

A UDS avoids TLS + a TCP hop (~0.2 ms lower latency than loopback TCP)
and keeps inference unreachable off-box. Use `tcp://` only when the
server runs on a different host.

### systemd unit for the serving server

```ini
# /etc/systemd/system/aegis-infer.service
[Unit]
Description=Aegis WAF AI Inference Server
After=network.target

[Service]
Type=simple
User=aegis
# RuntimeDirectory creates + chowns /run/aegis-infer (0750) on start
RuntimeDirectory=aegis-infer
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/aegis-infer \
    --model-path /etc/aegis/ai_model/waf_model.onnx \
    --workers 4 \
    --max-batch 256 \
    --delay-ms 2 \
    --bind-uds /run/aegis-infer/infer.sock \
    --log-level info
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Order it ahead of the WAF so the socket exists at WAF boot — though it
need not: the WAF **fail-soft** at boot (a missing server logs a warning
and falls back to in-process ONNX if `ai` was also built; otherwise AI
is simply absent) and **fail-open** per-request (a down/slow server →
no AI signal, the regex chain still serves). For a hard ordering add
`Wants=aegis-infer.service` + `After=aegis-infer.service` to the WAF unit.

### WAF config

```yaml
ai:
  enabled: true                 # seeds the dashboard AI toggle on
  confidence_threshold: 0.85    # reused for the remote verdict
  remote_endpoint: unix:///run/aegis-infer/infer.sock
  # tcp://127.0.0.1:50051       # alternative: same-host loopback
  # model_path: ...             # only used as the fallback (ai + ai-remote)
```

The dashboard **Detectors → AI** card and `PUT /api/ai/enabled` control
the remote detector exactly like the in-process one — the toggle is
seeded from `ai.enabled` and flips live without a restart.

### Tuning the serving server

| Workload | `--workers` | `--max-batch` | `--delay-ms` | Target RPS |
|----------|-------------|---------------|--------------|------------|
| < 1k RPS | 1 | 64 | 5 | ~1k |
| 1–5k | 2 | 128 | 2 | ~5k |
| 5–10k | 4 | 256 | 2 | ~10k |
| > 10k | 8 | 512 | 1 | 20k+ |

`--workers` = parallel ONNX sessions ≈ cores reserved for inference
(keep ≤ physical cores). Verify a batch is forming under load with
`aegis-infer`'s `Stats` RPC (`avg_batch_size` should be > 1).

### Verify

```sh
systemctl status aegis-infer            # server up, mode=onnx
ls -l /run/aegis-infer/infer.sock       # socket present, srw-r-----
# Boot the WAF; expect this line in the WAF log:
#   "remote AI detector connected (aegis-infer gRPC serving server)"
journalctl -u aegis-gate | grep -i "remote AI"
```

---

## Upgrade notes

Behavior changes a deployer should know about, newest first.

### 2026-05-23 — remote AI inference (`aegis-infer`)

- **New optional `ai-remote` build feature + `ai.remote_endpoint` config.**
  Offloads ML inference to the standalone `aegis-infer` gRPC batch server
  (see section 8). **Action for deployers:** none required — the feature
  is off unless you build with `ai-remote` AND set `ai.remote_endpoint`.
  Existing `ai` (in-process ONNX) deployments are unchanged. To adopt:
  build with `ai-remote`, deploy the `aegis-infer.service`, point
  `ai.remote_endpoint` at its socket. Remote AI is fail-soft at boot and
  fail-open per request, so a serving-server outage never takes the WAF
  down — it degrades to the regex/signature chain.

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
- [`../data/serving-server/INTEGRATION.md`](../data/serving-server/INTEGRATION.md) — remote AI (`aegis-infer`) integration + protocol (section 8).
