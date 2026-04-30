# Aegis-Gate Deployment Guide

Production deployment guide. Local dev is in
[`../QUICKSTART.md`](../QUICKSTART.md); the dev-infra catalogue is
in [`./README.md`](./README.md). This guide covers what changes
when you move from `cargo run` on a laptop to a multi-node
deployment behind a load balancer.

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

Multi-stage Dockerfile is the recommended packaging path. Until
the official `deploy/Dockerfile` lands (B6-T1, deferred), this
template is what we run against:

```dockerfile
# Build stage
FROM rust:1.82-slim AS builder
WORKDIR /src
COPY . .
RUN cargo build -p aegis-bin --release --features "redis affinity"

# Runtime stage — distroless nonroot
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/waf /usr/local/bin/waf
EXPOSE 8443 9443 9100
USER nonroot
ENTRYPOINT ["/usr/local/bin/waf"]
CMD ["run", "--config", "/etc/aegis/waf.yaml"]
```

Pin Rust + base-image versions to digests in CI.

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

---

## Cross-references

- [`../QUICKSTART.md`](../QUICKSTART.md) — local dev path.
- [`./README.md`](./README.md) — what's in this folder.
- [`../config/README.md`](../config/README.md) — full YAML reference.
- [`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) — Layer-2 cluster topology.
- [`../docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md) — Layer-1 worker sizing.
- [`../docs/operations/dr-backup.md`](../docs/operations/dr-backup.md) — snapshots, restore drills.
- [`../docs/operations/compliance.md`](../docs/operations/compliance.md) — what each profile actually changes.
