# Pre-prod Feature Test Plan — index

Chrome-MCP-driven UI/UX + feature test plan for the four features shipped
2026-06-01 → 2026-06-13, run against the **pre-prod 3-node cluster**.

- **Start with [`MASTER-TEST-PLAN.md`](./MASTER-TEST-PLAN.md)** — environment,
  routes, credentials, severity ladder, contract traceability, exit criteria.
- Each case under `cases/` is a self-contained playbook: read Given/When/Then,
  paste the **Paste-to-Claude** block into Claude Desktop (Chrome MCP drives
  the consoles + LB), tick the **Pass criteria**.
- Copy [`run-record-template.md`](./run-record-template.md) to
  `../reports/preprod-<UTC-date>-feature-run.md` to record a session.

## Environment (summary)

| Surface | URL |
|---|---|
| Data plane (LB → all 3 nodes) | `http://185.23.199.194:56208` |
| Admin console — node 1 / 2 / 3 | `:56243` / `:56244` / `:56245` |
| Creds | `admin` / `aegis-test-1234` |
| Upstreams (mock) | `10.20.0.72` — `/ws`→:9992, `/grpc`→:9993, catch-all `/`→:9991 (http+ws) |

## Cases

### Cluster Mode — `cases/cluster/`
| Case | Covers | Severity |
|---|---|---|
| CL-01 | 3-peer roster, distinct node identity, leaderless | High |
| CL-02 | Config-plane convergence across nodes | **Critical** |
| CL-03 | Config versions, rollback, 409 conflict | High |
| CL-04 | Shared blacklist enforced fleet-wide via LB | **Critical** |
| CL-05 | Shared rate-limit counters (not ×3) | High |
| CL-06 | Cross-node live events (fleet_events) | High |
| CL-07 | Merged fleet metrics + control-API parity | High |

### WebSocket (bug fix) — `cases/websocket/`
| Case | Covers | Severity |
|---|---|---|
| WS-01 | Plaintext upgrade regression (no 1006), `/ws` + catch-all | **Critical** |
| WS-02 | Handshake runs full pipeline (block before socket) | High |
| WS-03 | `ws_inspect` log_only frame block audit | High |
| WS-04 | `ws_inspect` enforce → 1008 (+ BUG-WS-2/3 known limits) | High / INFO |
| WS-05 | Live Feed "WS Proto" render + open/close events | Medium |
| WS-06 | Handshake response headers + audit correlation | High |

### mTLS (Zero Trust) — `cases/mtls/`
| Case | Covers | Severity |
|---|---|---|
| MT-01 | Zero Trust page mounts; both directions + cards | High |
| MT-02 | Downstream mode toggle (instant) + validation | High |
| MT-03 | Downstream enforcement (required/optional/SAN) | High |
| MT-04 | Upstream identity + per-pool upstream_mtls | High |
| MT-05 | Connections + failures telemetry (UI↔API) | Medium |
| MT-06 | Certs page (list/expiry/upload-download) | Medium |
| MT-07 | zero_trust config converges + nav badge cleanup | High |

### AI Copilot — `cases/copilot/`
| Case | Covers | Severity |
|---|---|---|
| CP-01 | Panel mount / feature-off state | High |
| CP-02 | Situational summary (grounded brief) | High |
| CP-03 | Ask (grounded Q&A) | Medium |
| CP-04 | Triage suggestions — never auto-applied | **Critical** |
| CP-05 | CostGuard budget / rate limit graceful | Medium |
| CP-06 | Egress redaction (no PII/secrets leak) | High |
| CP-07 | Cluster-aware summary consistency | Medium |
| CP-08 | Advisory-only negative test (no mutate/block) | **Critical** |

## Suggested run order

CL-* (establish a healthy, converging fleet) → WS-* → MT-* → CP-*.
Run CL-06's traffic drive before CP-02/03/04/07 so the copilot has signal.
