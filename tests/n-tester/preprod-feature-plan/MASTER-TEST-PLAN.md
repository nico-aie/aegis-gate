# Pre-prod Feature Test Plan — Cluster · WebSocket · mTLS · AI Copilot

**Target release:** features shipped 2026-06-01 → 2026-06-13 ·
**Environment:** pre-prod, **cluster mode, 3 WAF nodes** behind one LB ·
**Surface under test:** admin dashboard (UI/UX) + data-plane contract conformance ·
**Driver:** Claude Desktop + the **Chrome MCP** extension (manual playbooks) ·
**Author:** n-tester

---

> **Errata (2026-06-13 run).** Live endpoints differ from early drafts: mTLS
> telemetry lives under **`/api/zero-trust/{upstream,downstream}/*`** (e.g.
> `/upstream/failures`, `/downstream/ca-bundle/capability`) — **`/api/mtls/*`
> returns 404**. Copilot exposed **`/api/copilot/summary` + `/suggestions`
> only** on the deployed `v0.1.0` build; `/api/copilot/ask` 404'd there but **is
> wired on `develop`** (since 2026-06-02) — the 404 was a stale-deploy artifact,
> re-test after the cluster is rebuilt. The data plane is **HTTPS-only on
> :56208** (accept the self-signed cert once). Untrusted `X-Forwarded-For` is
> ignored (§10), so per-IP tests can't be driven by XFF spoofing. See
> `reports/preprod-2026-06-13-feature-run.md`.

## 1. Why this plan exists

Four features landed for this release and need a focused UI/UX + functional
pass on a real **3-node cluster** (not the dev 2-node fixture the older
`nt-*` suite uses):

| # | Feature | What shipped | Plan of record |
|---|---|---|---|
| 1 | **Cluster Mode** | Leaderless multi-node: shared state (rate-limit / block-list / risk / control-mode), config-plane convergence + versions/rollback, cross-node live events (`fleet_events`) + merged metrics (`fleet_view`). | `plans/archive/cluster-mode-multinode-sync.md`, `plans/archive/multi-node-consistency-implementation.md` |
| 2 | **WebSocket (bug fix)** | `.with_upgrades()` enabled on the plaintext `:8080` listener (commit `6aed24c`) so WS upgrades no longer 1006-drop; two-phase inspection (handshake always + `ws_inspect` frames); Live Feed "WS Proto" render fix (`d359e5b`). | `plans/archive/websocket-message-inspection.md`, `docs/security/websocket.md` |
| 3 | **mTLS** | Unified `zero_trust` module — downstream client-cert verify **and** upstream WAF-dials-backend mTLS; single "Zero Trust" (Beta) console page with instant mode toggle (`b94f93e`). | `plans/archive/zero-trust-unified-mtls.md`, `docs/security/zero-trust-mtls.md` |
| 4 | **AI Copilot** | LLM operator copilot (`--features llm`): situational summary + smart-catch triage suggestions; advisory-only; CostGuard budget; mandatory egress redaction. | `plans/archive/ai-operator-copilot.md`, `docs/control-plane/ai-operator-copilot.md` |

Each feature is verified against the interop contract where it touches
the contract surface — response headers (`Hackathon_Doc/EN_waf_interop_contract_v2.5.md` §5),
control API (§2), decision normalization (§7) — see the traceability
matrix in §6.

This plan is **UI/UX-first**: every page mounts cleanly, every control
does what it says, every config change persists and converges across the
fleet, and the data-plane behaviour the UI reports matches reality.

---

## 2. Environment under test

All three nodes share one Redis primary and sit behind a single L4/L7 LB.

| Role | URL | Notes |
|---|---|---|
| **Data plane (LB → all nodes)** | `http://185.23.199.194:56208` | Single entry point; LB fans out across node-1/2/3. All traffic-driving + contract-header checks go here. |
| **Admin console — node 1** | `http://185.23.199.194:56243/` | Per-node admin UI + API. |
| **Admin console — node 2** | `http://185.23.199.194:56244/` | Per-node admin UI + API. |
| **Admin console — node 3** | `http://185.23.199.194:56245/` | Per-node admin UI + API. |

**Credentials (every console):** user `admin` / password `aegis-test-1234`.

### Routes / upstreams in pre-prod

Three routes forward to mock upstreams on **10.20.0.72**. The **catch-all
route supports both HTTP and WebSocket** — so WS can be exercised on `/ws`
*and* on the catch-all `/`.

| Prio | Match | Scheme | Forwards to | Pool |
|---|---|---|---|---|
| #1 | `* · /ws` (PREFIX) | ws | `10.20.0.72:9992` | `ws-pool` (auto, 1 member) |
| #2 | `* · /grpc` (PREFIX) | grpc | `10.20.0.72:9993` | `grpc-pool` |
| #3 | `* · /` (PREFIX, **CATCH-ALL / FALLBACK**) | http **+ ws** | `10.20.0.72:9991` | `http-pool` (auto, 1 member) |

WS cases drive `/ws` (dedicated ws-pool) primarily; for the plaintext
upgrade regression (WS-01) also confirm WS works on the catch-all `/`
(it forwards to `http-pool`, which bridges WS too).

> The admin consoles are **per-node** — that is the whole point of the
> cluster tests. A config change made on node-1's console must be observed
> on node-2's and node-3's consoles (convergence), and traffic driven
> through the LB must be governed by shared state regardless of which node
> the LB happened to route it to.

### Auth / CSRF mechanics

After `POST /admin/login` each console sets an `aegis_session` + `aegis_csrf`
cookie pair. Mutations (PUT/POST/DELETE) need `X-CSRF-Token: <csrf-cookie-value>`
**and** the cookie sent (double-submit). When the Chrome MCP drives the
form login, cookies attach automatically and in-page `fetch(..., {credentials:"include"})`
carries them — read the csrf cookie in-page with
`document.cookie.match(/aegis_csrf=([^;]+)/)[1]` when a mutation needs the header.

---

## 3. How to run (Chrome MCP, manual)

This plan uses **Claude Desktop driving Chrome via the MCP extension** —
no sandbox network access to the pre-prod host is assumed. Each case doc
under `cases/` is self-contained and follows the house playbook shape:

1. **Given / When / Then** — read first; states what's being verified.
2. **Paste-to-Claude** — copy the fenced block verbatim into chat;
   Claude operates Chrome (navigate, click, type, screenshot) and, where
   the case checks contract headers, runs in-page `fetch()` from a
   data-plane tab against the LB and reports the `X-WAF-*` headers back.
3. **Pass criteria** — tick the checklist; any unticked Critical/High
   blocks the release.

### One-time setup

1. **Chrome MCP active** — in Claude Desktop run `/mcp`; confirm a
   Chrome server exposing `navigate` / `left_click` / `type` /
   `screenshot` / `javascript` tools.
2. **Three tabs for the consoles** — log each into its node:
   - Tab N1 → `http://185.23.199.194:56243/` (admin / aegis-test-1234)
   - Tab N2 → `http://185.23.199.194:56244/`
   - Tab N3 → `http://185.23.199.194:56245/`
3. **One data-plane tab** — open `http://185.23.199.194:56208/__qa-anchor`
   so in-page `fetch()` runs from the LB's origin (lets you set
   `X-Forwarded-For` and read `X-WAF-*` response headers without a CORS
   preflight).

### Run order

Cluster (`CL-*`) first — it establishes that the fleet is healthy and
converging, which every later case depends on. Then WebSocket (`WS-*`),
mTLS (`MT-*`), Copilot (`CP-*`). Within a feature, run in numeric order.

### Recording a run

Copy `run-record-template.md` to `reports/preprod-<UTC-date>-feature-run.md`
and fill the matrix as you go. `reports/` is gitignored — the run note is
an artifact, attach it to the tracker.

---

## 4. Severity ladder

Use these strings exactly (matches the `aegis-waf-tester` skill):

- **CRITICAL** — security regression, data loss, primary surface fully
  broken (a console page won't mount, blacklist not enforced fleet-wide,
  a copilot action mutates config). Stop and escalate.
- **HIGH** — a feature's primary path is broken (config doesn't converge,
  WS won't upgrade, mTLS required-mode admits a certless client).
- **MEDIUM** — secondary degradation or real UX friction (toast missing,
  metrics lag > window, a known limitation surfaced badly).
- **LOW** — polish, copy, alignment.
- **INFO** — passing observation / documented limitation (e.g. BUG-WS-2,
  BUG-WS-3 below). File these too — they prove the case ran.

### Known, accepted limitations — do NOT file as CRITICAL/HIGH

| ID | Limitation | Expected handling |
|---|---|---|
| **BUG-WS-2** | AI detector over-blocks ~100% of WS text frames in `enforce` (ONNX model OOD on per-frame synthetic views; `tag="ai"`). | Workaround = `ws_inspect.mode: log_only` or AI off. File **INFO**, confirm workaround works. |
| **BUG-WS-3** | Plaintext WS bridge sends a bare TCP close instead of the `1008` close frame on a frame block (TLS delivers `1008` cleanly). | File **INFO** on plaintext; verify `1008` on the TLS path if a TLS data port is exposed. |
| **F14** | `audit/since` latency carry-over pending live telemetry. | **INFO/MEDIUM** at most. |
| Copilot off | If a node isn't built with `--features llm` / no provider key, the Copilot panel shows a disabled/feature-off state. | That's **correct** — file INFO, not a bug. A *crash* instead of a clean disabled state IS a finding. |

---

## 5. Cross-cutting contract checks (apply to every traffic-driving case)

Whenever a case drives traffic through the LB, also confirm the response
carries the §5.1 required headers and they're internally consistent
(contract §5.3):

- `X-WAF-Request-Id` present, 8–64 chars `[A-Za-z0-9._-]`, and **equal to**
  the matching audit row's `request_id`.
- `X-WAF-Action` ∈ {`allow`,`block`,`challenge`,`rate_limit`,`timeout`,`circuit_breaker`}, lowercase.
- `X-WAF-Mode` ∈ {`enforce`,`log_only`} and reflects the policy that produced the action.
- `X-WAF-Rule-Id` set (or `none`); detector-class hits are prefixed `detector:`, access-list hits `blacklist`/`blacklist:<id>`.
- `X-WAF-Risk-Score` integer 0–100, reflects post-evaluation score.
- `X-WAF-Cache` ∈ {`HIT`,`MISS`,`BYPASS`}; `BYPASS` on dynamic/sensitive/high-risk routes.

A missing/malformed/inconsistent header on any probe is at least a
MEDIUM finding (HIGH if `X-WAF-Request-Id` is missing — it breaks
organizer correlation).

---

## 6. Traceability matrix (case → feature → contract)

| Case | Feature | Surface | Contract ref |
|---|---|---|---|
| CL-01 | Cluster | 3-peer roster, per-node identity | — (UI) |
| CL-02 | Cluster | config-plane convergence across nodes | §2.5 mode control |
| CL-03 | Cluster | config versions + rollback + 409 conflict | §2.6b rule schema |
| CL-04 | Cluster | shared blacklist enforced fleet-wide via LB | §5.1, §7 (`block`/`blacklist`) |
| CL-05 | Cluster | shared rate-limit counters via LB | §3.1, §5.1 (`rate_limit`) |
| CL-06 | Cluster | cross-node live events (`fleet_events`) | §6 audit fields |
| CL-07 | Cluster | merged fleet metrics + control-API parity | §2.1–2.4 control endpoints |
| WS-01 | WebSocket | plaintext upgrade regression (`6aed24c`) | §4 detection-via-response |
| WS-02 | WebSocket | handshake runs full pipeline (block before socket) | §5.1, §7 |
| WS-03 | WebSocket | `ws_inspect` log_only frame block audit | §2.5 log_only semantics, §6 |
| WS-04 | WebSocket | `ws_inspect` enforce → `1008` (+ BUG-WS-3) | §6 |
| WS-05 | WebSocket | Live Feed WS Proto render + open/close events | §6 audit fields |
| WS-06 | WebSocket | handshake response headers + audit correlation | §5.1, §5.3 |
| MT-01 | mTLS | Zero Trust page mounts; CA/conn/failure cards | — (UI) |
| MT-02 | mTLS | downstream mode toggle (instant) + validation | — (UI/config) |
| MT-03 | mTLS | downstream enforcement (required/optional/SAN) | §10 source-IP / identity |
| MT-04 | mTLS | upstream identity + per-pool `upstream_mtls` | — (config) |
| MT-05 | mTLS | connections + failures telemetry UI↔API | — (UI) |
| MT-06 | mTLS | certs page list / expiry / upload-download | — (UI) |
| MT-07 | mTLS | zero_trust config converges across fleet | §2.5 |
| CP-01 | Copilot | panel mount / feature-off state | — (UI) |
| CP-02 | Copilot | situational summary brief | — (advisory) |
| CP-03 | Copilot | ask (grounded Q&A) | — (advisory) |
| CP-04 | Copilot | triage suggestions, never auto-applied | §2.6b rule schema (simulate) |
| CP-05 | Copilot | CostGuard budget / rate limit graceful | — |
| CP-06 | Copilot | egress redaction (no PII/secrets leave) | §11 disclosure boundary |
| CP-07 | Copilot | cluster-aware summary consistent across nodes | — |
| CP-08 | Copilot | advisory-only negative test (no mutate/block) | — |

---

## 7. Exit criteria

- All **CRITICAL** and **HIGH** cases pass (or each open one has a filed,
  triaged finding with an owner).
- Every console page touched by these features **mounts cleanly** on all
  three nodes (no error-boundary card, no red console errors at idle).
- Contract §5 required headers present + consistent on every traffic probe.
- The four known limitations in §4 are confirmed as *still the documented
  behaviour* (filed INFO), not silently regressed into something worse.
- Run note committed to the tracker with the pass/fail matrix + screenshots.

---

## 8. Case index

See `cases/` — and `README.md` in this folder for the one-line index with
severities.

```
preprod-feature-plan/
├── MASTER-TEST-PLAN.md         ← this file
├── README.md                   ← one-line case index + severities
├── run-record-template.md      ← copy to reports/ per run
└── cases/
    ├── cluster/   CL-01 … CL-07
    ├── websocket/ WS-01 … WS-06
    ├── mtls/      MT-01 … MT-07
    └── copilot/   CP-01 … CP-08
```
