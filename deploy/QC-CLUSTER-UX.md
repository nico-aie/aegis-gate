# QC Cluster-Mode UI/UX Guide — Aegis-Gate 3-node fleet

> How QC (working from a **remote laptop**) verifies the **leaderless cluster**:
> every node's console shows the *whole* fleet, config + runtime state stay
> **consistent** across nodes, and the `/__waf_control/*` contract APIs work and
> **converge fleet-wide**. Pairs with [`QC-LOAD-TEST.md`](./QC-LOAD-TEST.md)
> (capacity), [`PRE-PROD-DEPLOY.md`](./PRE-PROD-DEPLOY.md) (topology §10a), and
> [`CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md) (config ops).

## 0. What's under test

```
QC laptop ── https ─▶ 185.23.199.194:56208  (data VIP, nginx stream TLS passthrough)
                                   └─round-robin─▶ waf-infra-1 / waf-2 / waf-3  :8443
          ── http  ─▶ 185.23.199.194:56243  (admin console → waf-infra-1 :9443)
          ── http  ─▶ 185.23.199.194:56244  (admin console → waf-2       :9443)
          ── http  ─▶ 185.23.199.194:56245  (admin console → waf-3       :9443)
   shared Redis 10.20.0.72:6379  ·  SigNoz 10.20.0.72:8090  ·  185.23.199.194 → infra host 10.20.0.72
```

- **Data / WAF fleet (HTTPS):** `https://185.23.199.194:56208` — self-signed, use `-k` / accept the cert.
- **Admin consoles (HTTP, one per node):** `http://185.23.199.194:5624{3,4,5}`.
  - ⚠️ The admin console is **plain HTTP** in this deployment — use `http://`, **not** `https://`. (`https` to an admin port just hangs.)
- Login: password **`aegis-test-1234`** (dev). Contract secret: **`waf-hackathon-2026-ctrl`**.

## 1. ⚠️ Read this FIRST — how the access model gates each surface

The two planes have very different reachability. Getting this wrong makes a working
feature look broken.

| Surface | Reachable from QC laptop? | Auth | Notes |
|---|---|---|---|
| **Dashboard UI + `/api/*`** (`/api/cluster`, `/api/stats`, `/api/audit/since`, `/dashboard/sse`, `PUT /api/config`) | ✅ via admin ports `:5624x` | **admin session** (login + CSRF) | Use the **browser** — it does login + CSRF for you. Loopback does **not** bypass this (so on-node `curl` is also 401). |
| **`/healthz/{ready,live,startup}`** | ✅ via `:5624x` | open | Node-local; no fleet merge. |
| **`/__waf_control/*`** (capabilities, set_profile, reset_state, healthz, flush_cache) | ❌ **not** via `:56208` or `:5624x` | **loopback-only** + `X-Benchmark-Secret` | Via `:56208` it's treated as normal traffic → **proxied to the upstream** (you'll get the echo app, not control). Via `:5624x` it's `401`. To drive it as a remote, use the **SSH tunnel** in §2.3. |

> Why: `/__waf_control` is gated to `peer.ip().is_loopback()`. Through nginx the peer
> is nginx's IP, never loopback. The contract's sanctioned remote path is an SSH
> local-forward so the WAF sees the request arriving on `127.0.0.1`.

## 2. Prereqs

### 2.1 Browser (cluster UI/UX + sync tests)
Open all three consoles, log in to each (`aegis-test-1234`):
`http://185.23.199.194:56243`, `:56244`, `:56245`. Keep them side-by-side.
> `:56244/:56245` only work once waf-2/waf-3 have `admin.bind: 0.0.0.0:9443` and are
> reachable from the infra host. If a port refuses, that node isn't exposed yet —
> all 3 fleet members still appear inside **any one** console (leaderless), so you can
> run every §3 test from `:56243` alone; the per-node ports are for confirming each
> node renders the **same** fleet view.

### 2.2 Data-plane traffic generator (effect-based convergence checks)
```sh
VIP=https://185.23.199.194:56208
ATTACK="$VIP/?q=1'%20OR%20'1'='1"     # SQLi → blocked when enforcing
LEGIT="$VIP/products"                  # benign → 200
curl -sk -o /dev/null -w '%{http_code}\n' "$ATTACK"   # expect 403 (enforce) / 200 (log_only)
```

### 2.3 `/__waf_control` over SSH (contract control APIs)
Issue control on **one** node; `cluster:true` (default) propagates to the fleet via
Redis — you do **not** need to SSH every node.
```sh
# one terminal — tunnel QC:9443 → infra-host loopback :9443 (admin, HTTP):
ssh -N -L 9443:127.0.0.1:9443 <user>@185.23.199.194
# another terminal on the QC laptop:
SECRET=waf-hackathon-2026-ctrl
CTL=http://127.0.0.1:9443/__waf_control
curl -s -H "X-Benchmark-Secret: $SECRET" $CTL/capabilities | head -c 200   # sanity → {"ok":true,...}
```

## 3. Cluster UI/UX — consistency & sync (browser, §2.1)

For each test, do the action on **one** console and confirm **all three** consoles
agree within the SLA. Inconsistency between consoles = a sync bug.

### 3.1 Fleet roster is identical on every node (`GET /api/cluster`)
On each console's cluster/fleet view (or hit `/api/cluster` while logged in): expect
the **same 3 peers** + `our_node` = that node, and **no `is_leader`** (leaderless).
- **Pass:** all 3 nodes listed on all 3 consoles; `last_heartbeat` recent (< 15 s).
- Kill one node's WAF → it ages out of the roster on the survivors within ~15 s (lease TTL); restart → reappears ≤ 5 s.

### 3.2 Merged fleet metrics (`GET /api/stats`, fleet_view)
Drive steady traffic at `:56208`. On each console's dashboard:
- **Pass:** `fleet_nodes: 3` present, and `request_rate` / `blocks_total` reflect the
  **whole fleet** (not 1/3). The headline numbers match across all 3 consoles
  (±1 refresh, snapshots refresh ~250–500 ms). Timeseries graph shape matches.
- If `fleet_nodes` is **absent**, that console fell back to local-only → fleet_view
  not converging (check Redis reachability / `fleet:snap:*` keys).

### 3.3 Live cross-node event feed (`/dashboard/sse`, fleet_events)
Send an attack through `:56208` (it lands on whichever node nginx picks). On **every**
console's live-events panel:
- **Pass:** the block event appears on **all 3** consoles within **≤ 5 s** (cross-node
  fanout), tagged with the originating node. Not just the node that served it.

### 3.4 Config-plane convergence (`PUT /api/config`, config plane)
In one console, change a config value (e.g. a detector toggle or risk threshold) and
activate. Then:
- **Pass:** the other two consoles show the **new active version** and a per-node
  "applied" indicator flips to that version within **~3 s**; the data-plane behavior
  at `:56208` changes accordingly on **all** nodes.
- Use **rollback** in the console and confirm all nodes revert together.
- **Drift check:** no node should be stuck on the old version (config:waf:applied:\<node\>
  ACK lags = that node not polling/applying).

## 4. `/__waf_control/*` — correctness + fleet convergence (§2.3 tunnel)

Issue on the tunneled node; verify the **effect** fleet-wide via `:56208` (which
round-robins all nodes) and/or the consoles. Reset between tests.

### 4.1 `capabilities` (GET)
```sh
curl -s -H "X-Benchmark-Secret: $SECRET" $CTL/capabilities | python3 -m json.tool
```
**Pass:** `ok:true`; lists `access_control, rate_limit, risk_engine, ddos, rules_engine`
with policies; `active.default_mode` + any `overrides`.

### 4.2 `set_profile` converges fleet-wide (POST)
```sh
# switch the whole fleet to log_only (observe, don't block):
curl -s -H "X-Benchmark-Secret: $SECRET" -H 'Content-Type: application/json' \
  -d '{"scope":"all","mode":"log_only","cluster":true}' $CTL/set_profile | python3 -m json.tool
```
- **Verify convergence (no SSH to other nodes needed):** fire the SQLi at `:56208`
  ~10× — every request should now return **200** (log_only) regardless of which node
  serves it. Before this call it was 403.
- Flip back: `'{"scope":"all","mode":"enforce","cluster":true}'` → attacks return to **403** on all nodes.
- **Pass:** convergence ≤ 2 s (≈ms with pubsub_nudge); response echoes `applied` + `active`; `unsupported:[]`.
- **Granularity:** `{"scope":"policies","feature":"rules_engine","policies":["sqli"],"mode":"log_only","cluster":true}` → only SQLi goes observe-only; XSS still blocks.

### 4.3 `reset_state` clears accumulated state fleet-wide (POST)
```sh
# 1) accumulate: flood the SQLi at :56208 until auto-block kicks in (429/403 sticky)
for i in $(seq 1 60); do curl -sk -o /dev/null "$ATTACK"; done
# 2) reset the whole fleet:
curl -s -H "X-Benchmark-Secret: $SECRET" $CTL/reset_state | python3 -m json.tool
```
- **Pass:** `ok:true`, `audit_log_preserved:true`. After reset, the previously
  auto-blocked source is **clean on all nodes** (a fresh `LEGIT` at `:56208` → 200;
  risk/rate-limit windows cleared). Convergence ≤ 2 s. The audit logs (`waf_audit.log`,
  chain ndjson, SigNoz) are **not** wiped.

### 4.4 `healthz` + `flush_cache` (POST/GET)
```sh
curl -s -H "X-Benchmark-Secret: $SECRET" $CTL/healthz       # → {"ok":true,"status":"alive"}
curl -s -H "X-Benchmark-Secret: $SECRET" $CTL/flush_cache   # → {"ok":true,"supported":<bool>}
```

### 4.5 Gating must hold (negative tests — these prove the security model)
```sh
# via the data VIP → NOT control; returns the upstream echo, NOT {"ok":...}:
curl -sk "$VIP/__waf_control/healthz"                        # expect upstream echo / normal routing
# via an admin port without login → 401:
curl -s  -o /dev/null -w '%{http_code}\n' http://185.23.199.194:56243/__waf_control/healthz   # 401
# wrong/absent secret on the tunnel → 403:
curl -s -o /dev/null -w '%{http_code}\n' $CTL/capabilities   # 403 (no secret)
```
**Pass:** control is unreachable except loopback+secret. A leak here is a finding.

## 5. Data / state consistency deep-checks (shared Redis)

These confirm the *substrate* the UI reads from is consistent. Run on the infra host
(or via the SSH session):
```sh
R="redis-cli -h 10.20.0.72"
$R get control:waf:modes          # mode doc + generation — same value backs every node
$R get control:waf:reset_epoch    # monotonic; bumps once per cluster reset
$R --scan --pattern 'members:*'   # one heartbeat key per live node (TTL ~15s)
$R --scan --pattern 'fleet:snap:*'# one snapshot per node (drives merged /api/stats)
$R get config:waf:doc | head -c 120 ; echo   # active config version
$R --scan --pattern 'config:waf:applied:*'   # per-node applied-version ACKs (all == active?)
```
- **Pass:** member + snapshot + applied keys all enumerate **3 nodes**; `applied` versions
  all equal the active `config:waf:doc` version; `generation` matches what set_profile returned.

## 6. What to watch (every test)
- **All 3 consoles side-by-side** — the leaderless promise is they're interchangeable.
  Any divergence (roster, stats, events, config version) is the bug you're hunting.
- **SigNoz** `http://10.20.0.72:8090` → Logs filter `log_type=waf_audit_chain` (per-node
  `host.name`) and Traces — cross-check that a decision QC sees in the UI is also logged.
- **Convergence timing** — eyeball the SLA: events ≤ 5 s, modes/reset ≤ 2 s, config ~3 s,
  stats ~sub-second. Slower = nudge/pubsub not firing (falls back to polling, still correct).
- **SNAT caveat (from QC-LOAD-TEST §1):** through `:56208` every client looks like nginx's
  IP, so per-IP differentiation isn't meaningful here — but it's *ideal* for cluster tests,
  because one shared bucket makes fleet-wide reset/convergence easy to observe.

## 7. QC pass/fail (cluster SLOs)

| Check | Pass |
|---|---|
| Fleet roster (`/api/cluster`) | 3 peers on every console, no `is_leader`; dead node ages out ≤ 15 s |
| Merged stats (`fleet_nodes`) | present = 3; headline numbers agree across consoles (±1 refresh) |
| Live events (SSE) | attack on any node appears on all 3 consoles ≤ 5 s |
| Config convergence | all nodes show new version + apply it ≤ ~3 s; rollback reverts all |
| `set_profile` (cluster) | fleet-wide effect at `:56208` ≤ 2 s; granular scope respected |
| `reset_state` (cluster) | accumulated state cleared on all nodes ≤ 2 s; audit preserved |
| Gating | `/__waf_control` only via loopback+secret (echo via `:56208`, 401 via `:5624x`, 403 no secret) |
| Redis substrate | members/snap/applied keys all enumerate 3 nodes; versions consistent |

## 8. Gotchas
- **Admin = HTTP, data = HTTPS.** `http://…:5624x` for consoles, `https://…:56208` for traffic. Mixing the scheme looks like an outage.
- **`/__waf_control` is loopback-only.** Don't test it through nginx — use the SSH tunnel (§2.3). Via `:56208` you'll get the *upstream echo* and mistake it for "working."
- **Issue cluster control once.** `cluster:true` propagates; running it on every node is unnecessary (and the other nodes aren't loopback-reachable to you anyway).
- **Reset between control tests** — leftover mode overrides / accumulated risk skew the next check. `reset_state` + `set_profile … enforce` to baseline.
- **Self-signed cert** on `:56208` → `-k` (curl) or accept once (browser).
- **Convergence is best-effort-fast, guaranteed-eventually** — if a number lags briefly, give it the SLA window before calling it a failure; pubsub nudge makes it ms, polling makes it ≤ 2–3 s.
- **`:56244/:56245` dark?** That node's admin is still `127.0.0.1` (default) or unreachable — fix on the node (`admin.bind: 0.0.0.0:9443`); every fleet member is still visible from `:56243`.
