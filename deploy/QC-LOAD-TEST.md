# QC Load-Test Guide — Aegis-Gate 3-node fleet

> How QC should load-test the live fleet: **3 WAF nodes behind the nginx `stream`
> LB**, sharing Redis state, terminating TLS at the edge. Uses the repo's k6
> scenarios in [`tests/load/`](../tests/load/) + the 5k mixed script. Pairs with
> [`STAGING-BENCHMARK.md`](./STAGING-BENCHMARK.md) (single-node methodology) and
> [`PRE-PROD-DEPLOY.md`](./PRE-PROD-DEPLOY.md) (the topology).

## 0. What's under test

```
k6 ─ https ─▶ nginx stream :8088 (TLS passthrough) ─┬─▶ 10.20.0.72:8443  waf-infra-1
   (load gen)                                        ├─▶ 10.20.0.40:8443  waf-3
                                                      └─▶ 10.20.0.21:8443  waf-2
   shared Redis 10.20.0.72:6379 · mock upstream :9991-9994 · SigNoz :4317/:8090
```
- **LB VIP (the fleet entry point):** `https://10.20.0.72:8088` (TLS — self-signed).
- **A single node (direct):** `https://10.20.0.<id>:8443`.

## 1. ✅ Read this FIRST — PROXY protocol now preserves the real client IP

As of 2026-06-11 the data VIP (`:56208` → nginx `:8088`) sends the **PROXY protocol
header**, and every node runs `accept_proxy`. So the WAF keys per-client risk on the
**real client IP** even through the LB — the old SNAT collapse (all load looking like
one client = nginx's IP) is **gone**. Consequences:

| Test type | Target | Why |
|---|---|---|
| **Throughput / latency / fan-out / failover** | **LB `:56208`** ✅ | aggregate behavior as real clients see it |
| **Single-source DDoS flood** (`ddos-burst`) | LB `:56208` ✅ | a flood from one IP is presented as that IP |
| **Multi-client differentiation** (legit NOT blocked while an attacker IP is; rate-limit/risk per distinct client) | **LB `:56208`, from DISTINCT source IPs** ✅ | the WAF now sees each real client IP via PROXY — a per-source k6 run differentiates correctly. (Generate from several source hosts / a fan-out runner; one host = one IP.) |

> Caveat: PROXY trust rides on `proxy.trusted_proxies` — only nginx's hop is trusted,
> so a client **cannot** spoof its own IP. If you bypass the LB and hit a node's
> `:8443` directly **without** a PROXY header, `accept_proxy: optional` still serves
> using the real TCP peer — also fine for per-IP tests. A k6 container behind rootless
> Docker still SNATs to the docker gateway as *its* source, so for true multi-IP
> realism use multiple source hosts, not one container.

## 2. Prereqs

```sh
# k6 via Docker (not installed on the host). Mount the scripts read-only.
K6="docker run --rm --add-host=host.docker.internal:host-gateway \
  -v $PWD/tests/load:/scripts -v $PWD/tests/hackathon/k6:/hk6 grafana/k6 run \
  --insecure-skip-tls-verify"          # self-signed cert → skip verify

VIP=https://10.20.0.72:8088            # the 3-node LB
# reset accumulated risk/rate-limit/cache on EVERY node before each run (contract §2.4):
for ip in 10.20.0.72 10.20.0.40 10.20.0.21; do
  curl -sk -X POST -H "X-Benchmark-Secret: waf-hackathon-2026-ctrl" https://$ip:8443/__waf_control/reset_state -o /dev/null
done
# NOTE: /__waf_control is loopback-gated — run reset_state ON each node (127.0.0.1),
# or via its admin :9443 over an SSH session to that node.
```

## 3. Test matrix

Run each, record k6 summary + the "what to watch" (§4). Reset state between runs.

### 3.1 Baseline throughput + latency (over TLS, via LB)
```sh
$K6 -e WAF_TLS_TARGET=$VIP -e VUS=200 -e DURATION=2m /scripts/tls-baseline.js
```
Measures p50/p95/p99 + RPS as clients see it (incl. TLS handshake). Ramp VUS
(100→200→400→800) to find the knee.

### 3.2 Fan-out distribution (are all 3 nodes serving?)
During 3.1, on the infra host:
```sh
docker exec aegis-nginx-lb-nginx-lb-1 sh -c 'tail -2000 /var/log/nginx/stream.log' \
  | grep -oE '10.20.0.(72|40|21):8443' | sort | uniq -c   # expect ~even thirds
```

### 3.3 High-volume mixed traffic (legit + crawler + attacker, ~5k RPS)
```sh
$K6 -e WAF_TLS_TARGET=$VIP \
    -e LEGIT_RPS=4000 -e CRAWLER_RPS=500 -e ATTACKER_RPS=500 -e DURATION=5m \
    /hk6/prod-balanced-5k-v2.js
```
Proves detection holds under load: legit→200, attacks→403/429, low false-positive.

### 3.4 Single-source DDoS flood (per-IP gate)
```sh
$K6 -e WAF_TLS_TARGET=$VIP -e BURST_RPS=3000 -e BURST_SECS=30 /scripts/ddos-burst.js
```
Expect: auto-block fires (`429`/`403`), first block p95 < ~2s. (Valid via LB —
it's a single source by design.)

### 3.5 Load-mode degradation / shedding
```sh
$K6 -e WAF_TLS_TARGET=$VIP -e RPS=20000 -e DURATION=2m /scripts/loadmode-degradation.js
```
Drive past `load_mode.critical_rps` → expect adaptive 503 shedding (Low→Med→High
tiers shed first; Critical never), recovery after load drops.

### 3.6 Failover (node loss mid-test)
```sh
$K6 -e WAF_TLS_TARGET=$VIP -e VUS=200 -e DURATION=2m /scripts/tls-baseline.js &
sleep 30
# kill one node (e.g. on 10.20.0.21): stop the ./waf process there
# nginx ejects it after max_fails=2 × fail_timeout; traffic continues on 2 nodes.
```
Expect: a brief blip, then steady on the survivors; error rate returns to ~0;
distribution becomes 50/50; the dropped node's lease ages out of Redis.

### 3.7 Per-IP rate-limit / risk-strikes (DIRECT to a node — see §1)
Run k6 **on a node** (or a host with distinct source IPs) against its own `:8443`:
```sh
# on the node host:
docker run --rm --network host -v $PWD/tests/load:/scripts grafana/k6 run \
  --insecure-skip-tls-verify -e WAF_TLS_TARGET=https://127.0.0.1:8443 \
  -e STRIKE_LIMIT=50 /scripts/risk-strikes.js
```
Proves per-IP accumulation/blocking with REAL distinct clients (loopback aliases),
which the SNAT LB can't represent.

## 4. What to watch (every run)

- **SigNoz UI** `http://10.20.0.72:8090` → Traces (decision latency breakdown,
  action mix), Logs (`serviceName=aegis-gate`, audit decisions), per-node `host.name`.
- **Per-node CPU/mem** on each WAF host: `top`/`htop` (or hostmetrics in SigNoz).
  To match the real **8 vCPU / 16 GB** spec, pin each node (`taskset -c 0-7`,
  `MemoryMax=16G`) — otherwise a 128-core box flatters the numbers.
- **Redis** (shared state): `redis-cli -h 10.20.0.72 info stats | grep ops`; watch
  for the leader lease staying stable (no flapping) under load.
- **Mock upstream** headroom (it's the origin — `:9991`); if it saturates, you're
  measuring the mock, not the WAF.
- **Error/status mix** from k6: 2xx vs 403/429/503; the WAF's `X-WAF-Action` mix.

## 5. QC pass/fail (SLOs)

Per-node reference (prod-balanced profile, single node): p95 ≈ 2.9 ms, p99 ≈ 4.5 ms,
≥99% legit OK, ~80%+ detection, ~3k+ RPS/node. For the **3-node fleet** target
roughly:

| Metric | Pass |
|---|---|
| Aggregate throughput | ≥ ~9k RPS (3× single-node) at SLO latency |
| p95 / p99 latency (via LB, incl. TLS) | p95 < ~10 ms, p99 < ~25 ms under nominal load |
| Legit success (non-stress) | ≥ 99% (false-positive < 1%) |
| Attack detection (mixed) | ≥ 80% blocked/challenged |
| Fan-out | each node within ±10% of 1/3 |
| Failover | no sustained errors after a node drop; recover < ~5 s |
| Shedding | 503s appear only past `critical_rps`; recover when load drops |
| Stability (soak 30–60 min) | no mem growth/leak, no lease flapping, flat latency |

Tune the absolute numbers to your acceptance bar; the **shapes** (linear scale,
graceful shedding, clean failover, low FP) are the QC signal.

## 6. Gotchas

- **Self-signed cert** → always `--insecure-skip-tls-verify` (or import the CA).
- **Reset between runs** — accumulated risk/rate-limit state will skew the next run;
  `reset_state` on every node first. It preserves `./waf_audit.log`.
- **Real client IP via PROXY** (§1) — per-IP/rate-limit numbers through `:56208` are
  now valid (PROXY protocol). For multi-IP realism still use multiple source hosts
  (one rootless-Docker k6 container SNATs to a single gateway IP).
- **Mount, don't reload** — if you change the LB upstream mid-campaign, recreate
  nginx (`up -d --force-recreate`), don't `restart` (stale single-file bind mount).
- **rootless Docker** — published-port SNAT also means the k6 container's source is
  the docker gateway; fine for capacity tests, not for source-IP realism.
- **Warm-up** — discard the first ~10–30 s (TLS/conn-pool/cache warm) from SLO math.
