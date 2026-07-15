# Runbook — DDoS Response

**Scope:** what an on-call operator does when Aegis-Gate is under a DDoS attack.
**Audience:** WAF operators with admin-dashboard access.
**Last reviewed:** 2026-07-15

---

## What Aegis-Gate can and cannot mitigate

Aegis-Gate is an **application-layer (L7) reverse proxy**. Read this table before doing
anything else — the response is completely different per layer.

| Attack class | Examples | Handled by |
| --- | --- | --- |
| **L4 volumetric** | SYN flood, UDP/DNS/NTP amplification, raw packet flood | **Upstream only** — CDN / scrubber / LB / kernel. Aegis-Gate never sees these packets as requests. → [§5](#5--l4--escalation-when-aegis-gate-cannot-absorb-it) |
| **Connection-layer** | Connection exhaustion, slowloris (slow headers) | **Aegis-Gate** — connection cap + header-read timeout (mostly automatic). → [§3](#3--connection-layer-flood--slowloris) |
| **L7 request flood** | High-RPS GET/POST floods, single-IP or distributed | **Aegis-Gate** — per-IP DDoS gate + spike mode. → [§1](#1--confirm-the-gate-is-enforcing)–[§2](#2--tighten-the-per-ip-volumetric-limits) |

> **The WAF cannot stop packets it never sees.** L4 volumetric mitigation must live
> *upstream* of Aegis-Gate. Confirm that layer exists **before** an incident.

---

## Deployment facts (from `config/prod.yaml`)

| Thing | Value |
| --- | --- |
| Data listener | `0.0.0.0:8443` (TLS) |
| Admin/dashboard listener | `127.0.0.1:9443` (**loopback** — reach it via SSH tunnel) |
| Upstream pools | `auth-pool`, `backend-pool`, `static-pool` |
| Route tiers | `auth`→critical, `api`→high, `static`→medium, catch-all→(default) |
| State backend | Redis (`redis://127.0.0.1:6379`) — required for cluster/fleet features |
| Ready posture policy profiles | `config/profiles/prod-strict.yaml`, `prod-balanced.yaml`, `prod-high-throughput.yaml` |

### Admin auth for `curl` (double-submit CSRF)

Admin mutations require **both** a session cookie and a matching CSRF token
(cookie `aegis_csrf` echoed in the `x-csrf-token` header). Session cookie is
`aegis_session`. Easiest path: log in once, save the cookie jar, then reuse it.

```bash
# 0. From the WAF host (admin is loopback-only). If remote, tunnel first:
#    ssh -L 9443:127.0.0.1:9443 waf-host
ADMIN=https://127.0.0.1:9443
JAR=/tmp/aegis.cookies

# Log in (TOTP required if dashboard_auth.totp_enabled) — stores aegis_session + aegis_csrf in $JAR
curl -sk -c "$JAR" "$ADMIN/admin/login" \
  -d '{"user":"admin","password":"'"$PASS"'","totp_code":"'"$CODE"'"}'

# Read the CSRF token back out of the jar for the x-csrf-token header
CSRF=$(awk '/aegis_csrf/{print $7}' "$JAR")

# Helper for every mutating call below:
adm() { curl -sk -b "$JAR" -H "x-csrf-token: $CSRF" "$@"; }
```

All `adm ...` calls below assume this setup. `GET` reads need only `-b "$JAR"`.

---

## Step 0 — Classify (30 seconds)

1. Open the dashboard **DDoS panel**, or:
   ```bash
   curl -sk -b "$JAR" "$ADMIN/api/gates/ddos"      # enabled, observe_only, current_rps, baseline_rps, spike_active
   curl -sk -b "$JAR" "$ADMIN/api/slo"             # is the origin actually degraded, or just noisy?
   ```
2. Check host NIC / conntrack stats. **Bandwidth saturated or host unreachable → L4 → [§5](#5--l4--escalation-when-aegis-gate-cannot-absorb-it) immediately.**
3. WAF reachable but origin overwhelmed and `current_rps ≫ baseline_rps` → **L7 flood → §1**.
4. Logs show `connection cap reached — rejecting connection at TCP` → **connection-layer → §3**.

---

## 1 — Confirm the gate is enforcing

The DDoS gate ships **on** and **enforcing** by default. Verify it wasn't left in
shadow mode:

```bash
curl -sk -b "$JAR" "$ADMIN/api/gates/ddos"   # want: "enabled": true, "observe_only": false
```

If `observe_only` is `true`, flip to enforce (audited, no restart):

```bash
adm -X PUT "$ADMIN/api/gates/ddos/mode" -d '{"observe_only": false}'
```

---

## 2 — Tighten the per-IP volumetric limits

Default is **1000 req / 10 s per IP** (`per_ip_limit` / `per_ip_window_s`); an IP that
breaches it is **auto-blocked** for `block_ttl_s` (default 300 s), and the block
propagates cluster-wide via the shared block-list.

Under attack, tighten and make spike mode engage sooner. Changes hot-apply via
`ArcSwap` — **no restart**, fully audited:

```bash
adm -X PUT "$ADMIN/api/gates/ddos" -d '{
  "enabled": true,
  "per_ip_limit": 200,
  "per_ip_window_s": 10,
  "spike_multiplier": 2.0,
  "tightened_per_ip_rps": 10,
  "block_ttl_s": 900
}'
```

What each knob does:

- **`per_ip_limit` / `per_ip_window_s`** — the sliding-window auto-block threshold.
- **`spike_multiplier`** — lower it (3.0 → 2.0) so **spike mode** engages earlier.
  When `current_rps > spike_multiplier × baseline_rps`, spike mode clamps **every**
  IP to `tightened_per_ip_rps`. Hysteresis: engages after 2 over-ticks, releases
  after 8 under-ticks (tighten-fast / relax-slow — won't flap).
- **`tightened_per_ip_rps`** — the hard per-IP cap during spike mode (an RPS).
- **`block_ttl_s`** — keep offenders banned longer.

**Prefer a vetted profile** over hand-tuning if you can redeploy config:

| Profile | Posture |
| --- | --- |
| `config/profiles/prod-strict.yaml` | `per_ip_limit: 200`, `spike_multiplier: 2.0` |
| `config/profiles/prod-balanced.yaml` | middle ground |
| `config/profiles/prod-high-throughput.yaml` | `per_ip_limit: 5000`, `spike_multiplier: 4.0` |

### Distributed flood spread thin across nodes

If each node sits below its own per-node threshold but the fleet total is clearly an
attack, switch spike detection to **fleet scope** so nodes sum RPS through the shared
per-second bucket (`ddos:fleet:rps:<epoch>`), failing safe to per-node on backend error:

```yaml
ddos:
  spike_scope: fleet     # default is per_node
```

(Config-doc change → publish to the fleet. Requires the Redis state backend.)

---

## 3 — Connection-layer flood / slowloris

These are handled **automatically** in the accept loop:

- **Connection cap** — a semaphore bounds concurrent connections per listener; on
  exhaustion the socket is dropped at TCP (`connection cap reached — rejecting
  connection at TCP` in debug logs) *before* admission, so it can't inflate the drain
  gauge.
- **Slowloris** — a **10 s header-read timeout** kills connections that dribble headers
  to hold slots open.

If the origin (not the WAF) is buckling under post-TLS request overload, enable the
**load-shedder** so excess requests get a cheap 503 instead of collapsing the pool:

```bash
adm -X PUT "$ADMIN/api/gates/shed" -d '{"enabled": true}'
```

If the per-upstream connection cap is set higher than an origin pool can absorb, lower
it in the pool config (`upstreams.<pool>`) and roll the config.

---

## 4 — Manually block known-bad sources

The blacklist is the **first** gate in the pipeline
(`blacklist → ddos → ip_limiter → strike-block → …`) — the cheapest possible rejection.
Use it for identified attack IPs/CIDRs the auto-block hasn't caught, or to pre-empt.

```bash
# Block an offender range
adm -X POST "$ADMIN/api/blacklist" -d '{"cidr": "203.0.113.0/24", "reason": "ddos-2026-07-15"}'

# See who is hammering the blacklist
curl -sk -b "$JAR" "$ADMIN/api/blacklist/hits"
```

**Protect legitimate traffic** — whitelist CDN / partner ranges so aggressive limits
don't catch them:

```bash
adm -X POST "$ADMIN/api/whitelist" -d '{"cidr": "198.51.100.0/24", "reason": "cdn-egress"}'
```

If a **real user** got swept up by cumulative IP-risk, clear just them:

```bash
adm -X PUT "$ADMIN/api/risk/<ip>/reset"
```

---

## 5 — L4 / escalation (when Aegis-Gate cannot absorb it)

If Step 0 classified the attack as **L4 volumetric**, the WAF is downstream of the
problem and its knobs won't help. Escalate:

1. **Engage the upstream scrubbing layer / CDN** — anycast, rate-based ACLs, SYN-cookie
   protection. This is the design assumption: Aegis-Gate expects a scrubber/LB in front.
2. **Host/kernel** — verify SYN cookies enabled, tighten conntrack limits, drop obvious
   junk at the host firewall.
3. **Scale horizontally** — the WAF is fleet-aware. Add nodes; fleet-scope spike
   detection ([§2](#distributed-flood-spread-thin-across-nodes)) and the shared
   block-list converge across the fleet.

---

## 6 — Return to steady state (do not skip)

1. **Restore normal limits.** Re-run `PUT /api/gates/ddos` with baseline values
   (1000 / 10 s, spike 3.0, `tightened_per_ip_rps` 20) or revert the config doc. Leaving
   strict limits on will throttle legitimate peak traffic.
2. **Clear temporary enforcement state** so baselines re-warm clean (spike state,
   rolling RPS, sliding windows, local auto-blocks — **durable config is preserved**):
   ```bash
   adm -X POST "$ADMIN/__waf_control/reset_state"
   ```
3. **Review.** Pull the audit chain and the SLO/Health page for the incident window.
   Keep persistent blacklist entries for repeat offenders; remove the temporary ones.

---

## Quick reference

| Action | Call |
| --- | --- |
| Read DDoS state | `GET /api/gates/ddos` |
| Enforce (exit shadow) | `PUT /api/gates/ddos/mode` `{"observe_only": false}` |
| Tighten limits | `PUT /api/gates/ddos` `{...}` |
| Enable load-shedder | `PUT /api/gates/shed` `{"enabled": true}` |
| Blacklist a CIDR | `POST /api/blacklist` `{"cidr": "...", "reason": "..."}` |
| Blacklist hit counts | `GET /api/blacklist/hits` |
| Whitelist a CIDR | `POST /api/whitelist` `{"cidr": "...", "reason": "..."}` |
| Reset one IP's risk | `PUT /api/risk/<ip>/reset` |
| Clear temp state (post-incident) | `POST /__waf_control/reset_state` |
| Origin health / SLO | `GET /api/slo` |

### Honest caveats

- Per-request DDoS counting is **per-node in-process** on the hot path. If the LB does
  **not** fan each source IP to every node, use `ddos.spike_scope: fleet`.
- `/__waf_control/*` and the admin API are **loopback-only** — tunnel in; they are not
  reachable from the data edge.
