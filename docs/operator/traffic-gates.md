# Traffic Gates — request-flow short-circuits

> Four binary block-or-pass gates run on every request **before**
> the detector chain. They live in
> `crates/aegis-security/src/{ddos,risk,rate_limit,...}` and are
> distinct from the signal-emitting `Detector` trait impls in
> `crates/aegis-security/src/detectors/`. The dashboard surfaces
> them on the **Traffic Gates** page under the Policy menu group.

## Why "gates" and not "detectors"

The detector chain (sqli, xss, path_traversal, …) emits
`Signal { score, tag, field }` rows that get summed into the per-IP
risk score; thresholds (`risk.thresholds.challenge_at`, `block_at`)
turn that score into an action. **Detectors are pattern-matchers
that contribute weight.**

The four request-flow gates are different:

- They **read shared cluster state** (StateBackend keyspace) — not
  the request content.
- They **return a binary decision** — block (403 / 429) or pass.
- They **short-circuit** before the detector chain runs, so a
  flooding source can't burn CPU on regex matchers.

Conflating the two has bitten operators before — see the
[BUG-DDOS-STUB internal audit](../../reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md)
for the docs-vs-code drift caused by treating DDoS as a detector.

## The four gates (firing order)

Gates fire **top-down**; the first one that decides "block"
terminates the request. Order is cheapest-first so a known-bad IP
costs the least CPU.

| # | Gate | Module | Returns | Trigger |
|---|---|---|---|---|
| 1 | **Access list** | `aegis-control/src/api/blacklist.rs` | 403 + `X-WAF-Action: block` | IP / CIDR / country on the operator blacklist |
| 2 | **Strike-block** | `aegis-security/src/risk/tracker.rs` | 403 + `X-WAF-Action: block` | Per-IP lifetime strikes ≥ `risk.strikes.block_at` (default 50) |
| 3 | **Rate-limit** | `aegis-security/src/rate_limit/` | 429 + `X-WAF-Action: rate_limit` | Token bucket exceeded for this request |
| 4 | **DDoS gate** | `aegis-security/src/ddos.rs` | 403 + `X-WAF-Action: block` | Per-IP sliding-window burst exceeded **OR** previously auto-blocked |

After all four pass, the request enters the detector chain. The
[detectors](../security/detectors/README.md) emit signals that
accumulate into the risk score; threshold crossings produce
challenges or blocks via the regular pipeline.

## Operator workflow

### Routine monitoring

The Traffic Gates page polls `/api/blacklist`, `/api/whitelist`,
`/api/risk`, and `/api/gates/ddos` every few seconds. Watch for:

| Indicator | What it means | Action |
|---|---|---|
| Blacklist count climbing | Operators or threat-intel feed adding entries | Verify ASN / country attribution if entries spiking |
| Strike-block count > 0 | One or more IPs have crossed the strike threshold | Investigate via `/dashboard/audit?ip=…` |
| `Spike active: ⚠ SPIKE ACTIVE` (yellow) on DDoS card | Cluster-wide RPS exceeded `spike_multiplier × baseline` | Likely an in-progress flood; correlate with Top Attackers |
| DDoS card shows `OBSERVE-ONLY` | Operator has set `cfg.ddos.observe_only: true` | Confirm intentional — observe-only does not protect, only audits |

### Tuning the four gates

| Gate | Tune via | Hot-reload? |
|---|---|---|
| Access list | Dashboard → Access Lists page (`POST /api/blacklist` etc.) | ✅ yes — audit-mutated |
| Strike-block threshold | Dashboard → Settings → Risk thresholds (`PUT /api/risk/thresholds`) | ✅ yes — audit-mutated |
| Rate-limit buckets | YAML `cfg.rate_limit.buckets`, reload | ⏳ requires reload |
| DDoS thresholds | YAML `cfg.ddos.*`, reload | ⏳ requires reload |

DDoS hot-reload of `per_ip_limit` / `block_ttl_s` / `spike_multiplier`
is queued as a follow-up — config is captured at boot via
`DdosDetector::new(cfg)`. To change values, edit YAML and run
`waf reload` (or restart the process).

### "Why was my legit traffic blocked?"

Walk the four gates in order. The audit log's `rule_id` tells you
which gate fired:

| `rule_id` | Gate | Look at |
|---|---|---|
| `blacklist:<entry-id>` | Access list | Dashboard → Access Lists; remove the entry |
| `risk-strikes` | Strike-block | Dashboard → Settings → reset strikes per IP via `POST /api/risk/reset` |
| `ip-rate-limit` | Rate-limit | YAML `cfg.rate_limit.buckets` — raise `limit` or `window_s` |
| `ddos` | DDoS gate | YAML `cfg.ddos.per_ip_limit` (raise to taste) or set `observe_only: true` for shadow mode while you investigate |

The audit field `ddos_observe_only: true/false` distinguishes
"would have blocked but ran in shadow" from "actually blocked".
Audit `action` field is `ddos_observed` (shadow) or `ddos_blocked`
(enforce).

## Why DDoS isn't on the Detectors page

DDoS does not implement the `Detector` trait. It can't:

- Contribute a `score` to the calibrated 5-tier ladder (probe / phishing / header / broad / high / critical).
- Run through the `run_all_filtered()` chain in `aegis-security/src/detectors/mod.rs`.
- Be toggled by the per-tier mask grid.
- Appear on the Detectors page's "Risk score reference" panel.

It's a separate concern with its own dashboard surface (this page).
The Detectors page is for the signal-emitting pipeline; the Traffic
Gates page is for the binary short-circuits that fire first.

## Cross-refs

- [`docs/security/ddos-protection.md`](../security/ddos-protection.md) — DDoS gate full spec
- [`docs/security/risk-scoring.md`](../security/risk-scoring.md) — strike-block threshold semantics
- [`docs/security/rate-limiting.md`](../security/rate-limiting.md) — token-bucket rate-limit details
- [`docs/security/ip-reputation.md`](../security/ip-reputation.md) — access list + threat-intel feeds
- [`docs/operator/risk-tuning.md`](./risk-tuning.md) — tuning the four-tier framework + threshold trio
