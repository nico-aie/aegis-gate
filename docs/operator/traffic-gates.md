# Traffic Gates — request-flow short-circuits

> Four binary block-or-pass gates run on every request **before**
> the detector chain. They live in
> `crates/aegis-security/src/{ddos,risk,rate_limit,...}` and are
> distinct from the signal-emitting `Detector` trait impls in
> `crates/aegis-security/src/detectors/`. The dashboard surfaces
> them on the **Traffic Gates** page under the Policy menu group.

> **2026-05-19 — Composite-key migration.** Three of the four
> gates (Strike-Block, Cumulative IP risk thresholds, Rate Limit)
> now key on the composite `RiskKey { ip, device_fp?, session? }`
> instead of just `IpAddr`. Two browsers on the same NAT'd IP
> each get their own bucket. **DDoS Gate stays IP-keyed by
> design** — volumetric protection must fire fast regardless of
> session shape, and a flooding source rotating cookies should
> not escape. Where this doc still says "per-IP", read it as
> "per-bucket" for the three migrated gates and as "per-TCP-peer-IP"
> for the DDoS gate.

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
[BUG-DDOS-STUB internal audit](../../plans/archive/issue-fix/internal-audit-2026-05-09-ddos/)
for the docs-vs-code drift caused by treating DDoS as a detector.

## The four gates (firing order)

Gates fire **top-down**; the first one that decides "block"
terminates the request. Order is cheapest-first so a known-bad IP
costs the least CPU.

| # | Gate | Module | Returns | Trigger |
|---|---|---|---|---|
| 1 | **Access list** | `aegis-control/src/api/blacklist.rs` | 403 + `X-WAF-Action: block` | IP / CIDR / country on the operator blacklist |
| 2 | **Strike-block** | `aegis-security/src/risk/tracker.rs` | 403 + `X-WAF-Action: block` + `X-WAF-Rule-Id: risk-strikes` | **Per-RiskKey-bucket** lifetime strikes ≥ `risk.strikes.block_at` (default 50) **AND** `risk.strikes.enabled = true` (opt-in, default `false` since 2026-05-10) |
| 3 | **Rate-limit** | `aegis-security/src/rate_limit/` | 429 + `X-WAF-Action: rate_limit` | **Per-RiskKey-bucket** token-counter exceeded for this request |
| 4 | **DDoS gate** | `aegis-security/src/ddos.rs` | 403 + `X-WAF-Action: block` | **Per-TCP-peer-IP** sliding-window burst exceeded **OR** previously auto-blocked. **Intentionally NOT keyed by the composite RiskKey** — a flooding source can't escape by rotating session cookies. |

> The **Cumulative IP risk thresholds** (#3 on the dashboard's
> Traffic Gates page) is not a fifth short-circuit gate — it
> tunes how the cumulative score from the regular detector
> chain produces `challenge` (≥ `risk.thresholds.challenge_at`,
> default 40) and `block` (≥ `risk.thresholds.block_at`,
> default 80) actions. The decaying score it gates is what
> `X-WAF-Risk-Score` reports on every response (contract §5.1),
> which is why operators tune it on the same page as the four
> per-flow gates.

### Blacklist vs whitelist precedence

The **blacklist is evaluated before the whitelist** (gate #1 above runs
first, and a blacklist match returns the 403 before the whitelist is
consulted). So a source that appears on **both** lists is **blocked** —
deny beats allow, by design. If you whitelist an IP and it's still
getting 403'd, check whether it (or a CIDR/country covering it) is also
on the blacklist.

To make contradictory config visible, the Access Lists page and the
add endpoint surface a **non-blocking warning** when the same
`(kind, value)` is added to the opposite list: the add still succeeds,
but the response carries a `conflict` object and the row is badged
(`⚠ also whitelisted` / `⚠ also blacklisted`). The check is **exact
(kind, value) match only** — it does NOT analyze CIDR-contains,
ASN-membership, or country-covers-IP overlaps, so a blacklisted
`10.0.0.0/8` plus a whitelisted `10.1.2.3` is a real conflict at
runtime that the warning won't flag. When in doubt, the precedence
above is the rule: blacklist wins.

### Strike-Block default + contract notes

Strike-Block is **opt-in (disabled by default)** as of 2026-05-10.
The lifetime strike counter never decays, which can interact
awkwardly with the contract's `X-WAF-Risk-Score` accumulation+
decay invariant (§5.1, §7) — an IP that has accumulated 50
strikes stays 403'd even after the cumulative score has decayed
back below threshold. Leaving the gate disabled keeps cumulative
IP risk thresholds (#3 on the dashboard) as the only score-based
block path, so a benchmark "send N attacks → wait → send benign
→ expect allow" lifecycle test passes cleanly.

When you do enable Strike-Block (production hardening for
repeat offenders), `X-WAF-Risk-Score` continues to report the
*decayed cumulative score* — the strike count is a separate
counter that the response stamper does not surface. The
distinct `X-WAF-Rule-Id: risk-strikes` tag lets operators
attribute blocks to this gate in the audit log and dashboards.

### Rate Limit vs DDoS — what's the difference?

They look similar (both have a "limit + window" pair) but they have **opposite enforcement semantics AND opposite keying**:

| Property | Rate Limit | DDoS Gate |
|---|---|---|
| Algorithm | Sliding-window token bucket | Sliding-window auto-block |
| **Keying** | **Composite RiskKey** `{ip, device_fp?, session?}` (2026-05-19) | **TCP peer IP** (intentional) |
| Trigger | Window count exceeds `limit` | Window count exceeds `per_ip_limit` |
| Response | 429 `X-WAF-Action: rate_limit` | 403 `X-WAF-Action: block` |
| Recovery | **Automatic** — bucket allowed again as the window slides | **TTL'd** — IP rejected for `block_ttl_s` (default 300s) |
| State location | In-process `DashMap<RiskKey, VecDeque<Instant>>` | Cluster `StateBackend::auto_block` keyspace |
| Cluster scope | Per-node | Cluster-wide via shared backend |
| Use case | "Steady-state per-bucket budget" — APIs with rate fairness | "Sustained-burst quarantine" — DDoS-grade protection |
| Session-rotation attack? | Attacker can rotate cookies to get a fresh bucket | Attacker stays blocked — IP is the only key |

In practice operators configure both:

- **Rate Limit** at e.g. `1000 req / 60 s` (≈16 req/s per bucket). Catches abusive clients gracefully — they get 429, can back off and retry. Legit user B sharing a NAT'd egress with attacker A keeps their own bucket budget.
- **DDoS Gate** at e.g. `1000 req / 10 s` (a much tighter burst window: 100 req/s sustained for 10 s). Catches actual flood attacks — burst-exceed → 5-minute auto-block. The IP is rejected entirely for that duration regardless of session shape.

The Rate Limit's 429 lets a misbehaving client recover. The DDoS Gate's 403 + TTL doesn't — by design, because if you're at "100 req/s sustained for 10 s from one IP" you're not a misbehaving client, you're an attack.

Both are **hot-reloadable** via the dashboard's edit modals (`PUT /api/rate-limit`, `PUT /api/gates/ddos`). State (per-bucket timestamps for Rate Limit, per-IP TTL'd block list for DDoS) is preserved across edits — flooding sources don't get a free reset when you tighten thresholds mid-attack.

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

| Gate / Knob | Tune via | Hot-reload? |
|---|---|---|
| Access list | Dashboard → Access Lists page (`POST /api/blacklist` etc.) | ✅ yes — audit-mutated |
| Strike-block (enable + threshold) | Dashboard → Traffic Gates → Strike-Block card → Edit (`PUT /api/gates/strikes`) — toggles `enabled` and tunes `block_at`. Reset every bucket sharing an IP via `POST /api/risk/<ip>/reset`; reset ONE composite-key bucket via `POST /api/risk/reset_key` (or the per-row button on Top Attackers → Composite RiskKey view). | ✅ yes — audit-mutated (2026-05-10; surgical reset added 2026-05-19) |
| Cumulative IP risk thresholds (global defaults) | Dashboard → Traffic Gates → Cumulative IP risk card (`PUT /api/risk/thresholds`) | ✅ yes — audit-mutated (moved 2026-05-10) |
| Per-tier `challenges_enabled` toggle | Dashboard → Detectors & Tiers → Edit tier (`PUT /api/tiers/<name>`) | ✅ yes — audit-mutated (defaults to `false` on every tier — challenges are opt-in) |
| Per-tier `cumulative_challenge_at` / `cumulative_block_at` overrides | API only — `PUT /api/tiers/<name>` accepts the fields, but the dashboard does not surface inputs (use the global thresholds above unless you have a strong per-tier need) | ✅ yes — audit-mutated |
| Rate-limit | Dashboard → Traffic Gates → Rate Limit card → Edit (`PUT /api/rate-limit`) | ✅ yes — audit-mutated (2026-05-09) |
| DDoS thresholds | Dashboard → Traffic Gates → DDoS card → Edit (`PUT /api/gates/ddos`) | ✅ yes — audit-mutated (2026-05-09) |

All four gates are hot-reloadable. Per-bucket (Strike-Block, Cumulative-risk, Rate Limit) and per-IP (DDoS) state is preserved across edits — flooding sources don't get a free reset when operators tighten thresholds mid-attack. Every change is captured in the audit chain via `AuditedMutate`.

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
