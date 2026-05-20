# Risk tuning — what to do instead of editing detector scores

> Aegis-Gate's per-detector risk scores (e.g. `sqli=70`, `cmdi=70`,
> `Log4Shell=90`, `recon_path=25`) are **not editable from the console
> UI**. This page explains why, and walks through every operator action
> available for tuning risk to your environment.

> **2026-05-20 — per-request tier gate (Option B).** A request is now
> blocked per-request when the **sum** of its detector scores reaches
> the matched tier's per-request threshold (`risk_threshold`:
> critical 50 / high 70 / medium 80 / low 90). This is separate from
> the **cumulative** IP-risk gate (which accumulates across requests
> and decays). Detector scores were recalibrated so a single clear
> exploit (sqli/xss/ssrf/path_traversal/cmdi/ssti/nosql/CRLF = 70)
> blocks on the protective tiers (critical, high), and definitive-RCE
> (Log4Shell, XXE = 90) blocks on **every** tier including `low`.
> Route → tier assignment therefore decides how aggressively each
> route blocks: put sensitive/public-attack-surface routes on
> `critical`/`high`; a route left on `low` only blocks RCE-class
> single hits (or multi-signal sums ≥ 90).

> **2026-05-19 — composite-key migration.** Cumulative risk scores
> are now per-`RiskKey { ip, device_fp?, session? }` bucket, not
> per-IP. Two browsers on the same NAT'd IP each carry their own
> bucket score; reset one without disturbing the other via the
> Top Attackers → Composite RiskKey view → "Reset bucket" button
> (or `POST /api/risk/reset_key`). The legacy IP-only reset
> (`POST /api/risk/<ip>/reset`) still exists and wipes every
> bucket sharing that IP.

---

## TL;DR

| You want to… | Do this | Where |
|---|---|---|
| Make a detector quieter without disabling it | Move it to `log_only` mode | Settings → set_profile, or `PUT /__waf_control/set_profile` |
| Block sooner (be more aggressive) | Lower `risk.thresholds.challenge_at` / `block_at` | `cfg.risk.thresholds` in YAML, or Settings → Risk thresholds |
| Block later (be more permissive) | Raise the same thresholds | Same |
| Bias scoring on a specific route | Add a custom rule with `RaiseRisk(delta)` | Rules page, or `POST /api/rules` |
| Suppress a specific detector on a specific endpoint | Per-tier override on the Detectors page | Detectors → Edit row → tier |
| Allow legitimate redirect targets | `cfg.detectors.open_redirect.allowed_domains` | YAML only (boot-time) |
| Test a tightening change without taking traffic | Run the [Simulator](../control-plane/dashboard.md#simulator) on the candidate config | Simulator page |

If the table doesn't cover your case, read [§ Why scores aren't editable](#why-scores-arent-editable) and the per-knob sections below before opening a feature request.

---

## Why scores aren't editable

The dashboard exposes detector **enabled / disabled** + per-tier **overrides** + the global **risk-threshold trio** (`challenge_at` / `block_at` / `strikes.block_at`), but does **not** expose a per-detector score editor. This is deliberate.

### Reason 1 — the score-tier framework is a calibration, not a config

Each detector emits a score from a small, **deliberately calibrated** ladder:

| Tier | Score | Detectors | Meaning |
|---|---|---|---|
| Definitive RCE / CVE | **90** | Log4Shell (`${jndi:…}`), XXE | Direct compromise vector; one hit blocks on EVERY tier incl. `low` |
| High-confidence exploit | **70** | sqli, xss, cmdi (baseline), ssrf, ssti, nosqli, path_traversal, header_injection (CRLF) | Unambiguous attack; one hit reaches the per-request gate on critical (50) + high (70) |
| Privileged / mass-assignment | **60** | body mass-assignment | Strong abuse signal; blocks on critical/high/medium |
| Heuristic | **50** | header XFH, prototype pollution, open_redirect, recon_tool UA, brute_force | Context-dependent; blocks on critical only as a single hit, else accumulates |
| Body shape | **30–35** | body_oversize, body_deep_nesting | Weak alone; meaningful in combination |
| Probe / canary | **25** | recon_path | Single hit is information-only; rate / accumulation matters more than score |

Two gates consume these scores:

1. **Per-request gate (Option B, 2026-05-20):** block when the
   **sum** of this request's detector scores ≥ the matched tier's
   `risk_threshold` (critical 50 / high 70 / medium 80 / low 90). A
   lone `sqli=70` blocks on critical+high; two probes (`recon_path 25`
   + `recon_tool 50` = 75) block on critical+high too; an RCE
   (`Log4Shell 90`) blocks everywhere.
2. **Cumulative gate:** each malicious request also adds `max(signal)`
   to the per-`RiskKey` bucket (SEC-M003 — max, not sum, to avoid a
   single multi-class hit clamping the bucket). When the bucket
   crosses `challenge_at` / `block_at` (or the tier's
   `cumulative_*` overrides) the client is challenged/blocked even on
   later requests that don't directly trip a detector.

If operators could move scores arbitrarily, both gates lose their
calibration — a site that bumps `recon_path` to 70 makes every single
canary probe block on critical/high, defeating the "probing
accumulates, doesn't block" intent. Tune the **thresholds** (per-tier
`risk_threshold` + the cumulative trio), not the scores.

### Reason 2 — every safe outcome is reachable via the threshold trio

The same effect "the WAF is too aggressive on recon" is achievable by:
- raising `challenge_at` from 40 to 50, or
- moving `recon` to `log_only` mode via `set_profile`, or
- adding an Allow rule for the legitimate scanner UA.

The same effect "the WAF is too permissive on Log4Shell" is achievable by:
- lowering `challenge_at` from 40 to 30, or
- adding a `RaiseRisk(delta: 30)` rule scoped to the cmdi class, or
- moving `cmdi` overrides to a stricter tier.

Every desired outcome has at least one safe path. None of them require touching the score ladder.

### Reason 3 — score-edit drift is silent

If scores were UI-editable, an operator change to `recon_path = 50` would silently invalidate the [score-tier framework](#tldr) documentation, every dashboard tooltip that mentions it, and every internal calibration assumption. There's no good place to surface "your recon score is now 2× the documented value." Threshold edits, by contrast, are visible in one place — the Settings page banner — and the documentation says "tune `challenge_at` to taste."

### Reason 4 — score visibility is still important

The follow-up work on task #293 surfaces every detector's score (read-only) on the Detectors page so operators can **see** the calibration. Visibility ≠ editability — a thermostat shows you the temperature without letting you redefine "70°F."

---

## What operators CAN do (in order of safety)

### 1. Move a detector class to `log_only` (safest)

`log_only` mode runs the detector and writes the audit row, but doesn't add to the per-bucket risk score and doesn't gate the request. Use this when a detector is **noisy in your environment but you still want forensic visibility**.

**Dashboard:** Settings → Mode profile → set `policies: ["recon"]` to `log_only`.

**API:**
```sh
curl -sS -X PUT "$BASE/__waf_control/set_profile" \
  -H "Content-Type: application/json" \
  --data-binary '{"policies":["recon"],"mode":"log_only"}'
```

Reverting: `mode: "enforce"` puts it back.

**When to use:** "the recon detector is firing on legit `/sitemap.xml` crawls from CDN and inflating risk scores."

### 2. Adjust the global `risk.thresholds` trio

These knobs scale the **interpretation** of the score ladder without changing the ladder itself:

```yaml
risk:
  thresholds:
    challenge_at: 40   # default — drop to 30 for stricter posture
    block_at:     80   # default — drop to 60 for stricter posture
  strikes:
    block_at:     50   # permanent block at this many strikes
```

| Want | Change |
|---|---|
| Block sooner | Lower `challenge_at` / `block_at` |
| Block later | Raise them (max 100) |
| Permanent ban faster | Lower `strikes.block_at` |
| No permanent bans (honeypot setups) | Set `strikes.block_at: 999999` |

**Dashboard:** Traffic Gates → Cumulative IP risk thresholds (#3).

Threshold changes are hot-reloadable (audit-mutated; takes effect within one tick) — see [`config-hot-reload.md`](../control-plane/config-hot-reload.md).

**When to use:** "the WAF blocks our internal QA scanner after 3 probes — we want it to take 6 before blocking" → raise `challenge_at` and/or `block_at`. "we're seeing a credential-stuffing wave and need to ban faster" → enable Strike-Block on Traffic Gates → #2 then lower `strikes.block_at`.

### 2.5 Per-tier knobs (2026-05-10)

Each tier carries:

- `risk_threshold` (per-request block score) — **edit from dashboard**
  (Detectors & Tiers → Edit tier).
- `challenges_enabled` (boolean) — **edit from dashboard**
  (same modal). Defaults to `false`: challenges are opt-in. With
  `false`, IPs over the cumulative challenge threshold escalate
  straight to **block** (403) instead of getting a PoW puzzle.
  Useful for high-stakes tiers (admin, payments) and machine-only
  API tiers where PoW breaks clients. With `true`, the tier emits
  the regular 429 + PoW challenge body.
- `cumulative_challenge_at` / `cumulative_block_at` — **API-only
  per-tier overrides** (R3, 2026-05-10). The wire shape accepts
  per-tier values; the dashboard does **not** surface inputs for
  them because per-tier cumulative tuning is a niche need. By
  default, every tier inherits the global thresholds edited on
  Traffic Gates → #3. If you have a real reason for per-tier
  cumulative thresholds (e.g. stricter Critical tier than the
  global default), `PUT /api/tiers/<name>` accepts the fields:

```json
{
  "pipeline": [...],
  "risk_threshold": 50,
  "block_threshold": 100,
  "cumulative_challenge_at": 25,
  "cumulative_block_at": 50,
  "challenges_enabled": false
}
```

**Decision flow** for a single request (three independent gates, first one fires):

1. **Traffic Gates** (global, before tier matching) — access list, strike-block, rate-limit, DDoS.
2. **Per-request gate** (this tier's `risk_threshold`) — block when this single request's detector scores sum ≥ threshold.
3. **Cumulative IP history gate** (this tier's `cumulative_*`) — block / challenge when the IP's running cumulative score crosses thresholds. With `challenges_enabled = false`, the challenge rung is removed and crossings escalate straight to block.

`X-WAF-Risk-Score` always reports the cumulative IP score (contract §5.1) regardless of which gate fired the action.

### 3. Add a custom rule with `RaiseRisk(delta)` (per-route or per-condition)

The rule engine (see [`security-engine.md`](../security/security-engine.md)) lets you bias scoring on a specific route, header, IP, ASN, or any combination. Unlike global threshold tuning, this is **scoped** — the rest of the site keeps default behaviour.

```yaml
rules:
  - id: "boost-cmdi-on-admin"
    when:
      route: "/admin/**"
      detectors: ["command_injection"]
    actions:
      - type: "raise_risk"
        delta: 25       # Log4Shell now effectively scores 85, blocks immediately
```

**Dashboard:** Rules page → New rule.

**When to use:** "we want any cmdi hit on `/admin/**` to block on first attempt without lowering thresholds globally" → scoped `RaiseRisk(25)` on `command_injection`.

### 4. Per-tier detector overrides

Different routes have different needs. The Detectors page lets you turn a class **off** for a specific tier (Low / Medium / High / Critical) without affecting the rest. The class still runs at the global level — the override only suppresses signals for requests classified to that tier.

**Dashboard:** Detectors → Edit row → tier-override checkboxes.

**API:**
```sh
curl -sS -X PUT "$BASE/api/detectors" \
  -H "Content-Type: application/json" \
  --data-binary '{"overrides":{"low":{"recon":false}}}'
```

**When to use:** "our Low-tier static-asset endpoints serve `/sitemap.xml` to crawlers and we don't want recon to fire on them."

### 5. Operator allowlists on specific detectors

Some detectors carry built-in allowlists for legitimate destinations:

| Detector | Allowlist knob | What it does |
|---|---|---|
| `open_redirect` | `cfg.detectors.open_redirect.allowed_domains` | Suppresses the signal when the redirect target host matches a literal hostname or `*.example.com` glob |
| `ssrf` | (built-in) | Always blocks loopback / link-local / private — no operator override |
| `recon` | (built-in) | `/health`, `/actuator/health`, `/actuator/info`, `/metrics` (bare) — operator-hosted endpoints stay green by default |

`open_redirect.allowed_domains` is **boot-time only** — runtime allowlist updates require a `waf reload` (see [`zero-downtime-ops.md`](../control-plane/zero-downtime-ops.md)).

### 6. Move to a different production profile

The three production profiles in [`config/profiles/`](../../config/profiles/) — `prod-balanced.yaml`, `prod-high-throughput.yaml`, `prod-strict.yaml` — encode entire calibration sets (thresholds + per-detector toggles + audit retention). If you find yourself making three or more individual tweaks to `prod-balanced.yaml`, consider whether `prod-strict.yaml` (lower thresholds, longer audit retention) or `prod-high-throughput.yaml` (higher thresholds, fewer detectors) is closer to what you want.

See [`profiles.md`](./profiles.md) for the empirical comparison + per-knob trade-off table.

---

## Operator action map — by symptom

| Symptom | First thing to try | Then try | Last resort |
|---|---|---|---|
| Detector firing on legitimate traffic | `log_only` for that detector class | Per-tier override on the affected tier | Allow rule for the specific UA / route |
| WAF blocking too aggressively | Raise `challenge_at` to 50 | Raise `block_at` to 90 | Move from `prod-strict` to `prod-balanced` profile |
| WAF blocking too permissively | Lower `challenge_at` to 30 | Add `RaiseRisk(25)` rule on the affected detector | Move from `prod-balanced` to `prod-strict` profile |
| Scanner from internal IP being banned | Whitelist the IP via Allow rule | Move the `recon` detector to `log_only` | Strikes-window reset — surgical (`POST /api/risk/reset_key` for one bucket) or IP-wide (`POST /api/risk/<ip>/reset`) |
| OAuth callback to partner domain blocked | Add domain to `open_redirect.allowed_domains` | (rare) move `open_redirect` to `log_only` | (rare) disable `open_redirect` for the OAuth route via per-tier override |
| Specific detector should escalate faster on `/admin/**` | `RaiseRisk(delta: 25)` rule scoped to route | Lower `block_at` globally | (don't) edit the score |
| Detector seems too noisy site-wide | Read its per-detector doc — many take a config knob | `log_only` until you've audited the noise | Raise thresholds globally |

---

## Validation before changes go live

```sh
# Confirm the YAML parses + lints cleanly.
target/release/waf validate --config config/active.yaml

# Run the simulator on the candidate config — drives synthetic traffic
# from the audit corpus and reports per-class fire rates.
target/release/waf simulate --config config/candidate.yaml --duration 60s

# Once happy, hot-reload (no restart needed for thresholds, mode, or
# per-tier overrides; allowed_domains needs a full reload).
target/release/waf reload
```

The simulator (also reachable on the Simulator page) lets you compare candidate vs current config side-by-side before turning anything on. Use it for any threshold change ≥10 points or any per-tier override.

---

## When to escalate to engineering

The score ladder being non-editable is a **policy** decision, not a technical limitation. If your environment genuinely needs a different ladder — e.g. an internal API where `recon_path` should weigh equal to `sqli` because every `recon_path` is an attempted breach — open an issue describing the use case. The right answer is usually "use a custom rule with `RaiseRisk`," but if the same scoping shows up across many operators, the calibration table itself can be revised.

What you should NOT do:

- ❌ Patch the source to change `Signal { score: ... }` literals — drifts on every upgrade.
- ❌ Run a fork with a different score table — your audit logs and metrics labels will diverge from upstream's documented meanings.
- ❌ Add a feature flag that lets the score table be loaded from YAML without a corresponding doc + simulator updates — the calibration framework breaks silently.

The right path is:
1. Document the symptom (what's the false-positive / false-negative rate, on which detector, with what corpus).
2. Run the simulator on the candidate fix.
3. Open an issue with the calibration table change request + simulator output.

---

## Cross-refs

- [`security/security-engine.md`](../security/security-engine.md) — pipeline + risk-weight ladder + threshold trio.
- [`security/risk-scoring.md`](../security/risk-scoring.md) — per-bucket score accumulation, strikes window, ASN modifiers.
- [`operator/profiles.md`](./profiles.md) — three production profiles + per-knob trade-off table.
- [`control-plane/dashboard.md`](../control-plane/dashboard.md#simulator) — simulator usage.
- [`control-plane/config-hot-reload.md`](../control-plane/config-hot-reload.md) — what's hot-reloadable vs reload-required.
- [`control-plane/enterprise/api.md`](../control-plane/enterprise/api.md) — `/__waf_control/set_profile`, `/api/detectors`, `/api/rules` endpoints.
