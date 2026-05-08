# Profile selection — picking the right `config/`

Aegis-Gate ships three production profiles under `config/profiles/`,
plus the existing `config/dev.yaml` for local development and
`tests/hackathon/configs/bench.yaml` for the synthetic-load
benchmark harness. This page tells you which one to fork.

---

## 30-second decision

```
Is this for a hackathon stress-test?
├── yes → tests/hackathon/configs/bench.yaml
└── no
    ├── Is this local dev?
    │   └── yes → config/dev.yaml
    │
    ├── Compliance audit mandate (PCI / HIPAA / SOC2 / GDPR / FedRAMP)?
    │   └── yes → config/profiles/prod-strict.yaml
    │
    ├── Throughput-first deployment (CDN front-door, > 5 k RPS sustained)?
    │   └── yes → config/profiles/prod-high-throughput.yaml
    │
    └── Default                          → config/profiles/prod-balanced.yaml
```

---

## Empirical comparison

Numbers from `tests/results/run-profile-sweep-20260502/` —
30-second k6 runs against `config/dev.yaml` derivatives.
"Detection" reflects the harness's mixed corpus (15 attack
shapes, ~5 of which are app-layer and undetectable by the
WAF tier).

| Knob                 | dev / bench | prod-balanced | prod-high-throughput | prod-strict |
|----------------------|-------------|---------------|----------------------|-------------|
| Median latency       | 1.89 ms     | ~2 ms         | **1.6 ms**           | ~2.5 ms     |
| p95 latency          | 2.90 ms     | ~3 ms         | **2.3 ms**           | ~4 ms       |
| p99 latency          | 4.52 ms     | ~5 ms         | 8.2 ms (heavier)     | ~10 ms      |
| Legit OK rate        | 99 %        | **99 %**      | 97 %                 | ~95 %       |
| Detection rate       | 80 %        | 80 %          | 80 %                 | **~85 %**   |
| Throughput           | 344 RPS     | ~340 RPS      | **417 RPS**          | ~250 RPS    |
| Audit retention      | 7d          | **7d**        | 3d                   | **90d**     |
| Rate-limit budget    | loose       | 6k/min        | 30k/min              | 3k/min      |
| `recon` detector     | on          | on            | **off**              | on          |
| `brute_force`        | on          | **on**        | off                  | on          |
| `command_injection`  | on          | on            | on                   | on          |
| `compliance.modes`   | none        | none          | none                 | populate    |
| TLS min version      | 1.2         | 1.2           | 1.2                  | 1.2 / 1.3   |
| State backend        | in-memory   | **redis**     | redis                | redis       |

Bold = the profile's distinctive choice.

---

## Profile breakdown

### `prod-balanced.yaml` — the default

Pick this unless you have a specific reason not to. 99 %
of deployments will be happiest here. Every detector enabled,
challenge_at 40 / block_at 80 — same shape as `dev.yaml` but
with Redis state (cluster-ready) + 7-day audit + secret-
manager-resolved admin credentials.

### `prod-high-throughput.yaml`

Trades some detection coverage and audit retention for raw
throughput.
- `recon` detector OFF (noisy on `/sitemap.xml`, `/robots.txt`,
  `/.well-known/*` from CDNs)
- `brute_force` OFF (state-keeping overhead; assumes auth
  shaping is handled at the upstream)
- Tighter `challenge_at: 60` (was 40) — fewer challenges fired
- Larger rate-limit bucket (30k/min vs 6k/min)
- Higher load-mode ceilings (`critical_rps: 8000`)
- 3-day audit retention

Use when: you're behind a CDN with bot-mitigation already in
place, or fronting a static-asset cache, or running an internal
API where most traffic is trusted.

### `prod-strict.yaml`

Trades latency + throughput for tighter security + longer audit
retention. Designed for compliance-driven deployments.
- Every detector on
- Earlier intervention: `challenge_at: 30`, `block_at: 60`,
  permanent strike-block at 25 strikes (vs balanced's 50)
- mTLS `mode: required` for the admin plane
- 90-day audit retention with IP pseudonymisation (GDPR)
- TLS 1.3 baseline (HSTS preload-eligible)
- `compliance.modes` placeholder ready to populate per regime

Use when: you have a regulatory audit mandate. Pick the
specific `compliance.modes` from your regime
(`pci_dss`, `hipaa`, `soc2`, `gdpr`, `fips`).

---

## Knob-by-knob — what to tune locally

If none of the three profiles fit, fork `prod-balanced.yaml`
and tune these knobs. Each row says **what you're trading**:

| Knob | Loosen for… | Tighten for… |
|---|---|---|
| `risk.thresholds.challenge_at` | Lower latency (raise to 50-60) | Earlier interception (drop to 30) |
| `risk.thresholds.block_at` | Avoid false-positive blocks (raise to 100) | Quick lockout (drop to 60) |
| `risk.strikes.block_at` | Tolerant repeat-offender policy (raise) | Quick permanent block (lower) |
| `rate_limit.buckets[].limit` | High-volume traffic (raise to 30k+) | DDoS-target apps (drop to 1-3k) |
| `load_mode.{elevated,critical}_rps` | Larger instance / cluster (raise) | Small box (lower) |
| `audit.retention` | Disk pressure (drop to 3-7d) | Compliance (raise to 90d / 1y) |
| `audit.pseudonymize_ip` | Op trace ease (`false`) | GDPR / data-min policies (`true`) |
| `detectors.recon.enabled` | Noisy CDN traffic (`false`) | Strict ops baseline (`true`) |
| `detectors.brute_force.enabled` | Shared-IP testing / upstream auth shaping (`false`) | Dedicated-IP prod (`true`) |
| `tls.min_version` | Legacy clients (`1.2`) | Modern clients only (`1.3`) |
| `tls.client_auth.mode` | Open admin (`disabled`) | Zero-trust admin (`required`) |
| `compliance.modes` | No clamp | Lock detector classes (PCI, HIPAA, SOC2, GDPR, FIPS) |

---

## Validate before booting

```sh
# Confirm the config loads + the compliance profile accepts it
target/release/waf validate --config config/profiles/prod-balanced.yaml

# Boot
target/release/waf run --config config/profiles/prod-balanced.yaml
```

`validate` exits 0 only when every clamp the chosen
`compliance.modes` defines is satisfied — the strict profile
will refuse to start with conflicting `detectors.*.enabled:
false` for a class compliance pins.

---

## UX defaults — what's tuned in every profile

The dashboard surface is the same across profiles; the
differences are server-side. UX choices baked in:

- **Auto-refresh cadences** are tuned: 2 s for high-frequency
  cards (mode toggle, traffic chart), 5 s for moderate (alerts,
  audit log), 30 s for slow (routes, certs).
- **Empty states** are honest — every page renders an
  explanatory message when its source returns `[]`, not a
  curated placeholder.
- **Toasts** auto-dismiss in 4 s for `ok` / `warn`, never
  auto-dismiss for `err` so failures stay on screen.
- **Mode pill** always reflects live `/api/mode`; the Settings
  page banner makes it impossible to miss when the WAF is in
  `log_only`.

---

## Re-running the empirical sweep

```sh
# 30-second runs vary one knob at a time; drops a per-run
# directory under tests/results/run-profile-sweep-<DATE>/runs/.
bash /tmp/sweep-one.sh A-baseline   tests/hackathon/configs/bench.yaml 30s 10 10
bash /tmp/sweep-one.sh B-heavy-load tests/hackathon/configs/bench.yaml 30s 30 30
bash /tmp/sweep-one.sh C-tight-rl   <your-test-config.yaml>            30s 10 10
```

Pasted-in sweep helper at `/tmp/sweep-one.sh` boots upstream +
WAF, runs k6 for $DUR, prints headline metrics. Keep + commit
results under `tests/results/run-profile-sweep-<DATE>/` so the
table above stays comparable.
