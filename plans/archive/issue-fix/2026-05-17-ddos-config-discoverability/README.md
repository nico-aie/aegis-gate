# DDoS config discoverability

> **Reported by:** operator review on 2026-05-17.
> **Symptom:** `ddos:` stanza is missing from every canonical config
> file (`config/dev.yaml`, `config/prod.yaml`, `config/profiles/*.yaml`,
> `waf.yaml`). An operator reading any of those files would not know
> that DDoS protection exists, is enabled, or has tunable knobs.

## What's actually broken

Nothing functional. `Config.ddos` is declared `#[serde(default)]` in
`crates/aegis-core/src/config.rs:148`, so when no YAML stanza is
present, `DdosConfig::default()` is applied at boot:

| Knob | Default |
|---|---:|
| `enabled` | `true` |
| `observe_only` | `false` (enforce) |
| `per_ip_limit` | `1000` |
| `per_ip_window_s` | `10` |
| `block_ttl_s` | `300` |
| `spike_multiplier` | `3.0` |
| `tightened_per_ip_rps` | `20` |

The 2026-05-14 5k stress run boot log confirms the gate installs:
`ddos: runtime installed (observe-only Phase 1) observe_only=false
per_ip_limit=1000 spike_multiplier=3.0`.

## Why this matters anyway

Three reasons silent defaults are bad for an operator-facing gate:

1. **Discoverability.** A new operator scanning `config/prod.yaml`
   sees `rate_limit:`, `risk:`, `detectors:` — they have no way to
   know DDoS exists as a separate gate, nor how to tune it.
2. **Posture-by-profile.** The three production profiles
   (`prod-balanced`, `prod-strict`, `prod-high-throughput`) already
   diverge on `risk.thresholds`, `rate_limit.limit`, and the
   `detectors` mask. They should diverge on DDoS posture too — but
   the absent stanza means they all run with the same baseline
   defaults, undermining the profile contract.
3. **Test-config gotcha.** `tests/hackathon/configs/prod-balanced-5k.yaml`
   already disables `brute_force` + relaxes `rate_limit` + raises
   `risk.thresholds` to handle shared-source-IP synthetic load.
   It does NOT disable the DDoS gate — which trips per-IP-burst on
   the first 1000 requests in 10 s. At 60k RPS, that's the first
   17 ms. The 2026-05-14 run's 99.99% "legit failure" rate is
   almost certainly this gate firing, not the WAF→upstream
   SendRequest theory I floated in the run report.

## Scope

Add explicit `ddos:` stanzas to all canonical configs with
environment-appropriate values. Co-locate inline comments pointing
at `docs/security/ddos-protection.md`. **No code changes.**

## Plan

### Phase 1 — surface explicit `ddos:` in the seven canonical configs

| File | `enabled` | `observe_only` | `per_ip_limit` | `per_ip_window_s` | `block_ttl_s` | `spike_multiplier` | `tightened_per_ip_rps` | Rationale |
|---|---|---|---:|---:|---:|---:|---:|---|
| `config/dev.yaml` | `true` | `false` | `1000` | `10` | `300` | `3.0` | `20` | Defaults made explicit; dev should match prod posture so behaviour parity holds. |
| `waf.yaml` | (mirrors `dev.yaml`) | | | | | | | Same file shape as `dev.yaml`. |
| `config/prod.yaml` | `true` | `false` | `1000` | `10` | `300` | `3.0` | `20` | Production template — defaults explicit so forks see the knobs. |
| `config/profiles/prod-balanced.yaml` | `true` | `false` | `1000` | `10` | `300` | `3.0` | `20` | Default profile; balanced threshold matching docs. |
| `config/profiles/prod-strict.yaml` | `true` | `false` | **`200`** | `10` | **`600`** | **`2.0`** | **`10`** | Tighter posture matches existing profile shape (lower `risk.thresholds`, tighter `rate_limit`). |
| `config/profiles/prod-high-throughput.yaml` | `true` | `false` | **`5000`** | `10` | **`180`** | **`4.0`** | **`100`** | Looser per-IP limit + shorter block — matches the larger `rate_limit` bucket (30k/min) the profile already uses. |
| `tests/hackathon/configs/prod-balanced-5k.yaml` | **`false`** | — | — | — | — | — | — | Single-source-IP synthetic load can't honour the per-IP burst gate. Same reasoning that already disables `brute_force` + relaxes `rate_limit` + raises `risk.thresholds`. |

Each block adds an inline comment block:
- pointer to `docs/security/ddos-protection.md`
- one-liner per knob
- profile-specific rationale (e.g. "tighter — compliance posture")

### Phase 2 — doc cross-link

In `docs/security/ddos-protection.md` § "Configuration", add a
profile-comparison table mirroring the values above so the doc
becomes a single source of truth for "what does my profile pick?".

### Phase 3 (deferred) — startup log line

`aegis-proxy/src/run.rs:716` currently logs only `per_ip_limit` and
`spike_multiplier`. Extend it to print all four numeric knobs +
`observe_only`. Tiny PR; not blocking this plan.

## Out of scope

- **Behaviour changes** — the defaults already apply; making them
  explicit doesn't change runtime semantics.
- **Cluster-wide spike-mode broadcast** — still deferred behind the
  ha-clustering work (already documented under "Future work" in
  the existing doc).
- **Phase 3 (startup-log expansion)** — small enough to land as a
  separate one-line PR.

## Verification

1. `cargo build -p aegis-bin` — no compile changes, but sanity.
2. `cargo run -p aegis-bin -- run --config config/dev.yaml` —
   confirm boot log still emits `ddos: runtime installed (...)`
   line with the explicit values (proves serde parsed the new
   block correctly and didn't fall through to defaults).
3. `cargo run -p aegis-bin -- run --config tests/hackathon/configs/prod-balanced-5k.yaml` —
   confirm boot log emits `ddos: cfg.ddos.enabled = false — detector
   not installed` instead.
4. Re-run the 5k stress test (`tests/hackathon/run-prod-balanced-5k.sh`)
   and verify the legit-success rate climbs back to >95% (was
   0.01% on 2026-05-14 with the gate active).

## Files touched

```
config/dev.yaml
config/prod.yaml
config/profiles/prod-balanced.yaml
config/profiles/prod-strict.yaml
config/profiles/prod-high-throughput.yaml
waf.yaml
tests/hackathon/configs/prod-balanced-5k.yaml
docs/security/ddos-protection.md
```

Eight files, all additive comments + one new YAML block each. No
Rust changes.
