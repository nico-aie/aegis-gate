# Copilot Live-Posture window labels + DDoS enforce/log-only toggle from the UI

**Status:** 🟢 A + B shipped (TDD, `feat/copilot-posture-labels-ddos-mode-toggle`, 2026-07-02)

Notes: enforce = explicit override (predictable even under a global
log_only default); enforce is single-click (restorative), log-only is
two-click armed (reduces protection). Live Posture got per-tile window
sublabels + a header caption. Backend helper `set_feature_mode` TDD'd
(4 tests); endpoint `PUT /api/gates/ddos/mode` mirrors handle_mode_put.
**Date:** 2026-07-02
**Reported by:** Nico — (1) Copilot "Live posture" reads 0/none while the 60-min
brief is full → the tiles' real time windows aren't labeled; (2) after a
`set_profile log_only` on the DDoS gate there's no way to re-enforce from the UI.

---

## Findings (verified in code, 2026-07-02)

### A — Live Posture tiles mix time windows without saying so

`CopilotPosture` (`pages.jsx:16272`) pulls from four sources with **different
windows**, all under one "Live posture" heading + a "Window: 60 min" selector:

| Tile | Source | Actual window |
|---|---|---|
| Req rate | `/api/stats` `request_rate` | **last 10 s** (`REQUEST_WINDOW`, `stats.rs:36`; `total / 10s`, `:320`) |
| Block rate | `/api/stats` `block_rate_pct` | same 10 s |
| Blocked | `/api/stats` `blocks_total` | **lifetime** (since boot; reset by `reset_state`) |
| Active alerts | `/api/incidents` | firing now |
| Top attack types | `/api/attacks/by-detector?window=<sel>` | the selected window |
| Top attackers | `/api/attacks/top` | the selected window |

So "60 min" only scopes the two attack lists (and the brief/campaigns) — NOT the
rate/blocked tiles. An idle-right-now WAF with earlier traffic shows `0/s`, `0%`,
and (if `blocks_total` was reset or the recent "blocks" were log-only intents)
`Blocked 0`, while the brief counts everything over the hour. Nothing is broken;
the labels just imply one window for tiles that have three.

### B — DDoS `set_profile log_only` is not reversible from the dashboard

The DDoS gate can be in log-only two independent ways, shown as two badges
(`pages.jsx:13673-13680`):
- **OBSERVE-ONLY** — the config `ddos.observe_only` flag. Already toggleable from
  the DDoS card's threshold form (`DdosPutBody.observe_only`, `gates.rs:154`).
- **LOG-ONLY (set_profile)** — an interop `ModeStore` feature override on `ddos`
  (`data.effective_mode === 'log_only'`, resolved by `mode_for_rule("ddos")`,
  `admin_get.rs:1092`). This is the one in the screenshot.

The `ModeStore` override is set only via `POST /__waf_control/set_profile`, which
is **loopback-only** (`admin_dispatch.rs:125`) + control-secret gated — no
dashboard path. `PUT /api/mode` flips the *global* default (and clears overrides)
but that's all-or-nothing. There is no per-feature mode control on the admin
surface. `ModeStore::set_feature(feature, mode)` (`mode.rs:110`) is the primitive;
`handle_mode_put` already shows the admin pattern: mutate `rt.modes` +
`rt.control.publish_modes()` to converge (`admin_mutate.rs:139-158`).

## Plan

### Part A — Live Posture labeling (frontend only, no backend)

1. Per-tile window sublabels in `CopilotPosture`:
   - Req rate / Block rate → `now` (tooltip: "instantaneous — last 10 s").
   - Blocked → `since boot` (tooltip: lifetime counter; reset by state reset).
   - Active alerts → `firing now`.
   - Top attack types / Top attackers → keep, but the section makes clear these
     follow the Window selector.
2. Reframe the header: "Live posture" stays, but add a one-line caption that the
   **Window selector scopes the attack lists + brief**, while the top tiles are
   live/lifetime. Small, unambiguous copy — no logic change.
3. Optional: when `request_rate === 0` but the window has attack-list data,
   a hint ("idle now — see the brief for the full window") so the empty tiles
   don't read as broken.

### Part B — DDoS enforce/log-only toggle (backend TDD + frontend)

1. **Backend, TDD** — testable helper in `api/gates.rs`:
   `set_feature_mode(modes: &ModeStore, feature: &str, mode_str: &str)
   -> Result<Mode, String>` — parse `enforce|log_only` (reject others), call
   `modes.set_feature(feature, mode)`, return the applied `Mode`. RED→GREEN:
   enforce/log_only round-trip via `mode_for_rule(feature)`; invalid string →
   `Err`; unknown mode leaves the store unchanged.
2. **Endpoint** `PUT /api/gates/ddos/mode` (`handle_ddos_mode_put`, audit-mutated,
   CSRF-gated — mirrors `handle_mode_put`): body `{ "mode": "enforce" | "log_only" }`,
   calls the helper on `rt.modes` for feature `"ddos"`, then
   `rt.control.publish_modes().await` so peers converge; 200
   `{ ok, mode, effective_mode }`. 503 when `services.interop` isn't wired
   (test bundle). Dispatch next to the other `/api/gates/*` routes
   (`admin_dispatch.rs:282`).
   - Semantics: `enforce` sets an **explicit** Enforce override (not "clear"), so
     the gate enforces even if the global default is log_only — matches the
     operator's intent ("enforce DDoS again"), and is symmetric with the reverse.
3. **Frontend** — DDoS gate card: when `effective_mode === 'log_only'` (the
   set_profile badge), show an **"Enforce now"** button that PUTs
   `{mode:'enforce'}`; when enforcing, a subtle **"Switch to log-only"** for
   symmetry (two-click arm on the enforce→log-only direction since it *reduces*
   protection; enforce is restorative → single click). `data.jsx` wrapper
   `ddosModePut(mode)`. Reload the gate view after.
   - Leave the config `observe_only` toggle (thresholds form) as-is — this new
     control targets the interop mode only; note both in the card so the two
     dry-run sources aren't conflated.

## TDD

- **B (Rust, RED→GREEN):** `set_feature_mode` cases above in `api/gates.rs`.
  `cargo test --workspace` green baseline holds.
- **A + B frontend (JSX):** no runtime harness — `build.sh` hook-guard + manual:
  DDoS in set_profile log_only → "Enforce now" → badge flips to ENFORCING, a
  tripping IP now 503s; Live Posture tiles show their window sublabels.

## Acceptance

- [ ] Live Posture tiles state their real window (now / since boot / selected).
- [ ] `PUT /api/gates/ddos/mode {mode:"enforce"}` flips the `ddos` feature
      override to enforce, publishes fleet-wide, and the gate GET reports
      `effective_mode: "enforce"`.
- [ ] DDoS card shows "Enforce now" in set_profile log-only and re-enforces on
      click (no loopback/curl needed); reverse toggle is arm-to-confirm.
- [ ] Invalid mode string → 400/Err; interop-absent → 503.
- [ ] `cargo test --workspace` green; `build.sh` green.

## Risks / notes

- **Reduces-protection direction** (enforce→log-only) is the only risky action;
  gate it behind arm-to-confirm. Enforce is always safe (restorative).
- **In-memory mode store** — the override is not durable across restart (same as
  today's `set_profile`); it publishes to peers via `publish_modes` but a full
  fleet restart returns to config defaults. Out of scope to change here.
- No change to the enforcement/eval path — the toggle only writes the existing
  `ModeStore` the data plane already reads.

## Estimated complexity: LOW-MEDIUM
- A ~1h · B backend+TDD ~1.5h · B frontend ~1.5h
