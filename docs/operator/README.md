# Operator docs

Hands-on guides for running, configuring, and observing Aegis-Gate.
Start here if you have a binary and need to make it do something.

| Doc | When you need it |
|---|---|
| [soc-runbook.md](./soc-runbook.md) | **SOC team cheat sheet** — config → build → deploy → login → test → monitor, plus 4 incident playbooks |
| [viptalk-setup.md](./viptalk-setup.md) | Wire SLO alerts to a real VipTalk room (env vars, smoke test, troubleshooting) |
| [usage.md](./usage.md) | Day-1 bring-up + day-2 runbook (config, security toggles, hot-reload, audit verification) |
| [cli.md](./cli.md) | Authoritative CLI reference for the `waf` binary — every subcommand, flag, exit code |
| [benchmark-mode.md](./benchmark-mode.md) | Opt-in diagnostic mode — per-request `X-Aegis-*` response headers + dashboard panels |
| [risk-tuning.md](./risk-tuning.md) | **What to do when a detector fires too much / too little** — why scores aren't UI-editable, and the safe knobs available (`set_profile log_only`, `risk.thresholds`, `RaiseRisk` rules, per-tier overrides, allowlists) |
| [traffic-gates.md](./traffic-gates.md) | **The four binary block-or-pass gates** that fire BEFORE the detector chain (access list, strike-block, rate-limit, DDoS) — operator workflow, tuning, and "why was my legit traffic blocked?" diagnostics |
| [profiles.md](./profiles.md) | Pick the right `config/profiles/*.yaml` — empirical comparison + per-knob trade-off table |

For testing the running system end-to-end, see
[`../../tests/TESTING.md`](../../tests/TESTING.md).
