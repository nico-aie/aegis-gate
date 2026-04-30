# Operator docs

Hands-on guides for running, configuring, and observing Aegis-Gate.
Start here if you have a binary and need to make it do something.

| Doc | When you need it |
|---|---|
| [soc-runbook.md](./soc-runbook.md) | **SOC team cheat sheet** — config → build → deploy → login → test → monitor, plus 4 incident playbooks |
| [usage.md](./usage.md) | Day-1 bring-up + day-2 runbook (config, security toggles, hot-reload, audit verification) |
| [cli.md](./cli.md) | Authoritative CLI reference for the `waf` binary — every subcommand, flag, exit code |
| [benchmark-mode.md](./benchmark-mode.md) | Opt-in diagnostic mode — per-request `X-Aegis-*` response headers + dashboard panels |

For testing the running system end-to-end, see
[`../../tests/TESTING.md`](../../tests/TESTING.md).
