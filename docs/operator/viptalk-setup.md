# VipTalk Alert Setup

Step-by-step for wiring SLO alerts to a real VipTalk room. Closes
the dispatch loop landed in CI-T7 — the engine evaluates every
30 s and pushes newly-fired alerts via HTTP POST.

## When this matters

The SLO engine is always running in the background, recording
samples from the audit bus and computing burn rates. **Without
VipTalk credentials configured, alerts still fire — they just
land in the WAF's tracing log, not in your team's chat.**

Wire VipTalk when you want operator paging.

## Prerequisites

| Need | Where to get it |
|---|---|
| **Bot token** | Ask your VipTalk workspace admin — usually shaped `xxxxxxxxxxxxxx` (32+ chars) |
| **Room ID(s)** | Right-click a room in the VipTalk client → "Room info" → copy the `!XXXX:matrix.viptalk.org` ID |
| **`alerts` Cargo feature** | Build with `cargo build -p aegis-bin --release --features "redis alerts"` |

The default receiver in `slo::default_receivers()` points at the
project's UAT bot and a hard-coded fallback room — **fine for dev,
not what you want in production.** Override via env vars below.

## Setup

### 1. Build with the `alerts` feature

```sh
# Includes the reqwest HTTP client used by `dispatch::send_viptalk`
cargo build -p aegis-bin --release --features "redis alerts"

# Or the full set
cargo build -p aegis-bin --release --features "redis alerts geoip taxii http3"
```

Without the `alerts` feature, `dispatch::send_alert` logs the
alert at `tracing::warn` and counts it as "external" so an
off-box dispatcher (Alertmanager → operator-side webhook) can
still pick it up.

### 2. Export the env vars before `waf run`

```sh
# REQUIRED for production routing
export AEGIS_VIPTALK_BOT_TOKEN="<your-bot-token>"
export AEGIS_VIPTALK_ROOM_IDS="!ROOM_ONE:matrix.viptalk.org,!ROOM_TWO:matrix.viptalk.org"

# Optional — only needed if your VipTalk deployment runs on a
# different host (e.g. a private/UAT cluster). Default is the
# public matrix.viptalk.org production endpoint.
export AEGIS_VIPTALK_API_BASE="https://api.viptalk.org"
```

| Variable | Purpose | Default |
|---|---|---|
| `AEGIS_VIPTALK_BOT_TOKEN` | Bot identity for `https://<api>/v1/bot/<token>/sendMessage` | UAT-only fallback (`slo::DEFAULT_VIPTALK_BOT_TOKEN`) |
| `AEGIS_VIPTALK_ROOM_IDS` | Comma-separated room IDs; one HTTP POST per room | UAT-only fallback room |
| `AEGIS_VIPTALK_API_BASE` | API hostname (no trailing slash) | `https://api.viptalk.org` |

For systemd, drop these into the unit file's `Environment=`
lines or `EnvironmentFile=/etc/aegis/viptalk.env`. For Docker,
use `--env-file` or k8s `Secret`-mounted env. Never commit the
bot token.

### 3. Boot the WAF

```sh
target/release/waf run --config config/prod.yaml
```

Look for this log line near startup:

```
INFO aegis_proxy: slo eval task spawned (interval=30s, receivers=1)
```

(Exact line wording may differ; the receiver count > 0 confirms
the loop is wired.)

## Smoke test — confirm delivery without waiting for a real burn

The engine fires alerts on real burn-rate exceedance, which can
take an hour of unhealthy traffic to surface. Two faster ways
to verify the wiring:

### A. Force a fast burn with synthetic samples

The test harness in `crates/aegis-control/src/slo.rs` covers this
under `#[cfg(test)]`. To exercise the **live** code path against
your real bot:

```sh
# Run a tiny binary that pushes 100 % error samples for 10 s,
# then evaluates. Outputs the dispatch summary as JSON.
cargo run -p aegis-bin --features alerts --bin waf -- \
    slo simulate-burn --sli data_plane_availability --duration 10s

# Output:
#   dispatched 1 alert
#   delivered:  ["default-viptalk"]
#   external:   []
#   failed:     []
```

If `delivered` lists your receiver name and your VipTalk room
shows the message within ~5 s, the wire is up.

> **Note:** `slo simulate-burn` is a debug subcommand wired
> behind a build flag. If your build doesn't have it, fall back
> to method B.

### B. Curl VipTalk directly with the same payload shape

`dispatch::send_viptalk` builds a form-encoded POST. You can
issue the same request by hand to isolate WAF wiring from
VipTalk credentials:

```sh
curl -i -X POST \
  -d "text=Aegis WAF — smoke test from $(hostname)" \
  -d "roomIds=$AEGIS_VIPTALK_ROOM_IDS" \
  "$AEGIS_VIPTALK_API_BASE/v1/bot/$AEGIS_VIPTALK_BOT_TOKEN/sendMessage"
```

Expect `HTTP/1.1 200 OK` and a JSON body. If this succeeds but
the WAF doesn't deliver, check that:

- `make build` was run with `--features "alerts"`
- The WAF's stdout shows `slo alert dispatched ... delivered=1`
- No firewall rules block the WAF host from reaching
  `api.viptalk.org`

## What the alert message looks like

`format_alert_text` in `crates/aegis-control/src/slo/dispatch.rs`
formats one line per alert:

```
🚨 Aegis WAF SLO breach
SLI: DataPlaneAvailability
severity: page
window: 1h
burn rate: 12.4× (consumed 124% of budget)
runbook: https://runbooks.aegis.local/slo/DataPlaneAvailability/1h
```

Operators click the runbook URL for response procedures (you
own that URL — set it via the SLO config or accept the default
template).

## Disabling VipTalk routing

To run without VipTalk delivery:

```sh
# Either: build without the `alerts` feature
cargo build -p aegis-bin --release --features redis

# Or: empty the env vars so default_receivers() falls through
export AEGIS_VIPTALK_BOT_TOKEN=""
export AEGIS_VIPTALK_ROOM_IDS=""
```

Either path leaves the SLO engine running and the alerts list
populated — only the chat fan-out is silenced. Operators can
still see firing alerts on the dashboard's **Tracking** page.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Logs show "viptalk delivery skipped" | Built without `--features alerts` | Rebuild: `cargo build -p aegis-bin --release --features "redis alerts"` |
| Logs show "viptalk delivery failed" | Bot token wrong, room ID wrong, network blocked | Verify with the curl smoke (method B) above |
| No alerts ever fire | Engine has 100 % SLI samples (no errors yet) | Either wait for real burn, or force samples via the test harness |
| `delivered=0, external=1` | The default `Webhook` / `Pagerduty` variants are descriptive-only | Either switch to `VipTalk` receiver kind, or wire an off-box dispatcher |
| Alert spam | Burn-rate thresholds too sensitive | Tune `SloObjective.burn_rates[*].budget_pct` in your config; operators commonly bump from 2 % → 5 % to reduce noise |

## Where to look in the code

| Path | What |
|---|---|
| `crates/aegis-control/src/slo.rs` | Engine, `default_receivers()`, env-var fallbacks |
| `crates/aegis-control/src/slo/dispatch.rs` | `send_viptalk()` HTTP POST + `format_alert_text()` |
| `crates/aegis-proxy/src/lib.rs` (search `slo eval`) | The 30 s eval task that pushes alerts to dispatch |
| `tests/api/openapi-shape.sh` | Validates `/api/alerts` shape against the contract |
| `docs/control-plane/api.openapi.yaml#/components/schemas/AlertsResponse` | Wire shape consumed by the dashboard |
