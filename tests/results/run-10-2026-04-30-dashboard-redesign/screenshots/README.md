# Run-10 — Dashboard redesign screenshots

Per-page baselines for the **Aegis WAF Console** redesign,
captured 2026-04-30 against the release binary built from the
DD-T7 wire-up commit. One PNG per route; this is the visual
regression baseline that future redesign PRs should diff against.

## How to regenerate

```sh
# 1. Bring up the release binary against the dev config.
target/release/waf run --config config/waf.dev.yaml &

# 2. Once at /healthz/ready 200, run the capture script.
node tests/dashboard/capture-screenshots.mjs \
     --admin=http://127.0.0.1:9443

# 3. Diff against this directory; treat unexpected pixel deltas
#    as a regression, not progress.
```

The script logs in via `POST /admin/login` with the dev-config
admin/password (`aegis-test-1234`), then hash-routes through every
sidebar route and full-page screenshots at 1440×900 viewport.

## Coverage

| File | Route | Page |
|---|---|---|
| `overview.png`  | `#/overview`  | Operator overview (KPIs, attack origin globe, timeseries) |
| `live.png`      | `#/live`      | Live Feed (real `/dashboard/sse` stream) |
| `attacks.png`   | `#/attacks`   | Attack Events drilldown |
| `analytics.png` | `#/analytics` | Aggregate analytics |
| `audit.png`     | `#/audit`     | Audit Log w/ filters |
| `rules.png`     | `#/rules`     | Rule Manager (CRUD + hot-reload toast) |
| `tiers.png`     | `#/tiers`     | Tier Config |
| `blacklist.png` | `#/blacklist` | Blacklist |
| `whitelist.png` | `#/whitelist` | Whitelist |
| `settings.png`  | `#/settings`  | Settings |
| `tracking.png`  | `#/tracking`  | Tracking (SLO, certs, alerts, GitOps, peers) |
| `help.png`      | `#/help`      | Help & Guide |
