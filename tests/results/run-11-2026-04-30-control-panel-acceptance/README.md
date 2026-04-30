# Run 11 — 2026-04-30 — Control Panel Full Acceptance

End-to-end acceptance of the Aegis WAF Console after the
CI-T1..T10 wave landed. Every dashboard page, every supporting
endpoint, every protocol, plus the SLO + VipTalk integration —
all tested against a live release binary.

## Headline

- **2,165 default-feature workspace tests pass** (2,232 with the
  `redis alerts geoip` feature trio).
- **22/22 dashboard-consumed endpoints serve real JSON.**
- **OpenAPI shape contract: 25/25 checks pass.**
- **Multi-protocol smoke: HTTP/1.1 ✅ HTTP/2 ✅ WebSocket ✅
  gRPC ✅** (HTTP/3 skipped — operator-side curl).
- **Round-1 acceptance: 8/8 contract checks pass** (real-time
  monitor 61 ms, hot-reload 52 ms, audit query 30 ms, all
  under their 5 s / 10 s / 30 s budgets).
- **12 fresh per-page screenshots** committed under
  `screenshots/`.
- **SLO engine + VipTalk dispatch is live** — the Tracking page
  captured **3 real SLO alerts firing** during the run.

## Run context

| Field | Value |
|---|---|
| Date (UTC) | 2026-04-30T15:54Z |
| Host | Darwin 23.1.0 arm64, 12 logical CPUs |
| Binary | `target/release/waf` built `--features "redis alerts geoip"` |
| Config | `config/dev.yaml` for dashboard tests, `config/prod.yaml` for protocol tests |
| Bundle | `app.js` 178 KB |
| Tests run | cargo workspace + tests/api/openapi-shape.sh + tests/dashboard/round1-acceptance.sh + tests/protocols/run-all.sh |

## What landed in CI-T1..T10

The dashboard wave that closed in this run:

| Track | What |
|---|---|
| CI-T1 | Overview page → live API (stats, timeseries, attacks, top attackers) |
| CI-T2 | Live Feed → `/dashboard/sse` (real audit-bus events) |
| CI-T3 | Audit / Blacklist / Whitelist / Upstreams / Tracking / Tier Config → live API |
| CI-T4 | Real `/api/slo`, `/api/certs`, `/api/gitops/status`, `/api/alerts` (replaced placeholder()) + `POST /api/alerts/{id}/ack` |
| CI-T5 | New `GET /api/routes` (read-only routing trie) |
| CI-T6 | Settings page Shadow Mode toggle → `PUT /api/mode` |
| CI-T7 | Periodic SLO `engine.evaluate()` task → VipTalk dispatch + per-window burn rates |
| CI-T8 | Geo enrichment for `/api/attacks/top` (MaxMind country + ASN) |
| CI-T9 | OpenAPI 3.0.3 spec for the admin API + 25-check contract test |
| CI-T10 | Wired `hyper_util::auto::Builder` into the data-plane TLS branch — h2 + gRPC actually negotiate now |

## API endpoint summary

Every dashboard-consumed endpoint, captured live:
[`api-summary.txt`](./api-summary.txt) (22 endpoints, all 200 OK,
real shapes — example `/api/slo` returns 267 bytes of live SLI
rows; `/api/cluster` shows the single-node lease holder; etc.).

## Test results

| Suite | Result | Notes |
|---|---|---|
| `cargo test --workspace` | 2,165 passed | default features |
| `cargo test --workspace --features "aegis-bin/redis aegis-bin/alerts aegis-bin/geoip"` | 2,232 passed | full features |
| `make openapi-test` | 25/25 PASS | OpenAPI shape contract |
| `make protocols-test` | h1 ✅ h2 ✅ WS ✅ gRPC ✅ h3 ⏭ | h3 skipped (curl-side) |
| `tests/dashboard/round1-acceptance.sh` | **8/8 PASS** | real-time 61 ms / hot-reload 52 ms / audit 30 ms |

## Screenshots

12 fresh per-page captures at 1440×900 in
[`screenshots/`](./screenshots/). Highlights:

- **Overview** (`overview.png`) — `0` requests/s, `0%` block rate,
  Active Threats `0`, Upstream `Down` (stub-pool members all
  unhealthy because no real backend running). World map shows
  `1 ACTIVE SOURCES · GEO DB NOT LOADED` honestly.
- **Rules** (`rules.png`) — shows the `round1-...` test rule
  created mid-run by `round1-acceptance.sh`. "1 total · validate
  before apply · audit-chained" sub. Live mutation activity.
- **Tracking** (`tracking.png`) — **3 firing alerts** (the SLO
  engine actually fired during the run because data-plane
  availability was 0%):
  - `PAGE: DataPlaneAvailability-1h`
  - `TICKET: DataPlaneAvailability-6h`
  - `TICKET: DataPlaneAvailability-72h`

  This proves CI-T7 end-to-end: engine → evaluate → dispatch
  reachable in production. SLO budget shows real percentages
  (`audit_delivery_rate` 100% / 99.99% target / 100% LEFT;
  `data_plane_availability` 0% current because nothing forwarded
  successfully).

  Cluster peers shows the single-node leader. GitOps panel
  honestly says `not configured`. Cert freshness empty (data
  plane is plaintext on dev config).
- **Audit** (`audit.png`) — admin events including the rule-create
  + mode-set mutations.

## Findings

### Working as designed

- The full CI-T1..T10 chain — every dashboard page reads live
  API; mutations land on the audit chain; SSE broadcasts every
  admin event within ~30 ms of the mutation.
- CI-T10's h2 wire-up is verified live: `openssl s_client`
  reports `ALPN protocol: h2`, curl `--http2` negotiates HTTP/2,
  `05-grpc.sh` forwards a gRPC frame end-to-end.
- CI-T7's SLO engine actually fires alerts in production —
  caught by the Tracking screenshot mid-run.

### Test-harness fixes during the run

`tests/dashboard/round1-acceptance.sh` had three portability
issues that surfaced during this run; all fixed in this commit:

1. **CSRF acquisition** — relied on `/dashboard/` setting
   `aegis_csrf`, which the server doesn't do. Now logs in via
   `POST /admin/login` (configurable via `$AEGIS_ADMIN_USER` /
   `$AEGIS_ADMIN_PASS`).
2. **macOS `date +%s%3N`** — non-portable. Replaced with a
   `ms_now()` helper that uses `python3` (or AWK as fallback).
3. **Bundle marker scan** — `BUNDLE_TEXT=$(curl …)` chained to
   `echo | grep -q` raced under `set -o pipefail` (broken pipe).
   Now streams the bundle to a tempfile and greps in place.

### Known gaps surfaced (non-blocking)

| Gap | Impact | Recommended track |
|---|---|---|
| Data-plane Allow / Block decisions don't broadcast to the audit bus | `/dashboard/sse` only carries admin events, not the full request stream the Live Feed page is designed for | Wire `services.bus.send` into the audit-emission point in `handle_data_request` (small surgical change) |
| HTTP/3 unverified | macOS-shipped curl lacks ngtcp2/nghttp3; can't test the QUIC listener with stock tooling | Operator-side; build curl with HTTP/3 or use `quiche-client` |
| GeoIP unverified live | No MaxMind DB loaded in dev; `country` / `asn` fields would surface only after `cfg.geoip.country_db` is set | Already documented in CI-T8 — works when DBs are shipped |

## Reproducing

```sh
# Build
make setup
cargo build -p aegis-bin --release --features "redis alerts geoip"

# Boot against dev (dashboard tests need login)
target/release/waf run --config config/dev.yaml &

# Suite
cargo test --workspace
make openapi-test
make protocols-test                                  # uses prod.yaml + TLS
bash tests/dashboard/round1-acceptance.sh
node tests/dashboard/capture-screenshots.mjs \
    --out=tests/results/run-11-…/screenshots
```

## What's next

The remaining open queue:

| Track | Effort | Notes |
|---|---|---|
| **B6-T1 production Dockerfile** | ~2 hr | Last Phase B item; multi-stage distroless + buildx. Long-deferred. |
| Data-plane audit emission for SSE Live Feed | ~1 hr | Surfaced by this run; small surgical change in `handle_data_request`. |
| Risk thresholds + DDoS auto-mode + honeypots Settings | ~3 hr | New mutation endpoints (CI-T6 follow-ups). |
| Helm chart (B6-T2), GitHub Actions CI (B6-T3), HSM (B6-T4), fd-pass (B6-T5) | ~10 hr total | Long-tail Phase B. |
