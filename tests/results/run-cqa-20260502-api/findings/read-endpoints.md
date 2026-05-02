# CQA — Read endpoint sweep

Each row hit via `curl` against the live WAF; verifies HTTP
status, content-type, and that the response is parseable JSON
with the expected top-level shape (or non-empty body for
non-JSON endpoints).

| Endpoint | HTTP | Content-Type | JSON | Bytes |
|---|---|---|---|---|
| `/api/about` | 200 | application/json | ❌ | 74 |
| `/api/stats` | 200 | application/json | ❌ | 178 |
| `/api/runtime` | 200 | application/json | ❌ | 162 |
| `/api/cluster` | 200 | application/json | ❌ | 270 |
| `/api/slo` | 200 | application/json | ❌ | 267 |
| `/api/certs` | 200 | application/json | ❌ | 12 |
| `/api/alerts` | 200 | application/json | ❌ | 40 |
| `/api/gitops/status` | 200 | application/json | ❌ | 124 |
| `/api/state` | 200 | application/json | ❌ | 142 |
| `/api/mode` | 200 | application/json | ❌ | 18 |
| `/api/risk/thresholds` | 200 | application/json | ❌ | 43 |
| `/api/rules` | 200 | application/json | ❌ | 12 |
| `/api/blacklist` | 200 | application/json | ❌ | 14 |
| `/api/whitelist` | 200 | application/json | ❌ | 14 |
| `/api/routes` | 200 | application/json | ❌ | 133 |
| `/api/tiers` | 200 | application/json | ❌ | 657 |
| `/api/upstreams` | 200 | application/json | ❌ | 107 |
| `/api/upstreams/config` | 200 | application/json | ❌ | 222 |
| `/api/alert-receivers` | 200 | application/json | ❌ | 239 |
| `/api/mtls/sans` | 200 | application/json | ❌ | 14 |
| `/api/mtls` | 200 | application/json | ❌ | 83 |
| `/api/mtls/connections` | 200 | application/json | ❌ | 40 |
| `/api/mtls/failures` | 200 | application/json | ❌ | 37 |
| `/api/mtls/ca-summary` | 200 | application/json | ❌ | 60 |
| `/api/detectors` | 200 | application/json | ❌ | 198 |
| `/api/loadmode` | 200 | application/json | ❌ | 126 |
| `/api/logging` | 200 | application/json | ❌ | 74 |
| `/api/cold-tier` | 200 | application/json | ❌ | 130 |
| `/api/risk` | 200 | application/json | ❌ | 143 |
| `/api/config/version` | 200 | application/json | ❌ | 102 |
| `/api/config/versions?limit=10` | 200 | application/json | ❌ | 41 |
| `/api/stats/timeseries?window=900&step=5` | 200 | application/json | ❌ | 9410 |
| `/api/attacks/distribution?window=900` | 200 | application/json | ❌ | 38 |
| `/api/attacks/top?window=900&limit=20` | 200 | application/json | ❌ | 48 |
| `/api/attacks/by-detector?window=900` | 200 | application/json | ❌ | 37 |
| `/api/bots/mix?window=900` | 200 | application/json | ❌ | 38 |
| `/api/threat-intel/hits?window=900&limit=20` | 200 | application/json | ❌ | 43 |
| `/api/audit/since?limit=20` | 200 | application/json | ❌ | 401 |
| `/healthz/ready` | 200 | application/json | ❌ | 132 |
| `/healthz/live` | 200 | application/json | ❌ | 15 |
| `/metrics` | 200 | text/plain | ❌ | 6240 |
