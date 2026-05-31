# n-tester — cluster + AI-confidence + UI/UX QC suite

Tests for the **new** features shipped through 2026-05 (the cluster config
plane and the AI `confidence_threshold` adjust), exercised in **cluster
mode** (two WAF nodes against a shared Redis). QC drives the dashboard
portion from **Claude Desktop with the Chrome MCP extension**; the rest
is shell scripts following the same shape as `tests/l-tester`.

> If you've used `tests/l-tester` you already know the shape: numbered
> shell scripts, one feature per file, exit 0 = pass, exit non-zero =
> fail, machine-readable JSON written to `reports/`.

## Layout

```
tests/n-tester/
├── README.md                       ← this file
├── _common.sh                      ← cluster bring-up + admin login/CSRF helpers
├── run-all.sh                      ← runs every nt-*.sh, writes reports/run-<ts>.json
├── nt-01..05-clu-*.sh              ← cluster config plane (converge / 409 / failover / rollback / rejoin)
├── nt-06..11-ai-confidence-*.sh    ← AI confidence_threshold adjust
├── nt-12-folded-toggles-regression.sh
└── ui/                             ← Claude-Desktop-driven dashboard playbooks
    ├── README.md
    └── nt-ui-01..07-*.md
```

## Prerequisites

1. **Release binary built** with the cluster-relevant features:
   ```sh
   cargo build -p aegis-bin --release --features "redis geoip alerts ai affinity"
   ```
   For NT-11 (the live-effect AI test, env-gated) you also need an ONNX
   model linked: `make ai-link MODEL=<path>`.
2. **Docker** running (the suite spins up `aegis-cluster-redis` via the
   same helper `tests/cluster/_common.sh` uses).
3. **Ports free**: `8080` `8090` (data), `9443` `9543` (admin), `6379`
   (Redis). If anything is already listening on these, stop it first —
   the harness does not steal ports.
4. **Tools**: `bash` 3.2+, `curl`, `jq`, `docker`.

## How to run

```sh
# All tests
tests/n-tester/run-all.sh

# Filter to one feature
tests/n-tester/run-all.sh --filter 'nt-0[6-9]*'

# One test only (verbose)
bash -x tests/n-tester/nt-01-clu-config-plane-converge.sh

# Skip the AI live-effect test (default — it needs an ONNX model)
AEGIS_AI_E2E=0 tests/n-tester/run-all.sh
# Enable it
AEGIS_AI_E2E=1 tests/n-tester/run-all.sh
```

Each test boots its own cluster fixture (Redis + 2 nodes) and tears it
down on exit, so they can be run individually or in any order. State is
namespaced by the test name in Redis so reruns don't collide.

## Reading the reports

`reports/run-<UTC-timestamp>.json` per `run-all.sh` invocation:

```json
{
  "timestamp": "20260529T103214Z",
  "results": [
    { "name": "nt-01-clu-config-plane-converge", "status": "pass", "duration_s": 8.2 },
    { "name": "nt-02-clu-version-conflict",       "status": "pass", "duration_s": 6.4 }
  ],
  "summary": { "total": 12, "pass": 12, "fail": 0, "skip": 0 }
}
```

A `fail` entry includes a `stderr_tail` field with the last 20 lines of
the script's stderr. A `skip` entry includes `reason`.

**`reports/` is gitignored** — these are run artifacts, not source.

## UI/UX (QC)

QC uses **Claude Desktop** with the **Chrome MCP extension** to drive
the dashboard. Each playbook under `ui/` is a self-contained markdown
file with:

1. A **Given / When / Then** statement of what's being verified.
2. A **Paste-to-Claude** block — copy verbatim into Claude Desktop chat;
   Claude operates Chrome via the MCP extension and reports back.
3. A **Pass criteria** checklist QC ticks.

QC runs the shell suite first (background sanity), then walks through
the `ui/` playbooks. Failures land in `reports/ui-<UTC-timestamp>.md`
(QC creates this; not auto-generated).

## What this suite does NOT cover (deliberate)

- **Detector bypass corpora** — see `tests/l-tester/lt-21..25-hack-*.sh`.
- **Model accuracy** — see `tests/ml-model/`.
- **Performance / load** — see `tests/perf/` and `tests/staging/`.
- **Single-node functional regression** — see `tests/l-tester/`.

If a finding falls into one of those, file it under the relevant suite,
not here.

## Reference

- Cluster fixture: `config/cluster-{a,b}.yaml` + `deploy/haproxy/haproxy.cfg`
- Cluster bring-up helper: `tests/cluster/_common.sh` (n-tester reuses
  the docker/Redis parts; admin login + CSRF helpers are added here)
- Endpoints exercised:
  - `GET / PUT / POST /api/config{,/rollback,/versions/<n>/rollback}`
  - `GET / PUT /api/ai/enabled`
  - `GET / PUT /api/ai/confidence` (the new one)
  - `GET /api/cluster/peers`
  - `GET /healthz/ready`
- Feature plan: `plans/archive/cluster-config-sync-and-scaling.md`
- AI threshold commit: `e77d379`
