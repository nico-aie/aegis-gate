# `tests/` — Whole-system test harness

Out-of-process tests that run against a live `waf` instance.
Rust unit and integration tests live next to their crates under
`crates/*/tests/`; this directory is for scenarios that need a
real network, real attacker tooling, or real admin sessions.

> **Looking for the end-to-end how-to?** See
> [`TESTING.md`](./TESTING.md) — bring-up, run order, CI
> thresholds, and troubleshooting in one place.

## Layout

```
tests/
├── README.md          (this file)
├── TESTING.md         (full system-test playbook)
├── api/               admin-API smoke tests (P1–P8 endpoints)
│   ├── _common.sh
│   ├── detectors.sh   /api/detectors      (P2 + P3)
│   ├── risk.sh        /api/risk*          (P6)
│   ├── loadmode.sh    /api/loadmode       (P7)
│   ├── logging.sh     /api/logging        (P8)
│   ├── cold-tier.sh   /api/cold-tier      (P8)
│   └── run-all.sh     drive everything in order
├── load/              k6 scripts — latency, throughput, toggles
│   ├── baseline.js                  golden-path SLOs
│   ├── mixed-tiers.js               multi-tier traffic blend
│   ├── ddos-burst.js                single-source flood
│   ├── security-toggle-flips.js     P2 — flip detector class mid-traffic
│   ├── risk-strikes.js              P6 — drive single IP to permanent block
│   ├── loadmode-degradation.js      P7 — verify auto Normal → Critical
│   └── verbosity-pin.js             P8 — pin verbosity, audit goes silent
└── security/          attack corpora + scanner runners
    ├── corpus/
    │   ├── benign/    FP regression — must NOT trigger any detector
    │   └── malicious/ must be blocked by the referenced detector
    ├── run-corpus.sh
    ├── run-nuclei.sh
    └── run-zap.sh
```

## Running

The test harness ships a self-contained dev config at
[`config/waf.dev.yaml`](../config/waf.dev.yaml) — no Redis, no
secret-resolver hookup, fixed admin credentials. The `cargo run`
line below reads it directly. See
[`TESTING.md`](./TESTING.md#3-bring-up) for the full diff
against the production-shape `config/waf.yaml`.

```sh
# Optional: bring up the auxiliary stack (Redis, k6, Nuclei, ZAP).
# Required only for the load + scanner layers.
docker compose \
  -f deploy/docker-compose.dev.yml \
  -f deploy/docker-compose.test.yml \
  up -d

# Start the gateway against the dev config
cargo run -p aegis-bin -- run --config config/waf.dev.yaml &
```

### Admin-API smoke

```sh
# Credentials are baked into config/waf.dev.yaml — fine to check
# in because the config itself is in VCS.
export ADMIN_USER=admin
export ADMIN_PASS=aegis-test-1234

# All endpoints in dependency order (~5 s)
./tests/api/run-all.sh

# One at a time
./tests/api/detectors.sh
./tests/api/risk.sh        203.0.113.7
./tests/api/loadmode.sh
./tests/api/logging.sh
./tests/api/cold-tier.sh
```

### Load tests

```sh
# Baseline: golden-path latency + throughput SLO check
docker exec aegis-k6 k6 run /scripts/baseline.js

# Mixed-tier traffic (CRITICAL/HIGH/MEDIUM blend)
docker exec aegis-k6 k6 run /scripts/mixed-tiers.js

# DDoS burst — verifies auto-block + adaptive shedder
docker exec aegis-k6 k6 run /scripts/ddos-burst.js

# Security-toggle flips — P2
docker exec aegis-k6 k6 run -e ADMIN_USER=admin -e ADMIN_PASS=$ADMIN_PASS \
  /scripts/security-toggle-flips.js

# Risk strikes — P6
docker exec aegis-k6 k6 run -e ADMIN_USER=admin -e ADMIN_PASS=$ADMIN_PASS \
  /scripts/risk-strikes.js

# LoadMode degradation — P7
docker exec aegis-k6 k6 run /scripts/loadmode-degradation.js

# Verbosity pin — P8
docker exec aegis-k6 k6 run -e ADMIN_USER=admin -e ADMIN_PASS=$ADMIN_PASS \
  /scripts/verbosity-pin.js
```

### Security tests

```sh
# OWASP attack corpus replay (true-positive suite)
./tests/security/run-corpus.sh malicious

# Benign corpus (false-positive regression)
./tests/security/run-corpus.sh benign

# Nuclei templates
docker exec aegis-nuclei /work/run-nuclei.sh http://host.docker.internal:8080

# OWASP ZAP baseline scan
./tests/security/run-zap.sh http://localhost:8080
```

## SLO Thresholds

CI fails the PR if any threshold is breached.

| Test                             | Metric                              | Threshold              | Plan reference |
|----------------------------------|-------------------------------------|------------------------|----------------|
| `baseline.js`                    | p99 latency, allow path             | ≤ 5 ms                 | M1 W5 DoD      |
| `baseline.js`                    | sustained RPS, 1 node               | ≥ 5 000                | M1 W5 DoD      |
| `mixed-tiers.js`                 | CRITICAL fail-closed count          | 0                      | M2 T1.5        |
| `ddos-burst.js`                  | auto-block latency                  | ≤ 2 s after threshold  | M2 T2.3        |
| `corpus/benign`                  | false-positive rate                 | < 1 %                  | M2 T2.4 DoD    |
| `corpus/malicious`               | true-positive rate, SQLi            | ≥ 99 %                 | M2 T2.4 DoD    |
| `corpus/malicious`               | true-positive rate, XSS             | ≥ 98 %                 | M2 T2.4 DoD    |
| `security-toggle-flips.js`       | mask flip propagation               | ≤ 200 ms (1 sample)    | P2             |
| `risk-strikes.js`                | strike-block reached after N events | rate == 1              | P6             |
| `risk-strikes.js`                | clean req blocked after strike      | rate == 1              | P6             |
| `loadmode-degradation.js`        | observed `critical` mode under load | rate > 0               | P7             |
| `verbosity-pin.js`               | new audit entries during silent     | count == 0             | P8             |
| `tests/api/run-all.sh`           | every script exits 0                | mandatory              | P1–P8          |

## Adding a corpus sample

- **Benign** samples come from real web traffic captures (anonymize
  first). One request per file, raw HTTP on the wire, named
  `NNN-<short-description>.http`.
- **Malicious** samples are grouped by the detector they target. A
  sample added to `malicious/sqli/` MUST be blocked by the SQLi
  detector specifically — not by a generic rule — otherwise the
  regression signal is lost.
- Update the manifest in each corpus subdirectory's `INDEX.md` with
  source and attack class.

## Notes

- All load and security tests talk to the gateway at
  `host.docker.internal:8080` (plaintext) or `:8443` (TLS). Override
  with `WAF_TARGET` if you run the gateway elsewhere.
- Admin-API tests target `https://127.0.0.1:9443` by default;
  override with `AEGIS_ADMIN`.
- Tests MUST be idempotent — no test may leave state in Redis,
  the strike map, or the load-mode override that another test
  depends on. Each script restores its preconditions on exit.
- Keep load-test durations short in CI (30–60 s) but document the
  longer soak-test variants in the script header.
