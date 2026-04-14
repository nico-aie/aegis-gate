# `tests/` — Load and Security Test Harness

Out-of-process tests that run against a live `waf` instance.
Rust unit and integration tests live next to their crates under
`crates/*/tests/` — this directory is for things that need a real
network and real attacker tooling.

## Layout

```
tests/
├── load/              # k6 scripts — latency + throughput
│   ├── baseline.js
│   ├── mixed-tiers.js
│   └── ddos-burst.js
└── security/          # attack corpora + scanner runners
    ├── corpus/
    │   ├── benign/    # FP regression — must NOT trigger any detector
    │   └── malicious/ # must be blocked by the referenced detector
    │       ├── sqli/
    │       ├── xss/
    │       ├── traversal/
    │       ├── ssrf/
    │       ├── header-injection/
    │       ├── recon/
    │       └── body-abuse/
    ├── run-nuclei.sh
    └── run-zap.sh
```

## Running

Bring up the test stack first:

```sh
docker compose \
  -f deploy/docker-compose.dev.yml \
  -f deploy/docker-compose.test.yml \
  up -d

# Start the gateway pointed at the dev config
cargo run -p aegis-bin -- run --config config/waf.dev.yaml &
```

### Load tests

```sh
# Baseline: golden-path latency + throughput SLO check
docker exec aegis-k6 k6 run /scripts/baseline.js

# Mixed-tier traffic (CRITICAL/HIGH/MEDIUM blend)
docker exec aegis-k6 k6 run /scripts/mixed-tiers.js

# DDoS burst — verifies auto-block and adaptive shedder
docker exec aegis-k6 k6 run /scripts/ddos-burst.js
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

These are the acceptance gates referenced by the member plans. CI
fails the PR if any threshold is breached.

| Test                | Metric                     | Threshold            | Plan reference |
|---------------------|----------------------------|----------------------|----------------|
| `baseline.js`       | p99 latency, allow path    | ≤ 5 ms               | M1 W5 DoD      |
| `baseline.js`       | sustained RPS, 1 node      | ≥ 5 000              | M1 W5 DoD      |
| `mixed-tiers.js`    | CRITICAL fail-closed count | 0                    | M2 T1.5        |
| `ddos-burst.js`     | auto-block latency         | ≤ 2 s after threshold| M2 T2.3        |
| `corpus/benign`     | false-positive rate        | < 1 %                | M2 T2.4 DoD    |
| `corpus/malicious`  | true-positive rate, SQLi   | ≥ 99 %               | M2 T2.4 DoD    |
| `corpus/malicious`  | true-positive rate, XSS    | ≥ 98 %               | M2 T2.4 DoD    |

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
- Tests MUST be idempotent — no test may leave state in Redis that
  another test depends on. Use `FLUSHDB` between runs if needed.
- Keep load-test durations short in CI (30–60 s) but document the
  longer soak-test variants in the script header.
