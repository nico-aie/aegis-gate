# Aegis-Gate — Whole-System Testing Playbook

Single source of truth for verifying a build of the WAF. Covers every
test layer from per-crate Rust unit tests up to live attack-replay
scans, in the order an operator should run them, with the SLO
thresholds CI gates on, and the recovery steps when something fails.

If you only want to run **one** thing — run `cargo test --workspace`
first, then `tests/api/run-all.sh`. Those two together cover the
contracts the security-toggle plan (P1–P8) and the post-k6 follow-up
(F-T1..F-T10) introduced.

> **Working with an AI assistant on tests?** Read
> [`AI-ASSISTANT-RULES.md`](./AI-ASSISTANT-RULES.md) (terse do/don't
> sheet) and [`AI-ASSISTANT-GUIDE.md`](./AI-ASSISTANT-GUIDE.md)
> (workflow + review checklist) **before** the first prompt.


## Layout

```
tests/
├── README.md                     this playbook
├── api/                          admin-API smoke tests (curl + jq)
│   ├── _common.sh                shared login + helpers
│   ├── detectors.sh              /api/detectors          (P2 + P3)
│   ├── risk.sh                   /api/risk*              (P6)
│   ├── loadmode.sh               /api/loadmode           (P7)
│   ├── logging.sh                /api/logging            (P8)
│   ├── cold-tier.sh              /api/cold-tier          (P8)
│   ├── acme.sh                   Pebble round-trip       (F-T7)
│   ├── tls.sh                    TLS hardening + headers on admin :9443 (P4)
│   ├── tls-ciphers.sh            cipher-suite negotiation + weak-suite reject (P4)
│   ├── tls-data.sh               TLS hardening on the data plane (skips when :8443 not bound)
│   ├── auth.sh                   admin login + lockout + CSRF reject (P1)
│   └── run-all.sh                drive everything in dependency order
├── cluster/                      HA two-node smoke tests (Phase B B1)
│   ├── README.md                 orchestration + bring-up notes
│   ├── _common.sh                two-node + redis fixture helpers
│   ├── 01-shared-counter.sh      state shared across nodes via Redis
│   ├── 02-leader-failover.sh     killing the leader hands off the lease
│   ├── 03-rehydrate-readiness.sh /healthz/ready 503 → 200 across the warm-up window
│   ├── 04-partition-fallback.sh  Redis partition → fallback → heal
│   └── run-all.sh                drive the whole cluster track
├── load/                         k6 scripts — latency, throughput, toggles
│   ├── README-perf.md            host-vs-laptop SLO targets    (F-T6)
│   ├── baseline.js               golden-path SLOs over plaintext HTTP (M1 W5 DoD)
│   ├── tls-baseline.js           same shape as baseline.js, over HTTPS (skips when :8443 not bound)
│   ├── mixed-tiers.js            multi-tier traffic blend      (M2 T1.5)
│   ├── ddos-burst.js             single-source flood           (M2 T2.3)
│   ├── security-toggle-flips.js  flip detector class mid-traffic (P2)
│   ├── risk-strikes.js           drive single IP to permanent block (P6)
│   ├── loadmode-degradation.js   verify auto Normal → Critical (P7)
│   ├── verbosity-pin.js          pin verbosity, audit goes silent (P8)
│   ├── audit-since.js            /api/audit/since contract     (F-T9)
│   ├── cold-tier.js              /api/cold-tier inventory      (F-T9)
│   └── rate-limit.js             per-IP rate-limit saturation
├── results/                      k6 artefacts + comparison reports
│   ├── README.md                 2026-04-28 baseline (post F-T1..F-T10)
│   ├── README-2026-04-29.md      post Phase B B3..B5 re-run + carry-overs
│   └── *.log                     per-script k6 output (date-suffixed = newer run)
└── security/                     attack corpora + scanner runners
    ├── corpus/
    │   ├── benign/               FP regression — must NOT trigger any detector
    │   └── malicious/            must be blocked by the referenced detector
    ├── run-corpus.sh
    ├── run-nuclei.sh
    └── run-zap.sh
```

## 1. Test pyramid

The project follows a four-layer pyramid:

```
                           ┌───────────────────────────┐
   integration scanners    │ Nuclei, ZAP, custom corpus │  ← tests/security/
                           ├───────────────────────────┤
   live load + behaviour   │ k6 scripts                 │  ← tests/load/
                           ├───────────────────────────┤
   live admin-API smoke    │ curl + jq                  │  ← tests/api/
                           ├───────────────────────────┤
   in-process Rust tests   │ unit + per-crate tests/*   │  ← cargo test
                           └───────────────────────────┘
```

| Layer | Where | Coverage |
|---|---|---|
| Rust unit | `crates/*/src/**` `#[cfg(test)]` | hot-path correctness, state machines, parsers |
| Rust integration | `crates/*/tests/*.rs` | dashboard router, audit chain, services bundle |
| Admin-API smoke | `tests/api/*.sh` | live endpoint shapes, CSRF, AuditedMutate round-trip, TLS hardening + cipher negotiation |
| HA cluster smoke | `tests/cluster/*.sh` | two-node fixture against shared Redis — counter sharing, leader failover, rehydrate gate, partition fallback (Phase B B1) |
| Load + behaviour | `tests/load/*.js` | latency / throughput SLOs + P2/P6/P7/P8 scenarios; HTTPS variant runs the same shape over TLS |
| Attack replay | `tests/security/*` | OWASP corpus, Nuclei, ZAP |

## 2. Prerequisites

- Rust toolchain matching `rust-version` in `Cargo.toml`
- Docker + Docker Compose (for the test stack: Redis, k6, Nuclei, ZAP, Pebble for ACME)
- `curl` and `jq` (for the API smoke layer)
- `openssl` (for `tests/api/tls-ciphers.sh`'s cipher-negotiation probes — the script skips quietly if absent)
- `bats` *(optional, only for adding new shell tests)*
- Ports free on the host:
  - `8080` (data plane plaintext) and `8443` (TLS data plane) for the single-node tracks
  - `9443` (admin) for the single-node tracks
  - `8090`, `9543` for the second cluster node — see [`tests/cluster/README.md`](./cluster/README.md)
  - `6379` (Redis) for both the cluster fixture and the optional shared-state work
  - `4443` (Pebble) for ACME
- An `ADMIN_USER` / `ADMIN_PASS` pair — `config/dev.yaml` ships with
  a baked-in `admin` / `aegis-test-1234` already hashed inline. To use a
  different password, generate a hash with
  `echo "<new-pw>" | cargo run -p aegis-bin -- admin set-password` and
  replace the `password_hash_ref` value in the dev config.

## 3. Bring-up

The test harness ships a self-contained dev config at
[`../config/dev.yaml`](../config/dev.yaml) — it has no
`${secret:env:...}` references, runs against the in-memory state
backend, and pre-loads a fixed admin credential pair so the test layers
can authenticate without a bootstrap step.

> **Test admin credentials** (declared inline in `config/dev.yaml`
> — *do not use in production*):
> - user: `admin`
> - password: `aegis-test-1234`
> - csrf secret: `test-csrf-secret-do-not-use-in-production-32b`

To rotate the password, regenerate the argon2id hash and replace the
`password_hash_ref` value:

```sh
echo "<new-password>" | cargo run -p aegis-bin -- admin set-password
# → paste the printed hash into config/dev.yaml
```

### Standard bring-up

> **Binary name.** The package is `aegis-bin` but the produced binary
> is **`waf`** (see `[[bin]] name = "waf"` in
> `crates/aegis-bin/Cargo.toml`). After a build the executable lives at
> `target/{debug,release}/waf` — there is no `target/release/aegis-bin`.

```sh
# 1. (Optional) Pre-build a release binary if you'll re-run the gateway
#    many times — release is ~10× faster than debug for the load layers.
cargo build --release --workspace
#    → produces target/release/waf  (NOT target/release/aegis-bin)

# 2. (Optional) Bring up the auxiliary test stack — Redis, k6, Nuclei,
#    ZAP, Pebble. The dev config doesn't require any of these for the
#    unit + admin-API smoke layers; only k6 + scanner runs need the
#    containers.
docker compose \
  -f deploy/docker-compose.dev.yml \
  -f deploy/docker-compose.test.yml \
  up -d

# 3. Validate the dev config first (catches schema drift fast)
cargo run -p aegis-bin -- validate --config config/dev.yaml
# → expected: "config OK: config/dev.yaml"

# 4. Run the gateway pointed at the dev config.
cargo run -p aegis-bin -- run --config config/dev.yaml &
WAF_PID=$!

# 5. Wait for readiness
until curl -sf http://127.0.0.1:9443/healthz/ready >/dev/null; do
  sleep 0.5
done
echo "ready"

# 6. Export the admin creds the API/load layers need.
export ADMIN_USER=admin
export ADMIN_PASS=aegis-test-1234

# 7. ... run tests ...

# 8. Tear down
kill $WAF_PID
docker compose -f deploy/docker-compose.dev.yml -f deploy/docker-compose.test.yml down
```

### What's in `dev.yaml` vs `waf.yaml`

| Field | `waf.yaml` (production-shape) | `dev.yaml` (test) |
|---|---|---|
| Listeners | TLS `:8443` + plain `:8080` + admin `:9443` | plain `:8080` + admin `:9443` |
| Routes | 4 named routes, tier overrides | one catch-all |
| Upstreams | 3 pools at `127.0.0.1:3001-3004` | one stub pool (`127.0.0.1:9999`) |
| State | configurable | `in_memory` (forced) |
| Admin password | `${secret:env:AEGIS_ADMIN_PASSWORD_HASH}` | inline argon2id hash |
| CSRF secret | `${secret:env:AEGIS_CSRF_SECRET}` | inline placeholder |
| Compliance | optional | `null` so detector toggle tests aren't clamped |
| `risk.strikes.block_at` | not set (legacy decay only) | `50` (matches `STRIKE_LIMIT` default in `risk-strikes.js`) |
| `load_mode.{elevated,critical}_rps` | defaults | `2000` / `8000` (laptop-friendly) |
| Audit sinks | empty | one jsonl sink at `/tmp/aegis-dev-audit.jsonl` |
| Rate limit (admin login) | per-IP 5/min, lockout 10 attempts | per-IP 100/min, lockout 50 — keeps API smoke re-runs fast |

## 4. Layer 1 — Rust unit + integration tests

```sh
# All workspace tests (≈ 1900 tests, ~10 s)
cargo test --workspace

# One crate
cargo test -p aegis-control

# A single test path
cargo test -p aegis-security risk::tracker::tests::strike_block

# With backtrace
RUST_BACKTRACE=1 cargo test -p aegis-proxy --lib acme::

# Style + lint gate (CI-required)
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

Specific module families to know about:

| Module | What it covers |
|---|---|
| `aegis-core::load_mode` | LoadMode + LoadGauge + transitions (P7) |
| `aegis-core::verbosity` | VerbosityLevel + SharedVerbosity (P8) |
| `aegis-security::detectors::mask` | DetectorMask + per-tier overrides (P2/P3) |
| `aegis-security::risk::tracker` | RiskTracker + strikes + trust recovery (P6) |
| `aegis-control::api::mutation` | AuditedMutate pipeline (P1) |
| `aegis-control::api::detectors` | /api/detectors handler (P2/P3) |
| `aegis-control::api::risk` | /api/risk handler (P6) |
| `aegis-control::api::load_mode` | /api/loadmode handler (P7) |
| `aegis-control::api::logging` | /api/logging + /api/cold-tier (P8) |
| `aegis-proxy::acme` | AcmeProvider trait + manager + scheduler (F-T8) |
| `aegis-proxy::acme_instant` | instant-acme network adapter (F-T8) |
| `aegis-proxy::listener::tls_policy` | TLS hardening + redirect (P4) |
| `aegis-control::metrics::request_duration` | per-stage latency histogram (F-T10) |

## 5. Layer 2 — Admin-API smoke

Bash + curl tests that exercise the live endpoint contracts. Take ~5 s
end-to-end.

```sh
# Run the whole suite (in dependency order)
./tests/api/run-all.sh

# Or by feature
./tests/api/auth.sh        # admin login + lockout + CSRF reject (P1)
./tests/api/tls.sh         # TLS minimum + security headers (P4)
./tests/api/detectors.sh   # P2 + P3
./tests/api/risk.sh        # P6
./tests/api/loadmode.sh    # P7
./tests/api/logging.sh     # P8
./tests/api/cold-tier.sh   # P8
./tests/api/acme.sh        # F-T7 — Pebble reachability
```

What every script asserts is documented in
[`api/README.md`](./api/README.md). Each script restores its
preconditions on exit so re-runs are deterministic.

### What to do when one fails

| Symptom | Likely cause | Fix |
|---|---|---|
| `FAIL: expected '200' got '403'` on a GET | session cookie missing | re-login: `aegis_login` in the script handles this; check `ADMIN_USER`/`ADMIN_PASS` |
| `FAIL: aegis_csrf cookie not set` | login returned 401/403 | wrong creds, or admin listener isn't reachable |
| Detectors PUT returns 400 | compliance clamp | check `cfg.compliance.modes`; the test config (`config/dev.yaml`) has compliance off |
| `cold-tier.sh` complains about `secret:` substring | regression — token leaked | open issue tagged `security/audit-redaction` |
| `auth.sh` lockout not reached | `admin.rate_limit.lockout` lowered to 5 in test config | check `config/dev.yaml` |
| `tls.sh` reports TLS 1.1 accepted | regression in `listener::tls_policy` | re-run with `RUST_LOG=debug` and inspect handshake |

## 6. Layer 3 — k6 load tests

The k6 scripts run inside the `aegis-k6` container started by
`docker-compose.test.yml`. The container mounts `./tests/load` at
`/scripts` and has network access to the gateway via
`host.docker.internal:8080` (or `:8443` for TLS).

```sh
# Golden-path SLOs (CI-required)
docker exec aegis-k6 k6 run /scripts/baseline.js

# Multi-tier traffic blend
docker exec aegis-k6 k6 run /scripts/mixed-tiers.js

# DDoS burst → auto-block
docker exec aegis-k6 k6 run /scripts/ddos-burst.js

# P2 — flip detector class while traffic flows
docker exec aegis-k6 k6 run \
  -e ADMIN_USER=$ADMIN_USER -e ADMIN_PASS=$ADMIN_PASS \
  /scripts/security-toggle-flips.js

# P6 — drive single IP through strike threshold
docker exec aegis-k6 k6 run \
  -e ADMIN_USER=$ADMIN_USER -e ADMIN_PASS=$ADMIN_PASS \
  /scripts/risk-strikes.js

# P7 — three traffic stages, observe LoadMode auto-elevation
docker exec aegis-k6 k6 run /scripts/loadmode-degradation.js

# P8 — pin verbosity to silent, audit chain stops growing
docker exec aegis-k6 k6 run \
  -e ADMIN_USER=$ADMIN_USER -e ADMIN_PASS=$ADMIN_PASS \
  /scripts/verbosity-pin.js

# F-T9 — audit replay contract
docker exec aegis-k6 k6 run \
  -e ADMIN_USER=$ADMIN_USER -e ADMIN_PASS=$ADMIN_PASS \
  /scripts/audit-since.js

# F-T9 — cold-tier inventory contract (no secret leakage)
docker exec aegis-k6 k6 run \
  -e ADMIN_USER=$ADMIN_USER -e ADMIN_PASS=$ADMIN_PASS \
  /scripts/cold-tier.js

# Per-IP rate limit saturation
docker exec aegis-k6 k6 run /scripts/rate-limit.js
```

For host-vs-laptop SLO calibration before reading any p99 number,
see [`load/README-perf.md`](./load/README-perf.md) (F-T6).

### CI-enforced thresholds

Each script declares its `thresholds` block; k6 exits non-zero on
breach. The full gating set:

| Test | Metric | Threshold | Plan ref |
|---|---|---|---|
| `baseline.js` | p99 latency, allow path | ≤ 5 ms | M1 W5 DoD |
| `baseline.js` | sustained RPS, 1 node | ≥ 5 000 | M1 W5 DoD |
| `baseline.js` | allow success rate | ≥ 0.999 | M1 W5 DoD |
| `mixed-tiers.js` | CRITICAL fail-closed count | 0 | M2 T1.5 |
| `ddos-burst.js` | auto-block latency | p95 < 2 000 ms | M2 T2.3 |
| `corpus/benign` | false-positive rate | < 1 % | M2 T2.4 DoD |
| `corpus/malicious` | TPR — SQLi | ≥ 99 % | M2 T2.4 DoD |
| `corpus/malicious` | TPR — XSS | ≥ 98 % | M2 T2.4 DoD |
| `security-toggle-flips.js` | mask flip propagation | ≤ 200 ms (1 sample) | P2 |
| `risk-strikes.js` | strike-block reached after N events | rate == 1 | P6 |
| `risk-strikes.js` | clean req blocked after strike | rate == 1 | P6 |
| `loadmode-degradation.js` | observed `critical` mode under load | rate > 0 | P7 |
| `verbosity-pin.js` | new audit entries during silent | count == 0 | P8 |
| `audit-since.js` | replay envelope shape ok | rate == 1 | F-T9 |
| `cold-tier.js` | secret leakage observed | count == 0 | F-T9 |
| `rate-limit.js` | 429 returned after burst | rate > 0.95 | rate-limiting |
| `tests/api/run-all.sh` | every script exits 0 | mandatory | P1–P8 + F-T7 |

### Soak-test variants

Each script accepts `DURATION=` to extend the run for soak testing.
Bump CI runs back to 30–60 s; reserve 30+-minute soaks for nightly
jobs.

## 7. Layer 4 — Attack replay + scanners

Long-running, network-heavy. Don't run on every commit; nightly or
pre-release.

```sh
# True-positive: every malicious sample MUST be blocked by the
# detector it's filed under
./tests/security/run-corpus.sh malicious

# False-positive: every benign sample MUST pass through
./tests/security/run-corpus.sh benign

# Nuclei templates against a brought-up gateway
docker exec aegis-nuclei /work/run-nuclei.sh http://host.docker.internal:8080

# OWASP ZAP baseline scan
./tests/security/run-zap.sh http://localhost:8080
```

The corpus runner is OWASP-aligned; samples live under
`tests/security/corpus/{benign,malicious}/` and an `INDEX.md` in each
subdirectory tracks source + attack class.

### Adding a corpus sample

- **Benign** samples come from real web traffic captures (anonymize
  first). One request per file, raw HTTP on the wire, named
  `NNN-<short-description>.http`.
- **Malicious** samples are grouped by the detector they target. A
  sample added to `malicious/sqli/` MUST be blocked by the SQLi
  detector specifically — not by a generic rule — otherwise the
  regression signal is lost.
- Update the manifest in each corpus subdirectory's `INDEX.md` with
  source and attack class.

## 8. Adding new tests

### Adding an admin-API smoke

1. Drop a new `tests/api/<name>.sh` that sources `_common.sh`.
2. Use `aegis_login`, `aegis_get`, `aegis_put`, `aegis_put_status`,
   `assert_eq`, `ok` — these are the only helpers, on purpose.
3. End the script with the precondition restore so re-runs are
   deterministic.
4. Add the script to `run-all.sh`.
5. Document the assertions table in `tests/api/README.md`.

### Adding a k6 scenario

1. Drop a new `tests/load/<name>.js`.
2. Set `options.thresholds` so failures break the run.
3. Read admin creds from `__ENV.ADMIN_USER` / `__ENV.ADMIN_PASS` if
   you need them; not every load test does.
4. End the test by reverting any state it changed (override, strike,
   mask flip). Idempotency is mandatory.
5. Update the SLO table in this README.

## 9. CI pipeline reference

Recommended stage layout:

```
stage 1  cargo fmt --check + cargo clippy --workspace -- -D warnings
stage 2  cargo test --workspace
stage 3  bring up dev gateway + tests/api/run-all.sh
stage 4  tests/contract/v2.3_compliance.sh         <- HACK-T2 gate
stage 5  k6 baseline.js + ddos-burst.js + the four P-track scenarios
         + audit-since.js + cold-tier.js + rate-limit.js
stage 6  (nightly) corpus/{benign,malicious} + Nuclei + ZAP
```

Stages 1–5 should land within ~5 minutes on a moderately-sized runner.
Stage 6 runs nightly because the scanners are slow and add no PR-level
signal.

**Stage 4 (`tests/contract/v2.3_compliance.sh`)** is the
hackathon-readiness regression gate. It runs 40 numbered checks
mapped directly to sections of
[`Hackathon_Doc/EN_waf_interop_contract_v2.3.md`](../Hackathon_Doc/EN_waf_interop_contract_v2.3.md):
control-endpoint dispatch (§2.1), `X-Benchmark-Secret` auth
(§2.2), capabilities response shape (§2.3), atomic
`reset_state` (§2.4), `set_profile` semantics (§2.5),
`flush_cache` not-5xx (§2.6), every required `X-WAF-*` header
on both allowed + blocked responses with exact value-set
matches (§5.1, §5.3), audit-log JSONL minimal schema + TCP-peer
IP semantics + request_id correlation (§6), decision-class
enforcement smoke (§3.1), and the startup contract (§8). The
script aborts on first failure with a `FAIL: [NNN] v2.3 §X.Y
— <description>` line so CI logs surface the offending
contract clause directly.

## 10. Notes

- All load and security tests talk to the gateway at
  `host.docker.internal:8080` (plaintext) or `:8443` (TLS). Override
  with `WAF_TARGET` if you run the gateway elsewhere.
- Admin-API tests target `https://127.0.0.1:9443` by default; override
  with `AEGIS_ADMIN`.
- Tests MUST be idempotent — no test may leave state in Redis, the
  strike map, or the load-mode override that another test depends on.
  Each script restores its preconditions on exit.
- Keep load-test durations short in CI (30–60 s) but document the
  longer soak-test variants in the script header.

## 11. Troubleshooting

| Problem | Where to look |
|---|---|
| Gateway won't start | `cargo run -p aegis-bin -- validate --config config/dev.yaml` (subcommand is `validate`, not `check`) |
| `target/release/aegis-bin: no such file` | The binary is named `waf` — use `target/release/waf` or `cargo run -p aegis-bin -- run` |
| Port 9443 already in use | `lsof -i :9443` — usually a stale gateway process |
| k6 can't reach the gateway | `host.docker.internal:8080` requires Docker Desktop or `--add-host` |
| `tests/api` returns 401 | session cookie missing; check `ADMIN_USER` / `ADMIN_PASS` |
| Audit chain integrity fails | every chain entry must hash from the previous; re-run `cargo run -p aegis-bin -- audit verify` |
| ACME tests fail with "tls handshake" | the rustls feature flag is off-by-one; `instant-acme` must be built with `aws-lc-rs`, not `ring` (see `Cargo.toml`) |
| Strike test clean-block-fails | `risk.strikes.block_at` in `config/dev.yaml` must match `STRIKE_LIMIT` env in the k6 run |

## 12. Reference: documentation map

The features under test are documented across:

- [`../docs/operator/usage.md`](../docs/operator/usage.md) § Security Toggles — operator guide + curl examples
- [`../docs/control-plane/enterprise/api.md`](../docs/control-plane/enterprise/api.md) § Security toggles — request/response shapes
- [`../docs/security/risk-scoring.md`](../docs/security/risk-scoring.md) — P6 strikes + trust recovery
- [`../docs/data-plane/tls-termination.md`](../docs/data-plane/tls-termination.md) — P4 hardening + P5 ACME
- [`../docs/observability/audit-logging.md`](../docs/observability/audit-logging.md) — P1 AuditedMutate + P8 verbosity gating
- [`../docs/data-plane/adaptive-load-shedding.md`](../docs/data-plane/adaptive-load-shedding.md) — P7 LoadMode
- [`../docs/data-plane/graceful-degradation.md`](../docs/data-plane/graceful-degradation.md) — P7/P8 degraded logging
- [`../docs/observability/siem-log-forwarding.md`](../docs/observability/siem-log-forwarding.md) — P8 cold-tier surface
- [`../Implement-Progress.md`](../Implement-Progress.md) — phase-by-phase changelog
