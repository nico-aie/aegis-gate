# Aegis-Gate — Whole-System Testing Guide

This is the end-to-end playbook for verifying a build of the
WAF. It covers every test layer from the per-crate Rust unit
tests up to live attack-replay scans, with the order an
operator should run them, the SLO thresholds CI gates on, and
the recovery steps when something fails.

If you only want to run **one** thing — run `cargo test --workspace`
first, then `tests/api/run-all.sh`. Those two together cover the
contracts the security-toggle plan (P1–P8) introduced.

## 1. Test Pyramid

The project follows a four-layer pyramid:

```
                            ┌───────────────────────────┐
   integration scanners     │ Nuclei, ZAP, custom       │  ← tests/security/
                            ├───────────────────────────┤
   live load + behaviour    │ k6 scripts                │  ← tests/load/
                            ├───────────────────────────┤
   live admin-API smoke     │ curl + jq                 │  ← tests/api/
                            ├───────────────────────────┤
   in-process Rust tests    │ unit + per-crate tests/*  │  ← cargo test
                            └───────────────────────────┘
```

| Layer | Where | Coverage |
|---|---|---|
| Rust unit | `crates/*/src/**/tests` | hot-path correctness, state machines, parsers |
| Rust integration | `crates/*/tests/*.rs` | dashboard router, audit chain, services bundle |
| Admin-API smoke | `tests/api/*.sh` | live endpoint shapes, CSRF, AuditedMutate round-trip |
| Load + behaviour | `tests/load/*.js` | latency / throughput SLOs + P2/P6/P7/P8 scenarios |
| Attack replay | `tests/security/*` | OWASP corpus, Nuclei, ZAP |

## 2. Prerequisites

- Rust toolchain matching `rust-version` in `Cargo.toml`
- Docker + Docker Compose (for the test stack: Redis, k6,
  Nuclei, ZAP, Pebble for ACME)
- `curl` and `jq` (for the API smoke layer)
- `bats` *(optional, only for adding new shell tests)*
- Ports `8080` (data plane), `8443` (TLS data plane), `9443`
  (admin), `4443` (Pebble) free on the host
- An `ADMIN_USER` / `ADMIN_PASS` pair — bootstrap with
  `cargo run -p aegis-bin -- admin init` if you don't have one

## 3. Bring-up

The test harness ships a self-contained dev config at
[`config/waf.dev.yaml`](../config/waf.dev.yaml) — it has no
`${secret:env:...}` references, runs against the in-memory state
backend, and pre-loads a fixed admin credential pair so the test
layers can authenticate without a bootstrap step.

> **Test admin credentials** (declared inline in
> `config/waf.dev.yaml` — *do not use in production*):
> - user: `admin`
> - password: `aegis-test-1234`
> - csrf secret: `test-csrf-secret-do-not-use-in-production-32b`

To rotate the password, regenerate the argon2id hash and replace
the `password_hash_ref` value:

```sh
echo "<new-password>" | cargo run -p aegis-bin -- admin set-password
# → paste the printed hash into config/waf.dev.yaml
```

### Standard bring-up

```sh
# 1. Build the gateway
cargo build --workspace --release

# 2. (Optional) Bring up the auxiliary test stack — Redis, k6,
#    Nuclei, ZAP. The dev config doesn't require any of these
#    for the unit + admin-API smoke layers; only k6 + scanner
#    runs need the containers.
docker compose \
  -f deploy/docker-compose.dev.yml \
  -f deploy/docker-compose.test.yml \
  up -d

# 3. Validate the dev config first (catches schema drift fast)
cargo run -p aegis-bin -- validate --config config/waf.dev.yaml
# → expected: "config OK: config/waf.dev.yaml"

# 4. Run the gateway pointed at the dev config
target/release/aegis-bin run --config config/waf.dev.yaml &
WAF_PID=$!

# 5. Wait for readiness
until curl -sf http://127.0.0.1:9443/healthz/ready >/dev/null; do
  sleep 0.5
done
echo "ready"

# 6. Export the admin creds the API/load layers need.
#    These are the literals from config/waf.dev.yaml — fine to
#    check into a runbook because the config itself is in VCS.
export ADMIN_USER=admin
export ADMIN_PASS=aegis-test-1234

# 7. ... run tests ...

# 8. Tear down
kill $WAF_PID
docker compose -f deploy/docker-compose.dev.yml -f deploy/docker-compose.test.yml down
```

### What's in `waf.dev.yaml` vs `waf.yaml`

| Field | `waf.yaml` (production-shape) | `waf.dev.yaml` (test) |
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
| `aegis-proxy::acme` | AcmeProvider trait + manager + scheduler |
| `aegis-proxy::acme_instant` | instant-acme network adapter |
| `aegis-proxy::listener::tls_policy` | TLS hardening + redirect (P4) |

## 5. Layer 2 — Admin-API smoke

Bash + curl tests that exercise the live endpoint contracts.
Take ~5 s end-to-end.

```sh
# Run the whole suite
./tests/api/run-all.sh

# Or by feature
./tests/api/detectors.sh   # P2 + P3
./tests/api/risk.sh        # P6
./tests/api/loadmode.sh    # P7
./tests/api/logging.sh     # P8
./tests/api/cold-tier.sh   # P8
```

What every script asserts is documented in
[`tests/api/README.md`](./api/README.md). Each script restores
its preconditions on exit so re-runs are deterministic.

### What to do when one fails

| Symptom | Likely cause | Fix |
|---|---|---|
| `FAIL: expected '200' got '403'` on a GET | session cookie missing | re-login: `aegis_login` in the script handles this; check `ADMIN_USER`/`ADMIN_PASS` |
| `FAIL: aegis_csrf cookie not set` | login returned 401/403 | wrong creds, or admin listener isn't reachable |
| Detectors PUT returns 400 | compliance clamp | check `cfg.compliance.modes`; the test config (`config/waf.dev.yaml`) has compliance off |
| `cold-tier.sh` complains about `secret:` substring | regression — token leaked | open issue tagged `security/audit-redaction` |

## 6. Layer 3 — k6 load tests

The k6 scripts run inside the `aegis-k6` container started by
`docker-compose.test.yml`. The container mounts `./tests/load`
at `/scripts` and has network access to the gateway via
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
```

### CI-enforced thresholds

Each script declares its `thresholds` block; k6 exits non-zero
on breach. The gating set:

| Script | Threshold |
|---|---|
| `baseline.js` | `p(99)<5` ms allow latency; `rate>5000` rps; `rate>0.999` allow success |
| `mixed-tiers.js` | CRITICAL fail-closed count == 0 |
| `ddos-burst.js` | `p(95)<2000` ms auto-block latency |
| `security-toggle-flips.js` | `rate>0.95` blocked when SQLi on; `rate>0.95` allowed when SQLi off |
| `risk-strikes.js` | `rate==1` strike-block reached; `rate==1` clean req still blocked |
| `loadmode-degradation.js` | `rate>0` `auto_critical_observed` |
| `verbosity-pin.js` | `count==0` audit entries during silent window |

### Soak-test variants

Each script accepts `DURATION=` to extend the run for soak
testing. Bump CI runs back to 30–60 s; reserve 30+-minute soaks
for nightly jobs.

## 7. Layer 4 — Attack replay + scanners

Long-running, network-heavy. Don't run on every commit; nightly
or pre-release.

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
`tests/security/corpus/{benign,malicious}/` and an `INDEX.md`
in each subdirectory tracks source + attack class.

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
3. Read admin creds from `__ENV.ADMIN_USER` / `__ENV.ADMIN_PASS`.
4. End the test by reverting any state it changed (override,
   strike, mask flip). Idempotency is mandatory.
5. Update `tests/README.md` SLO table.

### Adding a corpus sample

See `tests/README.md` § "Adding a corpus sample".

## 9. CI pipeline reference

Recommended stage layout:

```
stage 1  cargo fmt --check + cargo clippy --workspace -- -D warnings
stage 2  cargo test --workspace
stage 3  bring up dev gateway + tests/api/run-all.sh
stage 4  k6 baseline.js + ddos-burst.js + the four P-track scenarios
stage 5  (nightly) corpus/{benign,malicious} + Nuclei + ZAP
```

Stages 1–4 should land within ~5 minutes on a moderately-sized
runner. Stage 5 runs nightly because the scanners are slow and
add no PR-level signal.

## 10. Troubleshooting

| Problem | Where to look |
|---|---|
| `aegis-bin` won't start | `cargo run -p aegis-bin -- check --config config/waf.dev.yaml` |
| Port 9443 already in use | `lsof -i :9443` — usually a stale gateway process |
| k6 can't reach the gateway | `host.docker.internal:8080` requires Docker Desktop or `--add-host` |
| `tests/api` returns 401 | session cookie missing; check `ADMIN_USER` / `ADMIN_PASS` |
| Audit chain integrity fails | every chain entry must hash from the previous; re-run `cargo run -p aegis-bin -- audit verify` |
| ACME tests fail with "tls handshake" | the rustls feature flag is off-by-one; `instant-acme` must be built with `aws-lc-rs`, not `ring` (see `Cargo.toml`) |
| Strike test clean-block-fails | `risk.strikes.block_at` in `config/waf.dev.yaml` must match `STRIKE_LIMIT` env in the k6 run |

## 11. Reference: documentation map

The features under test are documented across:

- [`docs/USAGE.md`](../docs/USAGE.md) § Security Toggles — operator guide + curl examples
- [`docs/dashboard-enterprise/api.md`](../docs/dashboard-enterprise/api.md) § Security toggles — request/response shapes
- [`docs/risk-scoring.md`](../docs/risk-scoring.md) — P6 strikes + trust recovery
- [`docs/tls-termination.md`](../docs/tls-termination.md) — P4 hardening + P5 ACME
- [`docs/audit-logging.md`](../docs/audit-logging.md) — P1 AuditedMutate + P8 verbosity gating
- [`docs/adaptive-load-shedding.md`](../docs/adaptive-load-shedding.md) — P7 LoadMode
- [`docs/graceful-degradation.md`](../docs/graceful-degradation.md) — P7/P8 degraded logging
- [`docs/siem-log-forwarding.md`](../docs/siem-log-forwarding.md) — P8 cold-tier surface
- [`Implement-Progress.md`](../Implement-Progress.md) — phase-by-phase changelog
