# Rules for AI assistants working in `tests/`

> **Read this first** before writing or modifying any test in this
> repository. Compact do/don't sheet — the long version with
> rationale, workflow, and review checklist lives in
> [`AI-ASSISTANT-GUIDE.md`](./AI-ASSISTANT-GUIDE.md).

## Hard rules — never violate

1. **Tests are not generated speculatively.** A test exists because
   a real behaviour, requirement, or bug demanded it. Do not add a
   test "for completeness" or "to raise coverage."
2. **Never hand-author snapshot fixtures from your imagination.**
   Snapshots come from running the system. If you write a snapshot
   by typing what you think the output looks like, the test is
   worse than no test.
3. **Never weaken an assertion to make a test pass.** If the test
   says `assert_eq!(score, 80)` and the code returns 75, fix the
   code or change the test's *expectation rationale*. Don't drop
   to `>=` to make the failure go away.
4. **Never delete or skip a failing test without an issue link.**
   Quarantine via `#[ignore = "TODO(<issue>): <one-line why>"]`
   only — never `#[ignore]` bare.
5. **No mocking the system under test.** Mock the *boundary*
   (network, disk, clock). Don't mock `aegis-security` from a
   `aegis-security` test.
6. **No real secrets in fixtures.** Use the existing test
   credentials in `config/dev.yaml` (`admin / aegis-test-1234`,
   the literal CSRF secret). If a new secret-shaped value is
   needed, generate one obviously fake.
7. **Tests must be deterministic.** No real wall-clock dependencies
   (use `tokio::time::pause()` / explicit clocks); no random ports
   without retry; no order-dependent state across tests.
8. **Stay inside the conventions of the surrounding crate.** If
   `aegis-proxy` uses `#[tokio::test]` + `Reqwest`, don't introduce
   `hyper-test` for one new test.

## Soft rules — strong default, only break with reason

- Prefer **integration tests** (full pipeline through `aegis-proxy`)
  over unit tests when verifying request-handling behaviour. Unit
  tests are for pure functions and small data transforms.
- One assertion per behaviour, not per line. A test with 12
  unrelated `assert!`s is two tests pretending to be one.
- Test names describe behaviour, not implementation:
  `rejects_request_when_score_exceeds_block_threshold`, not
  `test_score_check_2`.
- Use the AAA pattern (Arrange–Act–Assert) with blank-line
  separators when the test exceeds ~10 lines.
- New end-to-end test fixtures live under `tests/fixtures/`,
  *not* embedded in the test file as multi-line strings.
- Hot-loop perf assertions (latency, throughput) belong under
  `tests/load/` or `tests/hackathon/`, never in unit tests.

## When you must touch detection / security tests

These are the highest-stakes tests in the repo:

- **Detector mask coverage** (`crates/aegis-security/src/detectors/*`)
- **Audit-chain integrity** (`crates/aegis-control/src/audit/*`)
- **Hot-reload semantics** (`crates/aegis-proxy/src/run.rs`,
  `accept.rs`)
- **mTLS identity extraction** (`aegis-proxy/src/tls_policy.rs`,
  `client_trust.rs`)

For these, **always** include both:

1. A negative test (the attack should be detected / the bad
   identity rejected).
2. A boundary test (the value just below the threshold should NOT
   trip; the value just above should).

If in doubt, copy an existing detector's test layout — they're
the validated pattern.

## Hackathon / stress-test boundary

`tests/hackathon/` runs synthetic load against a single source IP.
The configs there (`tests/hackathon/configs/*.yaml`) deliberately
override prod-balanced thresholds + disable `brute_force` because
shared-IP harnesses trip those false-positively. **Do not** copy
those overrides into `tests/api/`, `tests/cluster/`, etc — those
suites simulate real fan-out and need the production thresholds
intact.

## Build / run the test you wrote

Before declaring a test "done":

```sh
cargo test -p <crate> <test_name>     # the new test passes
cargo test -p <crate>                 # the rest still passes
cargo clippy -p <crate> -- -D warnings   # no new lints
```

For integration / shell-based suites:

```sh
make redis-up                              # most need Redis up
bash tests/<suite>/<your-script>.sh        # explicit invocation
```

If your test needs the WAF running, use the existing patterns in
`tests/api/openapi-shape.sh` or `tests/hackathon/run.sh`. Do not
spawn `cargo run` from inside a test process.

## What to NOT do — concrete failure modes seen in this repo

| Anti-pattern | Why it's wrong | Do this instead |
|---|---|---|
| `#[ignore]` to "skip flaky tests" | Hides real bugs; flaky → fix the determinism | Reproduce locally; if you can't, file an issue and `#[ignore = "TODO(#NN): …"]` |
| Asserting `result.is_ok()` and stopping | The error path is half the test | `assert_eq!(result.unwrap(), expected)` or pattern-match the variant |
| Pasting full HTTP responses as snapshot strings | Brittle on header reorder, locale, version | Assert the specific field that matters |
| Increasing timeouts to "fix" a test | Masks a real perf regression | Find the slow path; assert behaviour, not wall time |
| Generating 50 similar tests via `rstest` table when one parametric is enough | Inflates the count, not the signal | One `#[rstest]` with the cases inline |
| Calling production endpoints from a test (`api.example.com`) | Tests must be hermetic | Hit the local `aegis-mock` upstream or the WAF data plane on `127.0.0.1` |

## Where to file new tests

| Subject | Location | Style |
|---|---|---|
| Pure logic in one crate | `crates/<crate>/src/<mod>.rs` `#[cfg(test)] mod tests` | unit |
| Cross-crate behaviour | `crates/<crate>/tests/<scenario>.rs` | integration (binary per file) |
| HTTP API contract | `tests/api/<endpoint>.sh` | shell + curl |
| Multi-protocol (h1/h2/h3/WS/gRPC) | `tests/protocols/` | shell |
| Cluster / failover | `tests/cluster/` | shell |
| Stress / load | `tests/load/` (k6) or `tests/hackathon/` (15-min) | k6 / harness |
| Round-2 contract gate | `tests/contract/v2.3_compliance.sh` | shell + curl |
| Dashboard E2E | `tests/dashboard/` | Playwright |

## Checklist before opening a PR with new tests

- [ ] Each test name describes behaviour, not implementation
- [ ] AAA structure (or trivially short)
- [ ] Negative + boundary cases for security-relevant code
- [ ] No new `#[ignore]` without an issue link
- [ ] No real secrets / production hostnames
- [ ] Determinism verified (run the suite twice, both pass)
- [ ] Coverage *as a side effect* of meaningful tests, not the goal
- [ ] `cargo clippy -p <crate> -- -D warnings` is clean
- [ ] If integration/shell: ran end-to-end on a fresh `make run-dev`

When in doubt, ask in the PR: "is this exercising a real behaviour
or am I writing a tautology?"
