# AI-Assistant Testing Guide

> Long form. The terse do/don't sheet is
> [`AI-ASSISTANT-RULES.md`](./AI-ASSISTANT-RULES.md). Read the rules
> first; come here for the rationale, the workflow, and the review
> checklist.

This guide is for any AI assistant (Claude / Cursor / Copilot /
custom agent) that is asked to **write, modify, or review tests**
in this repository. Humans should read it too — most of the
"don'ts" come from real failure modes we've seen in the repo's
history.

## Why this guide exists

LLMs are very good at producing tests that *look* like tests and
*compile* and *pass* — and that test absolutely nothing of value.
The failure modes we've hit:

1. **Test mirrors implementation.** "Make sure `add(2, 2)` returns
   `4`" — but the implementation says `a + b`. The test verifies
   the LLM read the function name, not that the contract holds.
2. **Mocks tell the test what to assert.** A mock returning `OK`
   then asserting `was_called(OK)` is a tautology with extra
   ceremony.
3. **Snapshot of a fictional response.** The LLM imagines what
   the API "probably" returns, hand-types it, asserts equality.
   First time the API actually runs, the snapshot is wrong.
4. **Coverage padding.** 50 tests for `User::new` covering every
   permutation of empty / null / negative / unicode — none
   exercise the rule that fired the bug last week.
5. **Flaky-test acceptance.** "Sometimes this fails — adding
   `#[ignore]` for now." The bug doesn't go away because the
   test stopped looking for it.

The rules in `AI-ASSISTANT-RULES.md` exist to prevent each of
these. This guide explains how to use them in practice.

---

## Workflow — the order of operations matters

When asked to add or improve tests in this repo, an AI assistant
must follow this sequence:

### 1. Restate the actual contract being tested

Before writing any test code, write — in a comment or in the PR
description — a one-paragraph statement of the contract:

> "When the WAF receives a request whose body matches the
> mass-assignment pattern, the body_abuse detector should fire;
> the request should be blocked with HTTP 403 and
> `x-waf-action: block`; an audit-chain entry should be appended
> with the matched pattern."

If you can't write this paragraph, you don't have enough
understanding to write the test. Stop and ask the human.

### 2. Find the existing test that's closest in shape

Don't reinvent the harness. Search:

```sh
grep -rln "body_abuse" tests/ crates/*/tests/ crates/*/src/
```

Pick the closest analogue and copy its scaffolding (imports,
fixtures, async-runtime setup, teardown). The repo conventions
were validated when the original was written; reinventing them
breaks consistency.

### 3. Write the test in this order

Always:

1. **Arrange** — set up the world (config, mock upstream,
   fixtures).
2. **Act** — make the single call that exercises the contract.
3. **Assert** — check the *behaviour* the contract promises, in
   the order: status code → headers → body → side effects
   (audit chain, metrics).

If the test exceeds ~30 lines, you're testing too much in one
test. Split.

### 4. Run the test in three modes

Before declaring done:

```sh
# (a) New test passes
cargo test -p <crate> <test_name> -- --nocapture

# (b) New test isolation — run it alone, then with the suite
cargo test -p <crate> <test_name>
cargo test -p <crate>

# (c) Determinism — run the new test 10 times in a row
for i in {1..10}; do cargo test -p <crate> <test_name> || break; done
```

If any of these fail, the test is broken. Fix it before the human
reviews.

### 5. If it's security-relevant, add the boundary

For any test that involves a *threshold* — risk score, rate-limit
budget, brute-force window, etc — also write the **just-below**
and **just-above** cases. The boundary is where bugs hide.

Example pattern (from `crates/aegis-security/src/detectors/brute_force.rs`):

```rust
#[test]
fn fires_at_threshold() {
    let det = BruteForceDetector::new(10, Duration::from_secs(60));
    for _ in 0..10 { det.observe(IP, "/login"); }
    let result = det.observe(IP, "/login"); // 11th
    assert!(result.is_some());
}

#[test]
fn does_not_fire_below_threshold() {
    let det = BruteForceDetector::new(10, Duration::from_secs(60));
    for _ in 0..9 { det.observe(IP, "/login"); }
    let result = det.observe(IP, "/login"); // 10th — still ≤
    assert!(result.is_none());
}
```

---

## Test types — when to use which

| Type | Where | When |
|------|-------|------|
| **Unit test** (`#[cfg(test)] mod tests`) | inside the crate's `.rs` file | Pure functions; small data transforms; algorithms with clear input → output |
| **Integration test** (`crates/<crate>/tests/<file>.rs`) | one binary per `.rs` file | Cross-module within a crate; behaviours that need a tokio runtime + fixtures |
| **HTTP API contract** (`tests/api/*.sh`) | shell + curl | Verifying admin/data plane endpoints accept/reject the right shapes |
| **Cluster / failover** (`tests/cluster/*.sh`) | shell | Multi-node behaviours (lease handover, drain, VIP routing) |
| **Stress / load** (`tests/load/*.js` or `tests/hackathon/`) | k6 | Throughput, latency under load, detection rate at high RPS |
| **Multi-protocol** (`tests/protocols/*.sh`) | shell | h1 / h2 / h3 / WebSocket / gRPC parity |
| **Dashboard E2E** (`tests/dashboard/*.{mjs,js}`) | Playwright | Console UX flows, screenshot regressions |
| **Round-2 contract gate** (`tests/contract/v2.3_compliance.sh`) | shell | The 40-check external interop regression |

When in doubt: start with the integration test. It catches the
most real bugs per test written.

---

## Mocking — what to mock, what NOT to mock

### Mock these (system boundaries)

- **Network** — when testing logic that "what if the upstream is
  slow", a mock upstream that sleeps is correct.
- **Disk** — `tempfile::tempdir()` for any fixture path.
- **Clock** — `tokio::time::pause()` + `advance()` for time-based
  logic. Never `sleep` for real durations in tests.
- **Random** — seed-able RNG; deterministic inputs.
- **External APIs** — secret managers, threat-intel feeds, ACME
  CAs are mocked via the existing trait abstractions.

### Don't mock these (the system under test)

- **The detector you're testing.** A `body_abuse` test should
  feed a real request through `BodyAbuseDetector::evaluate`.
- **The audit chain.** Use the real chain; assert the entries
  that were written. The chain is the contract.
- **The config loader.** Use a real `WafConfig::from_str(yaml)`
  with a tiny inline YAML.
- **Redis** — for tests that exercise the Redis state backend
  path, run against the local docker Redis (`make redis-up`).
  Mocking Redis hides serialization bugs.

### The litmus test

> "If I delete the implementation and the test still passes,
> the test is mocking too much."

Run this thought experiment before committing.

---

## Coverage — the right way to think about it

Coverage as a *target* is wrong. Coverage as a *side effect* of
meaningful tests is fine. Specifically:

- The 80 % coverage rule in `~/.claude/rules/common/testing.md`
  is for production code paths, not for hand-coded boilerplate
  (Default impls, derive output, simple getters).
- 100 % coverage of a function with one trivial test is worse
  than 60 % coverage with three meaningful tests.
- The real metric is **mutation score**: if I change the `==`
  to `!=` in the implementation, does any test fail? If not,
  the tests aren't really exercising that line.

When the AI generates tests, ask it: "for each test, what
mutation in the production code would this catch?" If the
answer is "I'm not sure," the test is probably padding.

---

## Review checklist for AI-generated tests

When the AI hands you a batch of tests, walk this list before
merging. The first three are non-negotiable.

### Non-negotiable

1. **Does the test exercise a real contract?** Can the
   reviewer state, in one sentence, what the test is for?
2. **Is the assertion specific?** `result.is_ok()` is rarely
   enough.
3. **Is it deterministic?** Run it 10× in a loop. Any flake = fix.

### Important

4. **Names** — describe behaviour, not implementation.
5. **Boundaries** — security/threshold tests have just-below
   + just-above cases.
6. **No mocking of the system under test.**
7. **Hot-paths use the real code path** — don't bypass the
   security pipeline in security tests.
8. **Fixtures are external** — long inputs live under
   `tests/fixtures/`, not inline string constants.

### Good-to-have

9. **AAA structure** with blank-line separators when test > ~10 lines.
10. **`#[rstest]`** for parametric cases instead of N near-identical tests.
11. **Comments only when behaviour is non-obvious** — most tests
    don't need any.
12. **Cleanup** — `tempfile`, `tokio::test` block on
    `runtime.shutdown()`, no leaked Redis keys.

---

## Common request shapes — how to handle them

### "Add tests for module X"

Don't generate tests by reading the module's signatures. Instead:

1. Run `git log --oneline -- crates/<crate>/src/<module>.rs` to
   find the recent bugs / features. Each bug or feature is a
   candidate test.
2. Look for `// TODO: test` or `// FIXME` comments — those are
   the author's own flagged gaps.
3. Look at adjacent modules' test files for the test style.

### "Increase coverage of crate Y"

Push back. Coverage isn't the goal; behaviour assertions are.
If the human really wants this, ask: "what's the specific
behaviour you're worried isn't covered?" then test that.

### "Convert this test to use mocks for speed"

Push back. Speed of tests is a real concern — but the fix is
usually parallelism (`cargo test --test-threads=N`), not mocks.
Mocks at the wrong boundary make tests faster *and* useless.

### "This test is flaky — disable it"

Reproduce locally first:

```sh
for i in {1..50}; do cargo test -p <crate> <test_name> || { echo "FAILED at run $i"; break; }; done
```

If it really is flaky, file an issue and:

```rust
#[ignore = "TODO(#NN): flaky in CI; race in <reason>"]
```

Never `#[ignore]` bare.

### "Generate property-based tests with proptest"

Good instinct, but be careful. A useful proptest needs:

- A **shrinkable** generator that produces inputs that *look like
  real attack payloads*, not random bytes.
- A **specific oracle** — what property must hold? "Doesn't crash"
  is rarely enough; "produces the same result as a reference impl"
  is much better.

Look at `crates/aegis-security/src/detectors/sqli.rs` for a
proptest that does this right.

---

## Working with the user

If you're an AI assistant and the user asks for tests:

1. **Confirm the contract** before writing anything. One
   sentence is enough.
2. **Show your hand** — list the tests you intend to write
   *before* writing them, in 1-line summaries. Let the user
   correct you cheaply.
3. **Run them yourself** — every test in this guide assumes
   you've actually run the test you wrote, not just typed it.
4. **Report exactly** — "added 4 tests, all green; coverage
   on `body_abuse` went 71% → 84% but more importantly the
   mass-assignment regex now has both positive and negative
   boundary cases." Numbers + behaviour, not just numbers.

If at any point you're unsure, say so. A test you're unsure
about is worse than no test — it'll get cargo-culted into 50
copies.

---

## Cross-references

- [`AI-ASSISTANT-RULES.md`](./AI-ASSISTANT-RULES.md) — terse rules sheet
- [`tests/README.md`](./README.md) — test-suite catalogue
- [`Implement-Progress.md`](../Implement-Progress.md) §"AI-Assistant
  testing track" — current sprint state for this work
- [`docs/operator/profiles.md`](../docs/operator/profiles.md) — what
  "prod-balanced" means; tests should be honest about which profile
  they assume
- [`~/.claude/rules/common/testing.md`](https://example.invalid)
  — the global testing rules that apply across projects
