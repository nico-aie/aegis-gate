---
id: 2026-05-17-dead-code-modules-shed-quota-dr-traffic
date: 2026-05-17T00:00Z
severity: CRITICAL
area: documented-but-unimplemented features
component: crates/aegis-proxy/src/shed.rs · crates/aegis-proxy/src/quota.rs · crates/aegis-proxy/src/dr.rs · crates/aegis-proxy/src/traffic.rs
interop_contract: Round 1 stability + body limits · Round 3 graceful degradation + bonus features
status: open
test_mode: source-review (verified by zero-hit grep)
---

# F-CRITICAL-006 · Four advertised feature modules have ZERO callers — load shedding, body limits, snapshot/restore, traffic mirroring are non-functional

## Summary

Four modules in `aegis-proxy/src/` are publicly advertised in
`README.md` / `Architecture.md` but contain no call sites anywhere
else in the crate or workspace. They compile, are tested in isolation,
ship in the binary — but nothing wires them into the request path or
the operator surface. The advertised features simply do not exist at
runtime.

| Module | Lines | Advertised as | Actually used? |
|---|---|---|---|
| [shed.rs](../../../../crates/aegis-proxy/src/shed.rs) | 262 | "Graceful degradation under load" (Round 3) | ❌ Zero callers |
| [quota.rs](../../../../crates/aegis-proxy/src/quota.rs) | 171 | `client_max_body_size`, `max_uri_length`, `max_header_size` from config | ❌ Zero callers |
| [dr.rs](../../../../crates/aegis-proxy/src/dr.rs) | 170 | DR / snapshot / restore | ❌ Not used by `waf snapshot` CLI either |
| [traffic.rs](../../../../crates/aegis-proxy/src/traffic.rs) | 326 | Canary / shadow / mirror traffic, retry-budget | ❌ Zero callers |

**Verified** with grep across `crates/`:

```sh
grep -rn 'LoadShedder\|check_request_quota\|aegis_proxy::dr\|CanarySplitter\|RetryBudget\|should_mirror' \
    crates/ --include="*.rs" \
    | grep -v 'src/shed.rs\|src/quota.rs\|src/dr.rs\|src/traffic.rs'
# Zero hits.
```

Additionally, `shed.rs` itself has a fundamentally broken gradient
algorithm (filed in F-HIGH-lifecycle) — even if you wire it in, it
won't work correctly.

## Per-module detail

### shed.rs

File header docstring (`shed.rs:1-10`):

> *"Per-pool latency-aware shedder. Sheds requests when upstream
> latency exceeds a configured ceiling. Shed response: 503 +
> `Retry-After` + request id, zero pipeline cost."*

`LoadShedder::should_admit(...)`, `record_rtt(...)` exist. Nothing in
`accept.rs`, `data_plane.rs`, `proxy.rs`, or `forward.rs` calls them.
Round 3 "graceful degradation" scoring depends on observing actual
shedding under stress — there is none.

### quota.rs

File header docstring (`quota.rs:1-7`):

> *"Per-request quota enforcement: client_max_body_size,
> max_uri_length, max_header_size. Reads `cfg.quotas` and returns
> a 413 / 431 short-circuit when exceeded."*

`check_request_quota(...)` exists. Zero callers. The config fields
`cfg.quotas.client_max_body_size`, `max_uri_length`,
`max_header_size` are parsed at boot and ignored at request time.

This compounds with the previous-audit finding F-CRITICAL-004
(1 MiB hard-coded body cap in `data_plane.rs:180`): there's an
in-pipeline cap that fires (causing FPs on legitimate large
bodies), and an operator-config cap that doesn't fire (so the
operator's tuning has no effect). Worst of both worlds.

### dr.rs

File header docstring claims tar.zst + cluster-key-signed bundle.
The actual code (`dr.rs:36-93`) writes `[u32 LE meta_len][meta_json][config_bytes]`
— no magic number, no version envelope, no integrity hash, no
signature, no compression.

The CLI sub-commands `waf snapshot` and `waf restore`
([aegis-bin/src/snapshot.rs](../../../../crates/aegis-bin/src/snapshot.rs)) do NOT import `aegis_proxy::dr`. They
have their own implementation entirely. So the `dr` module is
double-dead: nobody calls it, and a separate parallel implementation
exists for the same feature.

Even within `dr.rs`, `dry_run_validate` only checks YAML
well-formedness, not WafConfig schema — a literal `{}` would pass
validation and would (if `dr.rs` were ever called) wipe the entire
config on restore.

### traffic.rs

Contains `CanarySplitter`, `RetryBudget`, `ShadowConfig`,
`should_mirror`, all referenced only by `traffic.rs`'s own tests.

Bugs INSIDE traffic.rs that would matter if it were wired:

- `CanarySplitter::pick` at line 64 returns `entries.last().unwrap()` — panics on empty `entries` vec; constructor at line 22 has no empty-check.
- `should_mirror` at line 172: `(cfg.sample_rate * 100.0) as u64` truncates `sample_rate=0.005` to threshold=0, never mirrors.
- `RetryBudget::try_retry` at lines 108-125 is not atomic — two threads can both see `ratio < max_ratio` and both increment, exceeding the budget.

## Impact

The standalone severity of unwired-but-buggy code would be MEDIUM
(code rot). The CRITICAL rating comes from:

1. **README veracity collapses.** A QA tester or BTC reviewer who
   verifies these features finds them non-functional. The README's
   trustworthiness on any other claim becomes suspect — they may
   start re-verifying every other feature claim, and the WAF
   doesn't survive that scrutiny well (see the rest of this audit).

2. **Round 1 stability** depends on quota enforcement to prevent
   abusive payloads (combined with `data_plane.rs`'s 1-MiB cap,
   the operator has no path to a working body-size policy — they
   either get the broken 1-MiB false-positives or no enforcement
   at all if they "fix" it by removing the 1-MiB check).

3. **Round 3 graceful degradation** requires actual load shedding.
   The README explicitly claims this. With the module dead, the
   WAF cannot demonstrate the behavior the scoring asks for.

4. **Operator quality scoring** (Round 3 bonus) typically credits
   features like DR snapshot / canary / mirror that the README
   markets. Each one is a free score the WAF leaves on the table —
   and BTC may treat the README claim as misrepresentation if they
   probe.

## Suggested fix

For each module, pick one of two paths:

### Path A — Wire it in

For `quota.rs`: call `check_request_quota(&req, &cfg.quotas)` at
the top of `data_plane::handle_data_request` and return its 413/431
short-circuit through `stamp_interop_response` so the 6 §5 headers
are present. Then RAISE the `data_plane.rs:180 MAX_BODY_BYTES` cap
to a defensive ceiling (e.g. 256 MiB) so the operator-config cap
is the effective limit.

For `shed.rs`: fix the gradient algorithm (see F-HIGH-lifecycle
item M4), then call `should_admit()` in the accept loop before
dispatching to the pipeline.

For `dr.rs`: either replace the existing `aegis-bin/src/snapshot.rs`
with the `dr.rs` implementation (after adding the magic number +
schema check + audit emit), or delete `dr.rs` outright.

For `traffic.rs`: wire `should_mirror` into the forward path; fix
the off-by-100 truncation bug; add an empty-list guard to
`CanarySplitter`.

### Path B — Delete and update README

If these features aren't going to ship in time, delete the modules
(or `#[cfg(false)]` them out of `lib.rs`) and remove the README
sections that advertise them.

The half-shipped state — modules present, advertised, but unused —
is the worst option because it implies fitness-for-purpose without
delivering.

## Verification

Pick the path. If A:

```sh
# After wiring quota.rs: send a 2 MiB POST when config says
# client_max_body_size=1MiB → expect 413.
curl -sk -X POST "$HOST/upload" \
    --data-binary @<(head -c 2M /dev/urandom) -w "%{http_code}\n"
# Expect 413; expect X-WAF-Rule-Id: quota.body_size; expect audit
# entry with action=block.

# After fixing shed.rs: induce upstream latency above the ceiling
# and observe 503 + X-WAF-Action: circuit_breaker (NOT block).

# After fixing dr.rs (or moving to snapshot.rs):
./waf snapshot --output /tmp/snap.bundle
./waf restore --from /tmp/snap.bundle
# Should print a per-field diff, emit an audit-chain entry for the
# restore, refuse to restore if WafConfig schema validation fails.
```

If B: removing dead code is a quiet PR. Update README's
"Performance", "Operations", and "Architecture" sections to remove
claims that no longer match the binary.

## Severity rationale

CRITICAL on the collective basis of README misrepresentation +
Round-1/3 scoring impact. Each individual module standalone is
HIGH-to-MEDIUM. Bundled because they share a root cause (advertised
without wiring) and the same fix decision (wire or delete).
