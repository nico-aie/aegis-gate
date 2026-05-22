---
id: 2026-05-17-canary-endpoint-doesnt-block-ip
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · canary / honeypot
component: crates/aegis-security/src/risk/mod.rs (Signal handling) · risk/tracker.rs
interop_contract: official rules §5.5 (canary → MAX score + immediate IP block) · Attack Battle scenario 08
status: open
test_mode: source-review
---

# F-CRITICAL-007 · Canary endpoints don't actually block IPs — only matches the literal Signal tag `"recon_path"`, never calls `auto_block`

## Summary

Official rules §5.5 are unambiguous:

> *Canary Endpoint / Honeypot: deploy decoy paths (/admin-test,
> /api-debug). **Bất kỳ request nào hit = auto set risk score = MAX,
> block IP ngay**.*

Two distinct mandates: (a) MAX risk score, (b) immediate IP block.

Shipped code does NEITHER:

- There is no path-list of canary endpoints; the only canary signal
  is a hardcoded tag match `Signal::tag == "recon_path"`
  ([risk/mod.rs:24-27](../../../../crates/aegis-security/src/risk/mod.rs#L24-L27)).
- When that tag matches, the code sets `score = max_score`
  ([risk/mod.rs:60-65](../../../../crates/aegis-security/src/risk/mod.rs#L60-L65))
  but does NOT call `state.auto_block(ip, ttl)`. So subsequent
  requests from the same IP are NOT blocked at the gate — they're
  only re-evaluated through the normal pipeline.
- The "recon_path" tag is only emitted by the `recon` detector
  (`detectors/recon.rs`), which fires on a long path list of CVE-ish
  endpoints. Operators have no way to add their own canary paths
  (e.g. `/admin-test`, `/api-debug` named in the rules) without
  modifying the recon detector's source.

Attack Battle scenario 08 ("Canary / Recon Scan") explicitly tests
canary-endpoint + recon behavior. The current implementation will:

- Bump risk score for one IP (good).
- Not propagate that into an immediate IP block (bad).
- Not allow operator-defined canary path lists (worse).

## Observed code path

[risk/mod.rs:24-27](../../../../crates/aegis-security/src/risk/mod.rs#L24-L27):

```rust
fn is_canary(signal: &Signal) -> bool {
    signal.tag == "recon_path"
}
```

[risk/mod.rs:60-65](../../../../crates/aegis-security/src/risk/mod.rs#L60-L65):

```rust
if signals.iter().any(is_canary) {
    state.set_score(ip, max_score);
    // No `state.auto_block(ip, ttl)` call here.
}
```

No reference to `auto_block` in the canary path. No config-driven
canary path list. The `recon` detector's path list is the only
source of the `"recon_path"` tag.

## Impact

- **§5.5 canary requirement** — half-implemented (score only, no
  block).
- **Intelligence rubric (20/120)** — canary behavior is explicitly
  enumerated as scored.
- **Attack Battle scenario 08** — Red Team scans canary paths
  expecting immediate IP block; observes only a single-request
  rejection followed by continued access from the same IP.
- **Operator usability** — there's no `cfg.security.canary_paths` to
  configure. The example paths named in the spec (`/admin-test`,
  `/api-debug`) aren't recognized as canaries unless operators add
  them to the recon detector's source code.

## Suggested fix

### Add a config-driven canary path list

```rust
// aegis-core/src/config.rs
pub struct CanaryConfig {
    pub paths: Vec<String>,                  // exact or glob
    pub auto_block_ttl: Duration,            // e.g. 1 hour
    pub broadcast_to_cluster: bool,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            paths: vec![
                "/admin-test".into(),
                "/api-debug".into(),
                "/.git".into(),
                "/.env".into(),
                "/wp-admin".into(),
                "/phpmyadmin".into(),
            ],
            auto_block_ttl: Duration::from_secs(3600),
            broadcast_to_cluster: true,
        }
    }
}
```

### Add an early canary check in the pipeline

Front-load the canary check BEFORE detectors run — minimal cost and
maximizes signal value:

```rust
// pipeline.rs (or data_plane.rs) — near the top of request handling.
if cfg.canary.paths.iter().any(|p| path_matches(p, req.uri().path())) {
    risk_tracker.set_score_at(ip, /* max */ u32::MAX);
    state.auto_block(ip, cfg.canary.auto_block_ttl).await.ok();
    audit_emit(AuditEntry {
        action: "block",
        rule_id: "canary.honeypot_hit",
        ...
    });
    return build_403_response();
}
```

### Make subsequent requests honor the auto-block

Verify the data-plane gate consults `StateBackend::is_blocked(ip)`
at request entry. If F-HIGH-rate-limit-ddos M-? (the `state` backend
might have its own bugs) is fixed first, the auto-block will
actually take effect on the second request from the same IP.

## Verification

```sh
HOST="http://127.0.0.1:8080"

# Probe a canary path:
curl -ski "$HOST/admin-test" -o /dev/null -w "first=%{http_code}\n"
# Expect: 403 (immediate block).

# Subsequent request from the SAME IP to a benign path — must be blocked:
curl -ski "$HOST/" -o /dev/null -w "after_canary=%{http_code}\n"
# Expect: 403 (IP auto-blocked).
# Today: 200 (gate doesn't honor canary's risk burst).

tail -2 ./waf_audit.log | jq '{action, rule_id, ip}'
# Expect: action=block, rule_id=canary.honeypot_hit on first;
#         action=block, rule_id=blacklist.auto on second.
```

Regression case in `tests/security/canary.sh`:

- Hit canary path → assert immediate 403.
- Immediately request any other path from same IP → assert 403.

## Severity rationale

CRITICAL. Half-implemented honeypot is worse than none — operators
THINK canary paths block attackers and configure CSPs / observation
flows around that assumption. Trivial fix: add a path list + one
`auto_block` call at the front of the pipeline. ~30 LoC.
