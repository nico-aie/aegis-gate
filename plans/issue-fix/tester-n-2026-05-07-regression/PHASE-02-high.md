# Phase 2 — HIGH fixes (rerun)

> **Branch:** all changes target `develop`.

---

## NEW-2 · Challenge response body insufficient for automated solving (contract violation)

**Source:** Run-2 §2 NEW-2.
**Contract ref:** v2.3 §3 — *"Return a challenge response, typically 429, with enough information for automated challenge solving."*

### Verified state (2026-05-08, on `develop`)

- `crates/aegis-proxy/src/data_plane.rs:601-621` — challenge body today contains only `challenge_type: "proof_of_work"`. No nonce, difficulty, submit_to, expires_at.
- `crates/aegis-security/src/challenge/token.rs` — `ChallengeTokens` exists (HMAC-signed nonce, single-use via `state.consume_nonce`). It's an opaque-cookie scheme, not a difficulty-based PoW.
- No `/__waf_control/challenge_verify` (or equivalent) endpoint exists. Grep across `admin_dispatch.rs` + `data_plane.rs` confirms.

The QA's contract-compliance call is correct. An automated client cannot complete the challenge flow today — the body advertises a PoW type but provides no parameters and no submission endpoint.

### Design decision

Two paths to "enough information for automated solving":

| Option | Shape | Effort |
|---|---|---|
| **A. Real difficulty-based PoW** | Server emits `{nonce, difficulty, expires_at}`. Client iterates `counter` until `blake3(nonce + counter)` has ≥ `difficulty` leading zero bits. Submits `{nonce, counter}` to verify endpoint. | ~5 h (new code path + nonce store + verify endpoint + tests) |
| **B. Opaque-token "challenge cookie"** | Server emits an HMAC-signed token (existing `ChallengeTokens::issue`) + `submit_to`. Client just resends with the token in a header. No actual computation. | ~2 h (reuse existing machinery, just plumb to body + verify) |

**Recommend Option A.** The contract calls the type `proof_of_work` — Option B's "no computation" semantics would still pass the body shape but a benchmark verifier inspecting the response would see `difficulty: 0` (or absent) and conclude we didn't implement PoW. Option A gives a real cost-of-failure for attackers.

The existing `ChallengeTokens` machinery is **kept and reused** for nonce single-use enforcement (the Lua `consume_nonce` primitive is already there in `state/redis.rs`). PoW just adds a difficulty field on top.

### Plan

**Step 1 — define the wire shape.**

```rust
// crates/aegis-proxy/src/data_plane.rs (challenge body)
serde_json::json!({
    "challenge": true,
    "challenge_type": "proof_of_work",
    "nonce": nonce_hex,                          // 32 hex chars
    "difficulty": difficulty_bits,               // u8, default 16
    "submit_to": "/__waf_control/challenge_verify",
    "expires_at": expires_iso8601,               // RFC 3339
    "reason": "risk score over challenge threshold",
})
```

**Step 2 — extend `ChallengeTokens` with PoW issuance.**

```rust
// crates/aegis-security/src/challenge/token.rs
pub struct PowChallenge {
    pub nonce: String,           // 32 hex chars
    pub difficulty: u8,           // leading zero bits
    pub expires_at: i64,          // unix ms
}

impl ChallengeTokens {
    /// Issue a PoW challenge. Stores the nonce so verify can
    /// single-use-consume it. Difficulty defaults to 16 leading
    /// zero bits (~65 K hashes on average to solve).
    pub async fn issue_pow(
        &self,
        state: &dyn StateBackend,
        key: &RiskKey,
        difficulty: u8,
    ) -> aegis_core::Result<PowChallenge> { ... }

    /// Verify a PoW solution. Validates: (a) nonce exists in store
    /// (single-use), (b) blake3(nonce + counter) has ≥ difficulty
    /// leading zero bits, (c) not expired. Consumes the nonce on
    /// success.
    pub async fn verify_pow(
        &self,
        state: &dyn StateBackend,
        nonce: &str,
        counter: &str,
        difficulty: u8,
    ) -> Result<(), TokenError> { ... }
}
```

**Step 3 — wire the data-plane challenge path.**

```rust
// crates/aegis-proxy/src/data_plane.rs:601-621
aegis_security::risk::RiskLevel::Challenge => {
    let pow = match challenge_tokens.issue_pow(state.as_ref(), &risk_key, 16).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "pow challenge issue failed; falling back to block");
            // Fall back to plain block on issuer failure (Redis down etc.)
            return blocked_response_fallback(...);
        }
    };
    let body = serde_json::json!({
        "challenge": true,
        "challenge_type": "proof_of_work",
        "nonce": pow.nonce,
        "difficulty": pow.difficulty,
        "submit_to": "/__waf_control/challenge_verify",
        "expires_at": chrono::DateTime::from_timestamp_millis(pow.expires_at).unwrap().to_rfc3339(),
        "reason": "risk score over challenge threshold",
    });
    let resp = Response::builder()
        .status(429)
        .header("content-type", "application/json")
        .header("retry-after", "5")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    (resp, DecisionTag::challenge("risk-challenge").with_tier(tier))
}
```

**Step 4 — add the verify endpoint.**

```rust
// crates/aegis-proxy/src/admin_dispatch.rs (alongside the other __waf_control/* routes)
// Body: { "nonce": "...", "counter": "..." }
// Response: 204 No Content + Set-Cookie aegis_challenge=<verified token> on success
//           400 / 403 on bad payload / replay / wrong difficulty
async fn handle_challenge_verify(
    req: hyper::Request<hyper::body::Incoming>,
    rt: &aegis_control::interop::InteropRuntime,
    state: Arc<dyn StateBackend>,
    challenge_tokens: Arc<ChallengeTokens>,
) -> Response<Full<Bytes>> { ... }
```

The route lives under `/__waf_control/challenge_verify` (matches the contract's "internal control" namespace) and follows the same auth-via-secret pattern as the other interop endpoints. Since the OC harness calls it, treat it like the other interop control surfaces.

**Step 5 — RED tests.**

In `crates/aegis-security/src/challenge/token.rs` test module:
- `pow_solution_with_correct_difficulty_verifies`
- `pow_solution_with_insufficient_difficulty_rejected`
- `pow_solution_with_replay_rejected` (verify twice → second fails)
- `pow_solution_after_expiry_rejected`

In `crates/aegis-proxy/tests/challenge_pow.rs` (new integration test, mirroring `interop_data_plane.rs` shape):
- `challenge_429_body_carries_pow_fields`
- `challenge_verify_endpoint_accepts_correct_solution`

**Step 6 — update `STAGING-BENCHMARK.md`** with the curl-side example for solving the challenge:

```sh
# 1. Trigger a challenge (after enough strikes on a peer)
RESP=$(curl -ks -i http://127.0.0.1:8080/some-protected-path)
echo "$RESP" | grep -i 'X-WAF-Action: challenge'

# 2. Parse body for nonce + difficulty
BODY=$(echo "$RESP" | tail -1)
NONCE=$(echo "$BODY" | jq -r .nonce)
DIFF=$(echo "$BODY" | jq -r .difficulty)

# 3. Solve (script provided in tests/challenge/solve_pow.py for reference)
COUNTER=$(python3 tests/challenge/solve_pow.py "$NONCE" "$DIFF")

# 4. Submit
curl -ks -X POST \
  -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d "{\"nonce\":\"$NONCE\",\"counter\":\"$COUNTER\"}" \
  http://127.0.0.1:8080/__waf_control/challenge_verify
# Expect: 204
```

A small reference solver in `tests/challenge/solve_pow.py` (Python, no deps beyond `hashlib` — actually we use blake3, so use `pip install blake3` or vendor a tiny Rust binary) lets the OC harness verify the round-trip.

### Acceptance

- [ ] Challenge response body carries `nonce`, `difficulty`, `submit_to`, `expires_at`
- [ ] `POST /__waf_control/challenge_verify` returns 204 on a correct PoW solution
- [ ] Replay (same nonce twice) returns 403
- [ ] Insufficient difficulty returns 403
- [ ] Expired nonce returns 403
- [ ] Reference solver script lives under `tests/challenge/`
- [ ] `STAGING-BENCHMARK.md` documents the round-trip
- [ ] All new + existing challenge tests pass

**Effort:** ~5 h. The single biggest item in this fix-pass.

**Risk:** PoW difficulty 16 is roughly 65 K blake3 hashes — milliseconds on a laptop. Operators may want to tune via `risk.challenge.difficulty` config. Defer to a follow-up unless the benchmark harness explicitly asks for tunability.

---

## NEW-3 · Scaling page renders phantom peer row

**Source:** Run-2 §2 NEW-3.

### Verified state (2026-05-08, on `develop`)

The QA's symptom description (`state: down · role: replica · heartbeat: —`) matches the dashboard rendering exactly when the dashboard reads field names that don't exist on `ClusterPeer`. Cross-check:

`ClusterPeer` struct (`crates/aegis-control/src/api/tracking.rs:107`):
```rust
pub struct ClusterPeer {
    pub id: String,
    pub addr: String,
    pub version: String,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    pub leases: Vec<String>,
}
```

Dashboard render code (`crates/aegis-control/assets/dashboard/src/pages.jsx:6275-6293`):
```jsx
{peers.map(p => {
  const isMe = p.node_id === ourNode;          // p.node_id ← does not exist on the JSON
  return (
    <tr ...>
      <td><code>{p.node_id}</code> ...</td>      // renders "" / undefined
      <td>
        <span className={`pill ${p.healthy ? 'up' : 'down'}`}>
          {p.healthy ? 'healthy' : 'down'}        // p.healthy missing → 'down'
        </span>
      </td>
      <td>{p.last_heartbeat_age_s != null ? ... : '—'}</td>  // missing → '—'
      <td>{p.leader ? ... : <span className="dim">replica</span>}</td>  // missing → 'replica'
    </tr>
  );
})}
```

When the membership writer self-publishes a `members:<our_node_id>` key, the poll picks it up and `LeaderView::set_members` stores ONE `ClusterPeer { id, addr, version, last_heartbeat, leases }`. The dashboard sees `peers.length === 1`, renders the row, every field lookup misses → exactly the QA-observed phantom row.

The M008 empty-id filter from Run-1 was correct but didn't address this — empty-id wasn't the path that hit; **field-name mismatch** is the actual bug.

### Plan

**Step 1 — fix the dashboard reader to use the real field names.**

```jsx
// crates/aegis-control/assets/dashboard/src/pages.jsx ScalingL2Card peer row
{peers.map(p => {
  const isMe = p.id === ourNode;
  // Derive heartbeat age from the timestamp the API returns
  const ageSec = p.last_heartbeat
    ? Math.max(0, Math.round((Date.now() - new Date(p.last_heartbeat).getTime()) / 1000))
    : null;
  // Healthy if heartbeat is recent (< 30 s = 2× the heartbeat
  // interval). Beyond that the lease TTL would have expired and
  // the peer wouldn't be in the list at all, but defend in depth.
  const healthy = ageSec != null && ageSec < 30;
  // Leader signal — the existing /api/cluster.is_leader is for
  // *this node*; no per-peer leader flag in ClusterPeer today.
  // Mark as leader only when leader_node matches this peer's id.
  const isLeader = leaderNode != null && p.id === leaderNode;
  return (
    <tr key={p.id} style={isMe ? { background: 'var(--surface-3)' } : undefined}>
      <td>
        <code>{p.id}</code>
        {isMe && <span ...>(this)</span>}
      </td>
      <td>
        <span className={`pill ${healthy ? 'up' : 'down'}`}>
          {healthy ? 'healthy' : 'down'}
        </span>
      </td>
      <td className="num">{ageSec != null ? `${ageSec}s ago` : '—'}</td>
      <td>{isLeader ? <span className="pill solid-yellow">leader</span> : <span className="dim">replica</span>}</td>
    </tr>
  );
})}
```

`leaderNode` is read from `cluster?.data?.leader_node` (already on the API response).

**Step 2 — single-node UX hint.**

The QA's recommended copy is good — surface "Single-node mode" when the only peer in `peers[]` is self.

```jsx
const peersExcludingSelf = peers.filter(p => p.id !== ourNode);
const isSingleNode = peersExcludingSelf.length === 0;

{isSingleNode ? (
  <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
    Running in single-node mode — no remote peers configured.
    {peers.length === 1 && <> This node ({ourNode}) is the only member.</>}
  </div>
) : (
  // existing table render, but iterate peersExcludingSelf or full list with `(this)` badge
)}
```

**Step 3 — manual verification.**

```sh
# Single-node: navigate to #/scaling
# Expect: "Running in single-node mode — no remote peers configured. This node (<id>) is the only member."
# Layer 2 card no longer shows a row with empty id / down / replica

# (If multi-node infra exists or a fixture is added) — verify the table renders correct fields
curl -s http://127.0.0.1:9443/api/cluster | jq
# Expect: peers[] with {id, addr, version, last_heartbeat, leases}
# Dashboard row should show id + heartbeat-age + healthy/down based on age + leader/replica
```

**Step 4 — no test infra in dashboard JSX bundle.** Verification is manual + the standard JSX rebuild (`bash crates/aegis-control/assets/dashboard/build.sh`).

### Acceptance

- [ ] Single-node deployment shows "Running in single-node mode" copy, no phantom row
- [ ] Multi-node deployment renders correct peer fields (id, heartbeat-age, healthy state, leader marker)
- [ ] Heartbeat freshness is derived (< 30 s healthy, else stale-down — defensive only; lease TTL handles real eviction)
- [ ] M008 empty-id filter remains in place in `accept.rs`
- [ ] Dashboard JSX rebuild produces app.js bundle without errors

**Effort:** ~30 min. Surgical dashboard fix.

---

## Sequencing

- **NEW-3 first** — small, self-contained dashboard fix; ships its own PR.
- **NEW-2 second** — larger; ships its own PR with the new endpoint + tests + ref solver.

Two PRs:

1. `fix(dashboard): Scaling page reads correct ClusterPeer field names (NEW-3)`
2. `feat(challenge): proof-of-work challenge body + verify endpoint (NEW-2)`
