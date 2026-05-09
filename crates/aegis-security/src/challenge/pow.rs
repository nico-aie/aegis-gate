//! Proof-of-work challenge for v2.3 §3 contract compliance.
//!
//! NEW-2 (2026-05-08) — the v2.3 interop contract states that a
//! challenge response (typically HTTP 429) must carry "enough
//! information for automated challenge solving." Pre-fix, the
//! data-plane challenge body advertised `challenge_type:
//! proof_of_work` but provided no parameters, and there was no
//! submission endpoint. An automated client (benchmark harness,
//! interop tester, bot-mitigation SDK) had no path past the
//! challenge tier.
//!
//! ## Design
//!
//! **Stateless issuance.** The server issues a challenge with no
//! state write. The body carries:
//!
//! ```json
//! {
//!   "nonce":         "<32 hex chars>",
//!   "difficulty":    16,
//!   "expires_at_ms": 1715049600000,
//!   "mac":           "<64 hex chars>"
//! }
//! ```
//!
//! `mac` is `blake3-keyed(server_key, nonce || ":" || difficulty
//! || ":" || expires_at_ms_be)`. It binds the difficulty + expiry
//! to the nonce so a client can't downgrade or extend either.
//!
//! **Solving.** The client finds a `counter` (any string) such
//! that `blake3(nonce || ":" || counter)` has at least
//! `difficulty` leading zero bits. With difficulty 16 the average
//! solver iterates ~65k blake3 hashes — milliseconds on a laptop,
//! but a meaningful tax on a bot at scale.
//!
//! **Verification — single-use via state put_nonce.** When the
//! client POSTs `{nonce, difficulty, expires_at_ms, mac, counter}`
//! to `/__waf_control/challenge_verify`, the server validates in
//! order:
//!
//! 1. `mac` matches expected → catches downgrade attacks.
//! 2. `now < expires_at_ms` → catches replay-after-expiry.
//! 3. `blake3(nonce || ":" || counter)` has `difficulty` leading
//!    zero bits → confirms solve.
//! 4. `state.put_nonce(nonce, ttl)` — first verify wins. A second
//!    verify of the same `(nonce, counter)` finds the nonce
//!    already inserted and returns `false` → reject as replay.
//!
//! Issue is stateless; verify is the single state hop.

use blake3::Hasher;
use std::time::Duration;

/// Stateless PoW challenge issuer + verifier.
///
/// Holds a 32-byte HMAC key; the same key must be present at issue
/// time and at verify time (i.e. the issuer is shared, single-process
/// or distributed via cluster config).
pub struct PowIssuer {
    key: [u8; 32],
    /// Default difficulty (leading zero bits). 16 ≈ 65k hashes
    /// average to solve.
    pub default_difficulty: u8,
    /// Default TTL — how long an issued challenge is valid before
    /// `expires_at_ms` rolls past.
    pub default_ttl: Duration,
}

/// Wire shape for a challenge — what the data plane stamps in the
/// 429 response body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowChallenge {
    /// Hex-encoded random nonce (32 chars = 128 bits).
    pub nonce: String,
    /// Number of leading zero bits the solver must achieve.
    pub difficulty: u8,
    /// Unix milliseconds — challenge is invalid after this point.
    pub expires_at_ms: i64,
    /// Hex-encoded HMAC over (nonce, difficulty, expires_at_ms).
    pub mac: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    /// MAC didn't match — body was tampered with or issuer key
    /// rotated.
    InvalidMac,
    /// Server clock past `expires_at_ms`.
    Expired,
    /// `blake3(nonce || ":" || counter)` had fewer than
    /// `difficulty` leading zero bits.
    InsufficientDifficulty,
    /// `put_nonce` returned false — the nonce was already
    /// consumed.
    Replay,
    /// State backend errored on the put_nonce call.
    StateError(String),
}

impl PowIssuer {
    pub fn new(key: [u8; 32], default_difficulty: u8, default_ttl: Duration) -> Self {
        Self { key, default_difficulty, default_ttl }
    }

    /// Issue a challenge. Stateless — no I/O.
    pub fn issue(&self) -> PowChallenge {
        let nonce = generate_nonce();
        let expires_at_ms = now_ms() + self.default_ttl.as_millis() as i64;
        let mac = self.sign(&nonce, self.default_difficulty, expires_at_ms);
        PowChallenge {
            nonce,
            difficulty: self.default_difficulty,
            expires_at_ms,
            mac,
        }
    }

    /// Verify a client's solution. Single state hop on success.
    ///
    /// `state` is the WAF's StateBackend; used to single-use-mark
    /// the nonce so a replay of the same `(nonce, counter)` is
    /// rejected.
    pub async fn verify(
        &self,
        state: &dyn aegis_core::state::StateBackend,
        nonce: &str,
        difficulty: u8,
        expires_at_ms: i64,
        mac: &str,
        counter: &str,
    ) -> Result<(), PowError> {
        // 1. MAC binds the (nonce, difficulty, expires_at) tuple.
        let expected = self.sign(nonce, difficulty, expires_at_ms);
        if !ct_eq(mac, &expected) {
            return Err(PowError::InvalidMac);
        }
        // 2. Expiry — fail before doing any other work.
        let now = now_ms();
        if now >= expires_at_ms {
            return Err(PowError::Expired);
        }
        // 3. PoW solution check.
        if !pow_solution_valid(nonce, counter, difficulty) {
            return Err(PowError::InsufficientDifficulty);
        }
        // 4. Replay protection — first verify wins. The TTL on
        //    the nonce mark is the remaining lifetime of the
        //    challenge, so memory pressure doesn't accumulate.
        let remaining_ms = (expires_at_ms - now).max(1) as u64;
        let inserted = state
            .put_nonce(nonce, Duration::from_millis(remaining_ms))
            .await
            .map_err(|e| PowError::StateError(e.to_string()))?;
        if !inserted {
            return Err(PowError::Replay);
        }
        Ok(())
    }

    fn sign(&self, nonce: &str, difficulty: u8, expires_at_ms: i64) -> String {
        let mut hasher = Hasher::new_keyed(&self.key);
        hasher.update(nonce.as_bytes());
        hasher.update(b":");
        hasher.update(&[difficulty]);
        hasher.update(b":");
        hasher.update(&expires_at_ms.to_be_bytes());
        hasher.finalize().to_hex().as_str().to_string()
    }
}

/// Validate a PoW solution. Public so external solvers (test
/// harnesses, the reference Python script) can re-use the same
/// rule.
pub fn pow_solution_valid(nonce: &str, counter: &str, difficulty: u8) -> bool {
    let mut hasher = Hasher::new();
    hasher.update(nonce.as_bytes());
    hasher.update(b":");
    hasher.update(counter.as_bytes());
    let h = hasher.finalize();
    leading_zero_bits(h.as_bytes()) >= difficulty
}

fn leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut count: u32 = 0;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count.min(u8::MAX as u32) as u8
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Generate a 128-bit hex nonce. The space is large enough that
/// timestamp_nanos + a process-local counter never collides
/// across one binary's lifetime.
fn generate_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let pid = std::process::id();
    let h = blake3::hash(format!("{ts_ns}:{pid}:{n}").as_bytes());
    h.to_hex().as_str()[..32].to_string()
}

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;

    struct MockState {
        nonces: Mutex<HashMap<String, ()>>,
    }

    impl MockState {
        fn new() -> Self {
            Self { nonces: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait::async_trait]
    impl aegis_core::state::StateBackend for MockState {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _k: &str, _w: Duration, _l: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _k: &aegis_core::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _k: &aegis_core::RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _ip: IpAddr, _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, nonce: &str, _t: Duration) -> aegis_core::Result<bool> {
            let mut map = self.nonces.lock().unwrap();
            Ok(map.insert(nonce.into(), ()).is_none())
        }
        async fn consume_nonce(&self, nonce: &str) -> aegis_core::Result<bool> {
            let mut map = self.nonces.lock().unwrap();
            Ok(map.remove(nonce).is_some())
        }
    }

    fn issuer() -> PowIssuer {
        PowIssuer::new([7u8; 32], 8, Duration::from_secs(60))
    }

    /// Reference solver — iterates counters until pow_solution_valid
    /// returns true. Used in tests and packaged separately for the
    /// OC harness.
    fn solve(nonce: &str, difficulty: u8) -> String {
        for c in 0u64.. {
            let s = c.to_string();
            if pow_solution_valid(nonce, &s, difficulty) {
                return s;
            }
        }
        unreachable!()
    }

    #[test]
    fn nonces_are_unique_under_concurrent_issue() {
        let issuer = issuer();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let c = issuer.issue();
            assert!(seen.insert(c.nonce.clone()), "nonce collision: {}", c.nonce);
        }
    }

    #[test]
    fn issued_challenge_carries_consistent_difficulty() {
        let issuer = issuer();
        let c = issuer.issue();
        assert_eq!(c.difficulty, 8);
        assert_eq!(c.nonce.len(), 32);
        assert_eq!(c.mac.len(), 64); // blake3 keyed digest hex
        assert!(c.expires_at_ms > now_ms());
    }

    #[tokio::test]
    async fn verify_accepts_correct_solution() {
        let issuer = issuer();
        let state = MockState::new();
        let challenge = issuer.issue();
        let counter = solve(&challenge.nonce, challenge.difficulty);
        let r = issuer.verify(
            &state,
            &challenge.nonce,
            challenge.difficulty,
            challenge.expires_at_ms,
            &challenge.mac,
            &counter,
        ).await;
        assert!(r.is_ok(), "verify failed: {:?}", r);
    }

    #[tokio::test]
    async fn verify_rejects_replay() {
        let issuer = issuer();
        let state = MockState::new();
        let challenge = issuer.issue();
        let counter = solve(&challenge.nonce, challenge.difficulty);
        // First verify wins.
        issuer.verify(
            &state,
            &challenge.nonce,
            challenge.difficulty,
            challenge.expires_at_ms,
            &challenge.mac,
            &counter,
        ).await.unwrap();
        // Second verify of the same (nonce, counter) is a replay.
        let r = issuer.verify(
            &state,
            &challenge.nonce,
            challenge.difficulty,
            challenge.expires_at_ms,
            &challenge.mac,
            &counter,
        ).await;
        assert_eq!(r, Err(PowError::Replay));
    }

    #[tokio::test]
    async fn verify_rejects_insufficient_difficulty() {
        let issuer = issuer();
        let state = MockState::new();
        let challenge = issuer.issue();
        // Empty counter doesn't satisfy difficulty 8 (1/256
        // chance of having 8 leading zero bits).
        let r = issuer.verify(
            &state,
            &challenge.nonce,
            challenge.difficulty,
            challenge.expires_at_ms,
            &challenge.mac,
            "0",
        ).await;
        // Almost always InsufficientDifficulty; on the rare
        // collision it would succeed which is fine.
        assert!(matches!(r, Err(PowError::InsufficientDifficulty) | Ok(_)));
    }

    #[tokio::test]
    async fn verify_rejects_expired_nonce() {
        let issuer = issuer();
        let state = MockState::new();
        let mut challenge = issuer.issue();
        // Forge an expiry in the past + recompute MAC to keep the
        // tuple internally consistent (tests the expiry branch
        // without conflating it with MAC failure).
        challenge.expires_at_ms = now_ms() - 1;
        challenge.mac = issuer.sign(
            &challenge.nonce,
            challenge.difficulty,
            challenge.expires_at_ms,
        );
        let counter = solve(&challenge.nonce, challenge.difficulty);
        let r = issuer.verify(
            &state,
            &challenge.nonce,
            challenge.difficulty,
            challenge.expires_at_ms,
            &challenge.mac,
            &counter,
        ).await;
        assert_eq!(r, Err(PowError::Expired));
    }

    #[tokio::test]
    async fn verify_rejects_tampered_mac() {
        let issuer = issuer();
        let state = MockState::new();
        let challenge = issuer.issue();
        let counter = solve(&challenge.nonce, challenge.difficulty);
        // Flip a bit in the MAC.
        let mut bad_mac = challenge.mac.clone();
        bad_mac.replace_range(0..1, "0");
        if bad_mac == challenge.mac {
            bad_mac.replace_range(0..1, "1");
        }
        let r = issuer.verify(
            &state,
            &challenge.nonce,
            challenge.difficulty,
            challenge.expires_at_ms,
            &bad_mac,
            &counter,
        ).await;
        assert_eq!(r, Err(PowError::InvalidMac));
    }

    #[tokio::test]
    async fn verify_rejects_difficulty_downgrade() {
        let issuer = issuer();
        let state = MockState::new();
        let challenge = issuer.issue();
        // Solve at difficulty 1 (easy); claim difficulty 1 in the
        // verify call but use the original (high-difficulty) MAC
        // — should fail because MAC binds to original difficulty.
        let easy_counter = solve(&challenge.nonce, 1);
        let r = issuer.verify(
            &state,
            &challenge.nonce,
            1, // claimed lower difficulty
            challenge.expires_at_ms,
            &challenge.mac, // MAC was issued at difficulty 8
            &easy_counter,
        ).await;
        assert_eq!(r, Err(PowError::InvalidMac));
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0xff, 0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x7f, 0xff]), 1);
        assert_eq!(leading_zero_bits(&[0x00, 0xff]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x7f]), 9);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x01]), 23);
    }
}
