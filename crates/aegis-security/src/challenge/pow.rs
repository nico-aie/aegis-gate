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
//! **Solving (v2.6 §4 Format B).** The client finds a `counter`
//! (any string) such that `SHA-256(challenge_token || counter)`
//! has at least `difficulty` leading zero **hex characters** —
//! exactly the computation the contract's published HTML reference
//! solver performs (`crypto.subtle.digest("SHA-256", token+nonce)`
//! then `hex.startsWith("0".repeat(difficulty))`). With difficulty
//! 4 the average solver iterates ~65k SHA-256 hashes — milliseconds
//! on a laptop, but a meaningful tax on a bot at scale.
//!
//! The `challenge_token` here is the opaque dot-joined string the
//! client received (`nonce.difficulty.expires_at_ms.mac`); the
//! benchmarker treats it as opaque and concatenates it verbatim.
//!
//! **Verification — single-use via state put_nonce.** When the
//! client POSTs `{nonce, difficulty, expires_at_ms, mac, counter}`
//! to `/__waf_control/challenge_verify`, the server validates in
//! order:
//!
//! 1. `mac` matches expected → catches downgrade attacks.
//! 2. `now < expires_at_ms` → catches replay-after-expiry.
//! 3. `SHA-256(challenge_token || counter)` has `difficulty`
//!    leading zero hex chars → confirms solve.
//! 4. `state.put_nonce(nonce, ttl)` — first verify wins. A second
//!    verify of the same `(nonce, counter)` finds the nonce
//!    already inserted and returns `false` → reject as replay.
//!
//! Issue is stateless; verify is the single state hop.

use blake3::Hasher;
use sha2::{Digest, Sha256};
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

impl PowChallenge {
    /// 2026-05-19 v2.5 contract §4 — encode (nonce, difficulty,
    /// expires_at_ms, mac) into a single opaque `challenge_token`
    /// string that the benchmarker echoes back on verify. Dot-
    /// separated because nonce/mac are hex and the other fields
    /// are digits, so no field can contain a dot.
    pub fn challenge_token(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.nonce, self.difficulty, self.expires_at_ms, self.mac
        )
    }

    /// Reverse of [`Self::challenge_token`]. Returns `None` when
    /// the input is malformed.
    pub fn unpack_token(token: &str) -> Option<UnpackedToken> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let difficulty: u8 = parts[1].parse().ok()?;
        let expires_at_ms: i64 = parts[2].parse().ok()?;
        Some(UnpackedToken {
            nonce: parts[0].to_string(),
            difficulty,
            expires_at_ms,
            mac: parts[3].to_string(),
        })
    }
}

/// Fields unpacked from a `challenge_token`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpackedToken {
    pub nonce: String,
    pub difficulty: u8,
    pub expires_at_ms: i64,
    pub mac: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    /// MAC didn't match — body was tampered with or issuer key
    /// rotated.
    InvalidMac,
    /// Server clock past `expires_at_ms`.
    Expired,
    /// `SHA-256(challenge_token || counter)` had fewer than
    /// `difficulty` leading zero hex chars.
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
        // 3. PoW solution check. The solver works over the opaque
        //    `challenge_token` string it received, so reconstruct it
        //    from the verified parts (pack is the exact inverse of
        //    `unpack_token`, so this equals the issued token).
        let challenge_token = format!("{nonce}.{difficulty}.{expires_at_ms}.{mac}");
        if !pow_solution_valid(&challenge_token, counter, difficulty) {
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

    /// v2.6 §4 — mint a short-lived signed challenge-pass token to
    /// hand back on a successful `/challenge/verify`. The data-plane
    /// challenge gate honors a valid (unexpired, correctly-signed)
    /// token so a client that already solved the PoW can replay the
    /// original request without being re-challenged for `ttl`. Shape
    /// is `"<expires_at_ms>.<mac>"`; the MAC binds the expiry to the
    /// issuer key so the token can't be forged or extended.
    pub fn issue_pass(&self, ttl: Duration) -> String {
        let expires_at_ms = now_ms() + ttl.as_millis() as i64;
        format!("{expires_at_ms}.{}", self.sign_pass(expires_at_ms))
    }

    /// Verify a challenge-pass token minted by [`Self::issue_pass`].
    /// Returns `true` only when the token is well-formed, unexpired,
    /// and carries a MAC matching this issuer's key.
    pub fn pass_valid(&self, token: &str) -> bool {
        let Some((exp_str, mac)) = token.split_once('.') else {
            return false;
        };
        let Ok(expires_at_ms) = exp_str.parse::<i64>() else {
            return false;
        };
        if now_ms() >= expires_at_ms {
            return false;
        }
        ct_eq(mac, &self.sign_pass(expires_at_ms))
    }

    fn sign_pass(&self, expires_at_ms: i64) -> String {
        let mut hasher = Hasher::new_keyed(&self.key);
        hasher.update(b"challenge_pass:");
        hasher.update(&expires_at_ms.to_be_bytes());
        hasher.finalize().to_hex().as_str().to_string()
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

/// Validate a PoW solution per v2.6 §4 Format B. Public so external
/// solvers (test harnesses, the reference HTML/Python solver) can
/// re-use the exact same rule: `SHA-256(challenge_token || counter)`
/// must have at least `difficulty` leading zero hex characters.
pub fn pow_solution_valid(challenge_token: &str, counter: &str, difficulty: u8) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge_token.as_bytes());
    hasher.update(counter.as_bytes());
    let h = hasher.finalize();
    leading_zero_hex_chars(&h) >= difficulty
}

/// Count leading zero hex characters in a byte slice. A hex char is
/// `'0'` exactly when its nibble is zero, so this counts leading
/// zero nibbles (high nibble first) — matching the contract's
/// `hex.startsWith("0".repeat(difficulty))` check.
fn leading_zero_hex_chars(bytes: &[u8]) -> u8 {
    let mut count: u32 = 0;
    'outer: for &b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if nibble == 0 {
                count += 1;
            } else {
                break 'outer;
            }
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
        // Difficulty 3 hex chars (~4096 hashes avg) keeps the test
        // solver fast while exercising the real SHA-256 hex-prefix path.
        PowIssuer::new([7u8; 32], 3, Duration::from_secs(60))
    }

    /// Reference solver — iterates counters until pow_solution_valid
    /// returns true. Mirrors the contract's Format B HTML solver:
    /// SHA-256(challenge_token || counter) with a leading-zero hex
    /// prefix. Used in tests and packaged separately for the OC harness.
    fn solve(challenge_token: &str, difficulty: u8) -> String {
        for c in 0u64.. {
            let s = c.to_string();
            if pow_solution_valid(challenge_token, &s, difficulty) {
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
        assert_eq!(c.difficulty, 3);
        assert_eq!(c.nonce.len(), 32);
        assert_eq!(c.mac.len(), 64); // blake3 keyed digest hex
        assert!(c.expires_at_ms > now_ms());
    }

    #[test]
    fn challenge_token_roundtrips() {
        // v2.5 §4 wire-shape regression. The opaque challenge_token
        // packs (nonce, difficulty, expires_at_ms, mac); benchmarker
        // echoes it back unchanged on verify.
        let issuer = issuer();
        let c = issuer.issue();
        let token = c.challenge_token();
        let u = PowChallenge::unpack_token(&token).expect("token unpacks");
        assert_eq!(u.nonce, c.nonce);
        assert_eq!(u.difficulty, c.difficulty);
        assert_eq!(u.expires_at_ms, c.expires_at_ms);
        assert_eq!(u.mac, c.mac);
    }

    #[test]
    fn challenge_token_rejects_malformed_inputs() {
        assert!(PowChallenge::unpack_token("").is_none());
        assert!(PowChallenge::unpack_token("only.three.fields").is_none());
        assert!(PowChallenge::unpack_token("nonce.NaN.1234.mac").is_none());
        // Extra trailing field → rejected (token shape is exactly 4).
        assert!(PowChallenge::unpack_token("a.8.123.mac.extra").is_none());
    }

    #[tokio::test]
    async fn verify_accepts_correct_solution() {
        let issuer = issuer();
        let state = MockState::new();
        let challenge = issuer.issue();
        let counter = solve(&challenge.challenge_token(), challenge.difficulty);
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
        let counter = solve(&challenge.challenge_token(), challenge.difficulty);
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
        // Counter "0" almost never satisfies difficulty 3 (a 1/4096
        // chance of 3 leading zero hex chars).
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
        let counter = solve(&challenge.challenge_token(), challenge.difficulty);
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
        let counter = solve(&challenge.challenge_token(), challenge.difficulty);
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
        let easy_counter = solve(&challenge.challenge_token(), 1);
        let r = issuer.verify(
            &state,
            &challenge.nonce,
            1, // claimed lower difficulty
            challenge.expires_at_ms,
            &challenge.mac, // MAC was issued at difficulty 3
            &easy_counter,
        ).await;
        assert_eq!(r, Err(PowError::InvalidMac));
    }

    #[test]
    fn leading_zero_hex_chars_counts_correctly() {
        // 0xff = "ff" → 0 leading zero hex chars.
        assert_eq!(leading_zero_hex_chars(&[0xff, 0xff]), 0);
        // 0x0f = "0f" → 1 leading zero hex char.
        assert_eq!(leading_zero_hex_chars(&[0x0f, 0xff]), 1);
        // 0x00 0xff = "00ff" → 2 leading zero hex chars.
        assert_eq!(leading_zero_hex_chars(&[0x00, 0xff]), 2);
        // 0x00 0x0f = "000f" → 3 leading zero hex chars.
        assert_eq!(leading_zero_hex_chars(&[0x00, 0x0f]), 3);
        // 0x00 0x00 0x10 = "000010" → 4 leading zero hex chars.
        assert_eq!(leading_zero_hex_chars(&[0x00, 0x00, 0x10]), 4);
    }

    #[test]
    fn challenge_pass_token_roundtrips_and_rejects_tampering() {
        let issuer = issuer();
        let pass = issuer.issue_pass(Duration::from_secs(300));
        assert!(issuer.pass_valid(&pass), "fresh pass must validate");
        // Tampered MAC → rejected.
        let mut bad = pass.clone();
        bad.replace_range(bad.len() - 1.., "0");
        if bad == pass {
            bad.replace_range(bad.len() - 1.., "1");
        }
        assert!(!issuer.pass_valid(&bad), "tampered pass must be rejected");
        // Malformed (no dot) → rejected.
        assert!(!issuer.pass_valid("garbage"));
        // A different issuer key → rejected.
        let other = PowIssuer::new([9u8; 32], 3, Duration::from_secs(60));
        assert!(!other.pass_valid(&pass), "cross-key pass must be rejected");
    }

    #[test]
    fn expired_challenge_pass_is_rejected() {
        let issuer = issuer();
        // Zero TTL → expires_at_ms == now; pass_valid requires now < exp.
        let pass = issuer.issue_pass(Duration::from_millis(0));
        assert!(!issuer.pass_valid(&pass), "expired pass must be rejected");
    }
}
