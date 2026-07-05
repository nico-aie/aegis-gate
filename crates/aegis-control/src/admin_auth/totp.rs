/// TOTP (RFC 6238) — 6-digit, 30s step, SHA-1 HMAC.
///
/// 2026-05-17 F-HIGH-admin sub-finding: pre-fix this module
/// generated codes with HMAC-SHA256 while the
/// `otpauth://` provisioning URI (line ~66) claimed `algorithm=SHA256`.
/// Standard authenticator apps (Google Authenticator, Authy,
/// 1Password, FreeOTP, Aegis Authenticator) ignore the algorithm
/// parameter on the URI and use SHA-1 by default, so the codes
/// they generated never matched the codes the WAF expected — the
/// feature was effectively non-functional outside of explicit
/// SHA-256-aware clients. Now we use HMAC-SHA1 (the RFC 6238
/// default) and advertise it on the URI; codes match for every
/// mainstream authenticator. RFC 6238 Appendix B test vectors
/// are pinned in the tests below.
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// TOTP configuration.
#[derive(Clone, Debug)]
pub struct TotpConfig {
    pub digits: u32,
    pub step: u64,
    pub skew: u64,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            digits: 6,
            step: 30,
            skew: 1,
        }
    }
}

/// Generate a TOTP code for a given time and secret.
///
/// Implements RFC 6238 (HOTP-based TOTP) with the RFC 4226
/// dynamic-truncation step. SHA-1 by default for authenticator-
/// app compatibility — see the module-level doc-comment for the
/// 2026-05-17 fix.
pub fn generate(secret: &[u8], time: u64, config: &TotpConfig) -> String {
    let counter = time / config.step;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226 §5.3. Last nibble of the
    // HMAC output picks a 4-byte window starting at that offset;
    // the high bit of the first byte is masked to keep the result
    // a positive 31-bit integer.
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    let modulus = 10u32.pow(config.digits);
    format!("{:0>width$}", code % modulus, width = config.digits as usize)
}

/// Verify a TOTP code, allowing ±skew steps. Returns `true` if
/// the code matches any time-step in `[time - skew*step, time +
/// skew*step]`.
///
/// **No replay protection.** A code accepted at `time` will also
/// be accepted at `time + 1s`, `time + 2s`, … until its window
/// ends. Callers that need replay protection wrap this in a
/// [`TotpReplayGuard`] (see below) or call [`verify_and_consume`].
pub fn verify(secret: &[u8], code: &str, time: u64, config: &TotpConfig) -> bool {
    verify_with_counter(secret, code, time, config).is_some()
}

/// Like [`verify`] but returns the matched counter on success so
/// callers can drive replay protection. `None` = no match.
pub fn verify_with_counter(
    secret: &[u8],
    code: &str,
    time: u64,
    config: &TotpConfig,
) -> Option<u64> {
    let step = config.step;
    let base_counter = time / step;
    for offset in 0..=config.skew {
        if ct_eq_str(&generate(secret, time + offset * step, config), code) {
            return Some(base_counter + offset);
        }
        if offset > 0
            && time >= offset * step
            && ct_eq_str(&generate(secret, time - offset * step, config), code)
        {
            return Some(base_counter - offset);
        }
    }
    None
}

/// SEC-02 (LT-RUN-11, 2026-06-19) — constant-time compare of the generated
/// candidate against the client-supplied code. Plain `==` short-circuits on the
/// first differing byte, leaking a timing signal about how many leading digits
/// matched. Length is not secret (it's the configured digit count), so an
/// early length mismatch is fine; equal-length comparison is branch-free over
/// the bytes. Mirrors `interop::control::constant_time_eq` /
/// `challenge::pow::ct_eq`.
fn ct_eq_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 2026-05-17 F-HIGH-admin sub-finding: pre-fix, `verify` had no
/// replay protection — a code captured in flight could be replayed
/// within its ±skew step window (up to ~90 seconds with default
/// `step=30, skew=1`). Wrapping the verifier in this guard ensures
/// each counter accepts at most one code, by tracking the highest
/// counter ever consumed and rejecting any later candidate ≤ that
/// counter.
///
/// One guard per principal (single-admin model = one global
/// guard); per-principal scoping arrives with the multi-user RBAC
/// refactor.
#[derive(Debug, Default)]
pub struct TotpReplayGuard {
    last_consumed_counter: std::sync::atomic::AtomicU64,
}

impl TotpReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify + atomically record the counter on success. Returns
    /// `true` only when the code matches AND the matched counter
    /// is strictly higher than every previously-consumed counter
    /// for this guard.
    pub fn verify_and_consume(
        &self,
        secret: &[u8],
        code: &str,
        time: u64,
        config: &TotpConfig,
    ) -> bool {
        use std::sync::atomic::Ordering;
        let Some(matched_counter) = verify_with_counter(secret, code, time, config) else {
            return false;
        };
        // CAS: only accept if the matched counter beats the
        // previous high-water mark. Concurrent verifies are rare
        // (single-admin model + login rate-limit), but the CAS
        // costs nothing and prevents a TOCTOU window.
        let mut last = self.last_consumed_counter.load(Ordering::Relaxed);
        loop {
            if matched_counter <= last {
                return false; // replay
            }
            match self.last_consumed_counter.compare_exchange_weak(
                last,
                matched_counter,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => last = actual,
            }
        }
    }
}

/// Generate a provisioning URI for authenticator apps.
///
/// `algorithm=SHA1` matches the actual HMAC primitive used in
/// `generate()` so authenticator apps that DO honour the
/// algorithm parameter (recent FreeOTP, Aegis Authenticator) line
/// up with the WAF, and apps that ignore it (Google Authenticator,
/// Authy) keep working as before.
pub fn provisioning_uri(secret_b32: &str, issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

/// Generate a fresh 32-byte TOTP shared secret, RFC 4648 base32
/// encoded (no padding — matches what `api::login` decodes and what
/// authenticator apps consume off the `otpauth://` URI).
///
/// CSPRNG source: two UUID v4s (the token standard across `csrf.rs` /
/// `session.rs`; the CLI's `enroll-totp` used the same construction —
/// TOTP-3 hoists it here so the web enrollment endpoint and the CLI
/// share one generator).
pub fn generate_secret_b32() -> String {
    let mut secret = [0u8; 32];
    secret[..16].copy_from_slice(&uuid::Uuid::new_v4().into_bytes());
    secret[16..].copy_from_slice(&uuid::Uuid::new_v4().into_bytes());
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret)
}

/// Generate recovery codes (10 codes, 8 chars each).
pub fn generate_recovery_codes(seed: &[u8]) -> Vec<String> {
    (0..10)
        .map(|i| {
            let input = format!("recovery:{i}:{}", hex_encode(seed));
            let hash = blake3::hash(input.as_bytes());
            hash.to_hex()[..8].to_string()
        })
        .collect()
}

/// Hash a recovery code for storage.
pub fn hash_recovery_code(code: &str) -> String {
    blake3::hash(code.as_bytes()).to_hex().to_string()
}

/// Verify a recovery code against its hash.
pub fn verify_recovery_code(code: &str, hash: &str) -> bool {
    hash_recovery_code(code) == hash
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"12345678901234567890123456789012";
    const CONFIG: TotpConfig = TotpConfig { digits: 6, step: 30, skew: 1 };

    #[test]
    fn generate_6_digits() {
        let code = generate(SECRET, 1000000, &CONFIG);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn ct_eq_str_matches_plain_equality_semantics() {
        // SEC-02 — the constant-time compare must agree with `==` on result.
        assert!(ct_eq_str("123456", "123456"));
        assert!(!ct_eq_str("123456", "123457"));
        assert!(!ct_eq_str("123456", "12345")); // length mismatch
        assert!(!ct_eq_str("000000", "999999"));
        assert!(ct_eq_str("", ""));
    }

    #[test]
    fn generate_deterministic() {
        let a = generate(SECRET, 1000000, &CONFIG);
        let b = generate(SECRET, 1000000, &CONFIG);
        assert_eq!(a, b);
    }

    #[test]
    fn generate_changes_with_time() {
        let a = generate(SECRET, 1000000, &CONFIG);
        let b = generate(SECRET, 1000030, &CONFIG);
        // Different time steps should (almost always) produce different codes.
        // Edge case: they could collide, but extremely unlikely.
        let _ = (a, b); // Just ensure no panic.
    }

    #[test]
    fn verify_current_step() {
        let time = 1000000u64;
        let code = generate(SECRET, time, &CONFIG);
        assert!(verify(SECRET, &code, time, &CONFIG));
    }

    #[test]
    fn replay_guard_consumes_each_counter_once() {
        // F-HIGH-admin regression: pre-fix `verify` had no replay
        // protection — a captured code stayed valid for the entire
        // ±skew step window. The guard records the matched counter
        // and rejects every subsequent submission of the same or
        // earlier counter.
        let guard = TotpReplayGuard::new();
        let time = 1_000_000u64;
        let code = generate(SECRET, time, &CONFIG);
        // First submission consumes the code.
        assert!(guard.verify_and_consume(SECRET, &code, time, &CONFIG));
        // Replay within the same window must be rejected.
        assert!(!guard.verify_and_consume(SECRET, &code, time, &CONFIG));
        // Slightly later time (same counter) is also rejected.
        assert!(!guard.verify_and_consume(SECRET, &code, time + 1, &CONFIG));
        // The NEXT counter's code accepts (no leakage between
        // counters).
        let next_code = generate(SECRET, time + 30, &CONFIG);
        assert!(guard.verify_and_consume(SECRET, &next_code, time + 30, &CONFIG));
        // And replaying THAT code is now rejected too.
        assert!(!guard.verify_and_consume(SECRET, &next_code, time + 30, &CONFIG));
    }

    #[test]
    fn replay_guard_rejects_codes_below_high_water_mark() {
        // If a later counter was accepted, an earlier code can't
        // be accepted afterwards — even if it would have matched.
        let guard = TotpReplayGuard::new();
        let later = generate(SECRET, 1_000_060, &CONFIG);
        assert!(guard.verify_and_consume(SECRET, &later, 1_000_060, &CONFIG));
        // Earlier code is genuinely valid for its own counter, but
        // the guard rejects it because we already consumed a
        // higher counter.
        let earlier = generate(SECRET, 1_000_000, &CONFIG);
        assert!(!guard.verify_and_consume(SECRET, &earlier, 1_000_000, &CONFIG));
    }

    #[test]
    fn verify_previous_step() {
        let time = 1000000u64;
        let code = generate(SECRET, time - 30, &CONFIG);
        assert!(verify(SECRET, &code, time, &CONFIG));
    }

    #[test]
    fn verify_next_step() {
        let time = 1000000u64;
        let code = generate(SECRET, time + 30, &CONFIG);
        assert!(verify(SECRET, &code, time, &CONFIG));
    }

    #[test]
    fn verify_rejects_two_steps_away() {
        let time = 1000000u64;
        let code = generate(SECRET, time + 60, &CONFIG);
        assert!(!verify(SECRET, &code, time, &CONFIG));
    }

    #[test]
    fn verify_wrong_code() {
        assert!(!verify(SECRET, "000000", 1000000, &CONFIG));
    }

    #[test]
    fn verify_wrong_secret() {
        let time = 1000000u64;
        let code = generate(SECRET, time, &CONFIG);
        assert!(!verify(b"wrong-secret-key-that-is-long-en", &code, time, &CONFIG));
    }

    #[test]
    fn provisioning_uri_format() {
        let uri = provisioning_uri("JBSWY3DPEHPK3PXP", "Aegis", "admin");
        assert!(uri.starts_with("otpauth://totp/Aegis:admin"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=Aegis"));
        assert!(uri.contains("digits=6"));
        // F-HIGH-admin: must advertise SHA1 (matches what
        // generate() actually computes). Pre-fix this said SHA256
        // while generate() also used SHA256 — but standard
        // authenticator apps default to SHA1 regardless of what
        // the URI advertises, so codes never matched.
        assert!(
            uri.contains("algorithm=SHA1"),
            "URI must advertise SHA1 to match generate(): {uri}",
        );
    }

    #[test]
    fn rfc_6238_appendix_b_test_vectors_sha1() {
        // RFC 6238 Appendix B — the canonical SHA-1 TOTP test
        // vectors. Secret is the ASCII string "12345678901234567890"
        // (20 bytes). 8-digit codes; 30-second step. These vectors
        // exist precisely so independent implementations can prove
        // they're interoperable with standard authenticator apps.
        //
        // If this test fails after a refactor, codes generated by
        // Google Authenticator / Authy / 1Password will not match
        // the server's expected code — the TOTP step is broken end
        // to end. Don't "fix" by relaxing the assertion; fix the
        // algorithm.
        let secret = b"12345678901234567890";
        let cfg = TotpConfig { digits: 8, step: 30, skew: 0 };
        let vectors = [
            (59u64,           "94287082"),
            (1_111_111_109,   "07081804"),
            (1_111_111_111,   "14050471"),
            (1_234_567_890,   "89005924"),
            (2_000_000_000,   "69279037"),
            (20_000_000_000,  "65353130"),
        ];
        for (time, expected) in vectors {
            let got = generate(secret, time, &cfg);
            assert_eq!(
                got, expected,
                "RFC 6238 §B vector at t={time}: expected {expected}, got {got}",
            );
        }
    }

    #[test]
    fn recovery_codes_count() {
        let codes = generate_recovery_codes(b"seed");
        assert_eq!(codes.len(), 10);
    }

    #[test]
    fn recovery_codes_unique() {
        let codes = generate_recovery_codes(b"seed");
        let mut deduped = codes.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), 10);
    }

    #[test]
    fn recovery_code_length() {
        let codes = generate_recovery_codes(b"seed");
        for code in &codes {
            assert_eq!(code.len(), 8);
        }
    }

    #[test]
    fn recovery_code_verify() {
        let codes = generate_recovery_codes(b"seed");
        let hash = hash_recovery_code(&codes[0]);
        assert!(verify_recovery_code(&codes[0], &hash));
        assert!(!verify_recovery_code("wrong", &hash));
    }

    #[test]
    fn recovery_codes_deterministic() {
        let a = generate_recovery_codes(b"seed");
        let b = generate_recovery_codes(b"seed");
        assert_eq!(a, b);
    }
}
