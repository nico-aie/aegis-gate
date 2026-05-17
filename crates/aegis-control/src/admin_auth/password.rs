/// Password verification using argon2id (PHC string format).
///
/// Unknown-user path runs full argon2id to equalize timing.
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use std::sync::OnceLock;

/// Hash a password with argon2id (default params).
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = generate_salt();
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

fn generate_salt() -> SaltString {
    // 2026-05-17 F-HIGH-admin sub-finding: pre-fix this derived
    // the salt from `blake3(clock_nanos + atomic counter)` —
    // deterministic on (now, counter), same entropy bug as the
    // CSRF token + session ID before Phase 3 step 1. An attacker
    // who knew the approximate hash time could brute-force the
    // salt and then run an offline argon2 candidate pre-computation
    // against a leaked hash. Argon2's memory cost makes that
    // expensive but not impossible; CSPRNG salt closes the gap.
    //
    // UUID v4 is what we standardised on for token entropy (see
    // `csrf.rs`, `session.rs`); reuse it here. 16 bytes = 128 bits
    // is the argon2-recommended salt size.
    let id = uuid::Uuid::new_v4().into_bytes();
    SaltString::encode_b64(&id).expect("16-byte salt always fits PHC b64")
}

/// Verify a candidate password against a PHC hash string.
///
/// Returns `true` if the password matches.
pub fn verify_password(hash: &str, candidate: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}

/// Dummy verify: runs an argon2id verify against a precomputed
/// hash so the wall-clock cost matches a real verify exactly.
///
/// 2026-05-17 F-HIGH-admin sub-finding: pre-fix `dummy_verify`
/// called `hash_password`, which generates a fresh salt and runs
/// argon2id once. That's the right COST (one argon2 unit) but a
/// different code path from `verify_password` (parses an existing
/// PHC string, then verifies). A patient attacker stopwatching
/// 10k+ logins could distinguish hash-time from verify-time by a
/// few microseconds and recover the user-enumeration signal that
/// `dummy_verify` exists to suppress. The fix is to take the exact
/// same path: a one-time-computed dummy hash, cached in a
/// `OnceLock`, then `verify_password` against it on every call.
pub fn dummy_verify(candidate: &str) {
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    let h = DUMMY_HASH.get_or_init(|| {
        hash_password("dummy-password-for-timing-equalization")
            .expect("argon2 default params always succeed")
    });
    let _ = verify_password(h, candidate);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_correct() {
        let hash = hash_password("correct-horse-battery-staple").unwrap();
        assert!(verify_password(&hash, "correct-horse-battery-staple"));
    }

    #[test]
    fn verify_wrong_password() {
        let hash = hash_password("secret123").unwrap();
        assert!(!verify_password(&hash, "wrong"));
    }

    #[test]
    fn hash_is_phc_format() {
        let hash = hash_password("test").unwrap();
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn hash_contains_argon2id() {
        let hash = hash_password("test").unwrap();
        assert!(hash.contains("argon2id"));
    }

    #[test]
    fn different_salts_different_hashes() {
        let h1 = hash_password("same").unwrap();
        let h2 = hash_password("same").unwrap();
        assert_ne!(h1, h2); // Different salts.
    }

    #[test]
    fn verify_invalid_hash_returns_false() {
        assert!(!verify_password("not-a-hash", "password"));
    }

    #[test]
    fn verify_empty_hash_returns_false() {
        assert!(!verify_password("", "password"));
    }

    #[test]
    fn dummy_verify_does_not_panic() {
        dummy_verify("anything");
    }

    #[test]
    fn verify_empty_password() {
        let hash = hash_password("").unwrap();
        assert!(verify_password(&hash, ""));
        assert!(!verify_password(&hash, "notempty"));
    }

    #[test]
    fn verify_unicode_password() {
        let hash = hash_password("pässwörd🔑").unwrap();
        assert!(verify_password(&hash, "pässwörd🔑"));
        assert!(!verify_password(&hash, "password"));
    }

    #[test]
    fn verify_long_password() {
        let long = "a".repeat(1000);
        let hash = hash_password(&long).unwrap();
        assert!(verify_password(&hash, &long));
    }
}
