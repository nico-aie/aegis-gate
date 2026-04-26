/// Password verification using argon2id (PHC string format).
///
/// Unknown-user path runs full argon2id to equalize timing.
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;

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
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let cnt = CTR.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash = blake3::hash(format!("salt:{now}:{cnt}").as_bytes());
    // encode_b64 takes raw bytes and encodes them as PHC B64.
    SaltString::encode_b64(&hash.as_bytes()[..16]).unwrap()
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

/// Dummy verify: runs a full argon2id hash to burn the same time as a real
/// verify, preventing user-enumeration timing attacks.
pub fn dummy_verify(candidate: &str) {
    let _ = hash_password(candidate);
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
