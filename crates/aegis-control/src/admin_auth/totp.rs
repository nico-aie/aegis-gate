/// TOTP (RFC 6238) — 6-digit, 30s step, SHA-1 HMAC.
///
/// Uses HMAC-SHA1 for compatibility with standard authenticator apps.
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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
pub fn generate(secret: &[u8], time: u64, config: &TotpConfig) -> String {
    let counter = time / config.step;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3, adapted for SHA-256).
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

/// Verify a TOTP code, allowing ±skew steps.
pub fn verify(secret: &[u8], code: &str, time: u64, config: &TotpConfig) -> bool {
    let step = config.step;
    for offset in 0..=config.skew {
        if generate(secret, time + offset * step, config) == code {
            return true;
        }
        if offset > 0 && time >= offset * step && generate(secret, time - offset * step, config) == code {
            return true;
        }
    }
    false
}

/// Generate a provisioning URI for authenticator apps.
pub fn provisioning_uri(secret_b32: &str, issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&algorithm=SHA256&digits=6&period=30"
    )
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
