/// Format-Preserving Encryption stub (AES-FF1).
///
/// In production, use a proper FF1 crate. This provides the interface
/// and key versioning logic.
///
/// FPE key with version.
#[derive(Clone, Debug)]
pub struct FpeKey {
    pub version: u32,
    pub key: [u8; 32],
    pub retired: bool,
}

/// FPE engine with key versioning.
pub struct FpeEngine {
    keys: Vec<FpeKey>,
    active_version: u32,
}

impl FpeEngine {
    pub fn new(initial_key: [u8; 32]) -> Self {
        Self {
            keys: vec![FpeKey {
                version: 1,
                key: initial_key,
                retired: false,
            }],
            active_version: 1,
        }
    }

    /// Rotate to a new key. Old key remains for decryption.
    pub fn rotate_key(&mut self, new_key: [u8; 32]) {
        let new_version = self.active_version + 1;
        self.keys.push(FpeKey {
            version: new_version,
            key: new_key,
            retired: false,
        });
        self.active_version = new_version;
    }

    /// Retire a key version (can no longer decrypt).
    pub fn retire_key(&mut self, version: u32) {
        if let Some(k) = self.keys.iter_mut().find(|k| k.version == version) {
            k.retired = true;
        }
    }

    /// Encrypt digits preserving format using active key.
    ///
    /// Stub: XORs with key bytes for demonstration. Real impl would use FF1.
    pub fn encrypt(&self, plaintext: &str) -> Option<(String, u32)> {
        let key = self.keys.iter().find(|k| k.version == self.active_version)?;
        let encrypted = xor_digits(plaintext, &key.key);
        Some((encrypted, self.active_version))
    }

    /// Decrypt digits using the specified key version.
    pub fn decrypt(&self, ciphertext: &str, version: u32) -> Option<String> {
        let key = self.keys.iter().find(|k| k.version == version && !k.retired)?;
        Some(xor_digits(ciphertext, &key.key))
    }

    pub fn active_version(&self) -> u32 {
        self.active_version
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

/// Stub FPE: XOR each digit with key byte mod 10. Symmetric.
fn xor_digits(text: &str, key: &[u8; 32]) -> String {
    text.chars()
        .enumerate()
        .map(|(i, ch)| {
            if ch.is_ascii_digit() {
                let d = ch.to_digit(10).unwrap();
                let k = (key[i % 32] % 10) as u32;
                let encrypted = (d + k) % 10;
                char::from_digit(encrypted, 10).unwrap()
            } else {
                ch // Preserve separators.
            }
        })
        .collect()
}

/// Reverse XOR for decryption.
fn _reverse_xor_digits(text: &str, key: &[u8; 32]) -> String {
    text.chars()
        .enumerate()
        .map(|(i, ch)| {
            if ch.is_ascii_digit() {
                let d = ch.to_digit(10).unwrap();
                let k = (key[i % 32] % 10) as u32;
                let decrypted = (d + 10 - k) % 10;
                char::from_digit(decrypted, 10).unwrap()
            } else {
                ch
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn encrypt_produces_same_length() {
        let engine = FpeEngine::new(test_key());
        let (encrypted, _) = engine.encrypt("4111111111111111").unwrap();
        assert_eq!(encrypted.len(), 16);
    }

    #[test]
    fn encrypt_preserves_format() {
        let engine = FpeEngine::new(test_key());
        let (encrypted, _) = engine.encrypt("4111-1111-1111-1111").unwrap();
        assert_eq!(encrypted.len(), 19); // Same length including dashes.
        assert_eq!(encrypted.chars().filter(|c| *c == '-').count(), 3);
    }

    #[test]
    fn encrypt_changes_digits() {
        let engine = FpeEngine::new(test_key());
        let (encrypted, _) = engine.encrypt("4111111111111111").unwrap();
        assert_ne!(encrypted, "4111111111111111");
    }

    #[test]
    fn encrypt_only_digits() {
        let engine = FpeEngine::new(test_key());
        let (encrypted, _) = engine.encrypt("4111111111111111").unwrap();
        assert!(encrypted.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn key_rotation() {
        let mut engine = FpeEngine::new(test_key());
        assert_eq!(engine.active_version(), 1);
        engine.rotate_key([99u8; 32]);
        assert_eq!(engine.active_version(), 2);
        assert_eq!(engine.key_count(), 2);
    }

    #[test]
    fn old_key_still_decrypts() {
        let mut engine = FpeEngine::new(test_key());
        let (ct, v) = engine.encrypt("1234567890").unwrap();
        assert_eq!(v, 1);
        engine.rotate_key([99u8; 32]);
        // Old ciphertext still decryptable with v1.
        let pt = engine.decrypt(&ct, 1);
        assert!(pt.is_some());
    }

    #[test]
    fn retired_key_cannot_decrypt() {
        let mut engine = FpeEngine::new(test_key());
        let (ct, _) = engine.encrypt("1234567890").unwrap();
        engine.retire_key(1);
        assert!(engine.decrypt(&ct, 1).is_none());
    }

    #[test]
    fn different_keys_different_output() {
        let e1 = FpeEngine::new([1u8; 32]);
        let e2 = FpeEngine::new([2u8; 32]);
        let (ct1, _) = e1.encrypt("4111111111111111").unwrap();
        let (ct2, _) = e2.encrypt("4111111111111111").unwrap();
        assert_ne!(ct1, ct2);
    }
}
