/// Basic Auth verification against htpasswd-style entries.
use std::collections::HashMap;

/// Basic auth store (username → hashed password).
pub struct BasicAuthStore {
    entries: HashMap<String, String>,
}

/// Basic auth result.
#[derive(Debug, PartialEq, Eq)]
pub enum BasicAuthResult {
    Ok,
    InvalidCredentials,
    MissingHeader,
    Malformed,
}

impl BasicAuthStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Add a user with a plain-text password (hashed with blake3 for storage).
    pub fn add_user(&mut self, username: &str, password: &str) {
        let hash = blake3::hash(password.as_bytes()).to_hex().to_string();
        self.entries.insert(username.to_string(), hash);
    }

    /// Verify a Basic auth header value.
    ///
    /// Expects `Basic <base64(username:password)>`.
    pub fn verify(&self, auth_header: Option<&str>) -> BasicAuthResult {
        let header = match auth_header {
            Some(h) => h,
            None => return BasicAuthResult::MissingHeader,
        };

        let encoded = match header.strip_prefix("Basic ") {
            Some(e) => e,
            None => return BasicAuthResult::Malformed,
        };

        let decoded = match base64_decode_simple(encoded) {
            Some(d) => d,
            None => return BasicAuthResult::Malformed,
        };

        let (username, password) = match decoded.split_once(':') {
            Some((u, p)) => (u, p),
            None => return BasicAuthResult::Malformed,
        };

        let hash = blake3::hash(password.as_bytes()).to_hex().to_string();
        match self.entries.get(username) {
            Some(stored) if *stored == hash => BasicAuthResult::Ok,
            _ => BasicAuthResult::InvalidCredentials,
        }
    }

    pub fn user_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for BasicAuthStore {
    fn default() -> Self {
        Self::new()
    }
}

fn base64_decode_simple(input: &str) -> Option<String> {
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input.to_string(),
    };

    let mut result = Vec::new();
    let chars: Vec<u8> = padded.bytes().collect();
    let mut i = 0;
    while i + 3 < chars.len() {
        let a = b64_val(chars[i])?;
        let b = b64_val(chars[i + 1])?;
        result.push((a << 2) | (b >> 4));
        if chars[i + 2] != b'=' {
            let c = b64_val(chars[i + 2])?;
            result.push(((b & 0xF) << 4) | (c >> 2));
            if chars[i + 3] != b'=' {
                let d = b64_val(chars[i + 3])?;
                result.push(((c & 0x3) << 6) | d);
            }
        }
        i += 4;
    }
    String::from_utf8(result).ok()
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_basic(user: &str, pass: &str) -> String {
        let raw = format!("{user}:{pass}");
        let encoded = base64_encode_simple(raw.as_bytes());
        format!("Basic {encoded}")
    }

    fn base64_encode_simple(data: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 { result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char); } else { result.push('='); }
            if chunk.len() > 2 { result.push(CHARS[(triple & 0x3F) as usize] as char); } else { result.push('='); }
        }
        result
    }

    #[test]
    fn correct_password() {
        let mut store = BasicAuthStore::new();
        store.add_user("admin", "secret123");
        let header = encode_basic("admin", "secret123");
        assert_eq!(store.verify(Some(&header)), BasicAuthResult::Ok);
    }

    #[test]
    fn wrong_password() {
        let mut store = BasicAuthStore::new();
        store.add_user("admin", "secret123");
        let header = encode_basic("admin", "wrong");
        assert_eq!(store.verify(Some(&header)), BasicAuthResult::InvalidCredentials);
    }

    #[test]
    fn unknown_user() {
        let store = BasicAuthStore::new();
        let header = encode_basic("nobody", "pass");
        assert_eq!(store.verify(Some(&header)), BasicAuthResult::InvalidCredentials);
    }

    #[test]
    fn missing_header() {
        let store = BasicAuthStore::new();
        assert_eq!(store.verify(None), BasicAuthResult::MissingHeader);
    }

    #[test]
    fn malformed_no_basic_prefix() {
        let store = BasicAuthStore::new();
        assert_eq!(store.verify(Some("Bearer token123")), BasicAuthResult::Malformed);
    }

    #[test]
    fn user_count() {
        let mut store = BasicAuthStore::new();
        store.add_user("a", "1");
        store.add_user("b", "2");
        assert_eq!(store.user_count(), 2);
    }
}
