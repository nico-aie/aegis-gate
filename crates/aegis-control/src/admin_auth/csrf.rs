// CSRF double-submit cookie protection.
//
// `aegis_csrf = random 128-bit` (NOT HttpOnly — JS must read it).
// Mutating methods require `X-CSRF-Token` header matching cookie value.

/// Generate a CSRF token (128-bit hex).
pub fn generate_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let cnt = CTR.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash = blake3::hash(format!("csrf:{now}:{cnt}").as_bytes());
    hash.to_hex()[..32].to_string()
}

/// Validate CSRF: check that header value matches cookie value.
pub fn validate(cookie_value: Option<&str>, header_value: Option<&str>) -> CsrfResult {
    let cookie = match cookie_value {
        Some(c) if !c.is_empty() => c,
        _ => return CsrfResult::MissingCookie,
    };
    let header = match header_value {
        Some(h) if !h.is_empty() => h,
        _ => return CsrfResult::MissingHeader,
    };
    if constant_time_eq(cookie.as_bytes(), header.as_bytes()) {
        CsrfResult::Valid
    } else {
        CsrfResult::Mismatch
    }
}

/// Check if a method requires CSRF protection.
pub fn requires_csrf(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

/// CSRF validation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrfResult {
    Valid,
    MissingCookie,
    MissingHeader,
    Mismatch,
}

/// Format the CSRF Set-Cookie (NOT HttpOnly so JS can read).
pub fn format_csrf_cookie(token: &str) -> String {
    format!("aegis_csrf={token}; Secure; SameSite=Strict; Path=/")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_token_length() {
        let token = generate_token();
        assert_eq!(token.len(), 32);
    }

    #[test]
    fn generate_unique_tokens() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn generate_is_hex() {
        let token = generate_token();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validate_matching() {
        let token = generate_token();
        assert_eq!(validate(Some(&token), Some(&token)), CsrfResult::Valid);
    }

    #[test]
    fn validate_missing_cookie() {
        assert_eq!(validate(None, Some("token")), CsrfResult::MissingCookie);
    }

    #[test]
    fn validate_empty_cookie() {
        assert_eq!(validate(Some(""), Some("token")), CsrfResult::MissingCookie);
    }

    #[test]
    fn validate_missing_header() {
        assert_eq!(validate(Some("token"), None), CsrfResult::MissingHeader);
    }

    #[test]
    fn validate_empty_header() {
        assert_eq!(validate(Some("token"), Some("")), CsrfResult::MissingHeader);
    }

    #[test]
    fn validate_mismatch() {
        assert_eq!(validate(Some("abc"), Some("xyz")), CsrfResult::Mismatch);
    }

    #[test]
    fn requires_csrf_mutating() {
        assert!(requires_csrf("POST"));
        assert!(requires_csrf("PUT"));
        assert!(requires_csrf("PATCH"));
        assert!(requires_csrf("DELETE"));
    }

    #[test]
    fn requires_csrf_safe_methods() {
        assert!(!requires_csrf("GET"));
        assert!(!requires_csrf("HEAD"));
        assert!(!requires_csrf("OPTIONS"));
    }

    #[test]
    fn csrf_cookie_not_httponly() {
        let cookie = format_csrf_cookie("token123");
        assert!(!cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn csrf_cookie_contains_token() {
        let cookie = format_csrf_cookie("mytoken");
        assert!(cookie.contains("aegis_csrf=mytoken"));
    }
}
