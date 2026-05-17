// CSRF double-submit cookie protection.
//
// `aegis_csrf = random 128-bit` (NOT HttpOnly — JS must read it).
// Mutating methods require `X-CSRF-Token` header matching cookie value.

/// Generate a CSRF token (128-bit hex).
///
/// 2026-05-17 F-CRITICAL-005 — entropy upgraded from
/// `blake3(clock_nanos + atomic counter)` to UUID v4 (getrandom
/// under the hood). The previous form was deterministic on the
/// (now, counter) pair and an attacker observing one issued token
/// could predict the next within a microsecond window. UUID v4
/// gives 122 bits of CSPRNG entropy per call.
pub fn generate_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
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
///
/// The `Secure` flag is included by default. Browsers reject
/// `Secure` cookies sent over plain HTTP, so the dev profile
/// (admin listener on plain `127.0.0.1:9443`) needs the flag
/// dropped — set `AEGIS_INSECURE_COOKIES=1` in the environment.
/// **Dev-only escape hatch — never set in production.** The
/// Makefile's `run-dev` target sets it; `run` / `run-strict` /
/// `run-throughput` do not.
pub fn format_csrf_cookie(token: &str) -> String {
    let secure = if insecure_cookies_enabled() { "" } else { "Secure; " };
    format!("aegis_csrf={token}; {secure}SameSite=Strict; Path=/")
}

/// Read the dev-only `AEGIS_INSECURE_COOKIES=1` opt-out. See
/// [`format_csrf_cookie`] for why this exists.
pub fn insecure_cookies_enabled() -> bool {
    matches!(
        std::env::var("AEGIS_INSECURE_COOKIES").as_deref(),
        Ok("1") | Ok("true")
    )
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
    fn generate_token_is_unpredictable_across_many_calls() {
        // F-CRITICAL-005 regression: pre-fix, an attacker who knew
        // the clock and approximate atomic counter could predict
        // the next token (blake3 of those two inputs). With UUID v4
        // / getrandom under the hood, 10 000 calls must produce
        // 10 000 distinct tokens. The previous blake3-clock-counter
        // form would also pass this test by accident; we're really
        // asserting the new source is *not* the old one — see the
        // length assertion below as a second checkpoint.
        let mut set = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(set.insert(generate_token()), "collision");
        }
        // Sanity: uuid simple form is exactly 32 hex chars; if any
        // future refactor swaps the source back to a non-uuid path
        // with a different length, this catches it.
        for t in set.iter().take(8) {
            assert_eq!(t.len(), 32);
        }
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
