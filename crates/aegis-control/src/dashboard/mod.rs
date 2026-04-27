pub mod assets;
pub mod dispatch;
pub mod security;
pub mod sse;
pub mod overview;

/// Check if a session is authenticated (stub for now).
pub fn is_authenticated(_session_cookie: Option<&str>) -> bool {
    // In W4 this will check HMAC session cookies.
    // For W1 we allow access.
    true
}

/// Redirect URL for unauthenticated requests.
pub fn login_redirect(next: &str) -> String {
    format!("/admin/login?next={}", urlencoded(next))
}

fn urlencoded(s: &str) -> String {
    s.replace('&', "%26").replace('=', "%3D").replace(' ', "%20")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The legacy DASHBOARD_HTML constant + module were removed in
    // D-M6-T6.9. The new SPA shell is the only dashboard surface.

    #[test]
    fn login_redirect_includes_next() {
        let url = login_redirect("/dashboard/");
        assert!(url.starts_with("/admin/login?next="));
        assert!(url.contains("dashboard"));
    }

    #[test]
    fn login_redirect_encodes_special_chars() {
        let url = login_redirect("/api?a=1&b=2");
        assert!(url.contains("%26"));
        assert!(url.contains("%3D"));
    }

    #[test]
    fn is_authenticated_stub_returns_true() {
        assert!(is_authenticated(None));
        assert!(is_authenticated(Some("session123")));
    }
}
