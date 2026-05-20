//! Open-redirect detector.
//!
//! 2026-05-09 (Run-5 GAP-009) — closes the gap that no detector
//! covered before: a query parameter named `?next=`, `?redirect=`,
//! `?return=`, etc. carrying an external `http(s)://`, protocol-
//! relative `//evil.com`, `javascript:`, or `data:` URL is the
//! classic phishing / CSRF-bypass / OAuth-token-theft vector.
//!
//! ## Why a dedicated detector (not folded into `ssrf`)
//!
//! SSRF and open redirect look syntactically similar (both feature
//! URL-shaped values in query parameters) but have **opposite
//! enforcement models**:
//!
//! - SSRF should always block external URLs in fetch-style params
//!   (`?url=`, `?fetch=`) regardless of destination — the WAF
//!   doesn't know which internal service is dangerous to fetch.
//! - Open redirect should allow external URLs in redirect-style
//!   params **when the destination is on an operator-approved
//!   allowlist** (legitimate OAuth `redirect_uri=https://google.com/
//!   oauth2/...` is the canonical case).
//!
//! Folding into SSRF would force one of those policies onto the
//! other; splitting keeps both coherent.
//!
//! ## Detection logic
//!
//! 1. Parse query string. Iterate `(key, value)` pairs.
//! 2. If `key` matches a redirect-param name (closed list — `next`,
//!    `redirect`, `redirect_uri`, `return`, `goto`, `callback`,
//!    `continue`, `url`, `to`, `destination`, `forward`, `rurl`,
//!    `return_to`, `return_url`, `checkout_url`, `image_url`,
//!    `domain`) — proceed.
//! 3. URL-decode the value once. Apply the suspicious-shape regex
//!    set:
//!    - `^\s*https?://` — absolute external URL
//!    - `^\s*//\w` — protocol-relative reference (`//evil.com`)
//!    - `^\s*javascript\s*:` — XSS pivot
//!    - `^\s*data\s*:` — HTML-injection pivot
//!    - `^\s*(%2[fF])?(%2[fF])?(https?|javascript|data)\s*(%3[aA]|:)`
//!      — URL-encoded scheme prefix (`%2F%2Fevil.com`,
//!      `%6A%61%76%61%73%63%72%69%70%74:`)
//! 4. If the value matches any pattern AND the host portion of
//!    the value isn't on `allowed_domains` (literal or
//!    `*.example.com` glob), emit a `Signal { score: 30, tag:
//!    "open_redirect", field: "uri" }`.
//!
//! ## Score 30 (phishing / info-disclosure tier)
//!
//! Open redirect's exploitability is real but indirect — it
//! enables phishing, OAuth token theft, CSRF bypass, but isn't
//! a direct compromise vector like sqli/cmdi. Pattern is
//! heuristic — false positives on legit OAuth flows are realistic
//! without operator config. Score 30 means a single hit doesn't
//! reach `challenge_at: 40`; the signal accumulates only when the
//! IP shows multiple suspicious behaviors. Operators who care more
//! can raise the score via rule engine override OR move to
//! `enforce` from `log_only`.
//!
//! ## Allowlist behaviour (2026-05-20 FP review)
//!
//! - **High-confidence evasions** (`javascript:` / `data:` schemes,
//!   URL-encoded scheme tricks, `@`-userinfo, backslash bypasses)
//!   flag REGARDLESS of the allowlist — they have no legitimate use
//!   in a redirect param.
//! - **Ambiguous absolute / protocol-relative URLs** (`https://host`,
//!   `//host`) flag ONLY when `allowed_domains` is configured AND the
//!   destination host is off it. The default empty allowlist does
//!   NOT flag bare absolute URLs — they're ubiquitous in legitimate
//!   traffic (CDN image proxies, OAuth `redirect_uri`, share links),
//!   and the AI classifier + the evasion set cover the unambiguous
//!   attacks. Operators who want strict off-list blocking populate
//!   `allowed_domains` (literal or `*.example.com` glob).
//!
//! Operators with legitimate redirect targets configure
//! `cfg.detectors.open_redirect.allowed_domains` to suppress the
//! known-good destinations.

use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{url_decode, Detector, Signal};

/// Score emitted when a redirect param carries a suspicious URL.
/// Re-export of the canonical const in [`super::scores::open_redirect`]
/// — kept here for the in-file `tests` module to use.
pub const SCORE: u32 = super::scores::open_redirect::OPEN_REDIRECT;

/// Closed list of conventional redirect-style query parameter
/// names. Match is case-insensitive on the key.
static REDIRECT_PARAM_NAMES: &[&str] = &[
    "next",
    "url",
    "to",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_to",
    "return_url",
    "rurl",
    "destination",
    // 2026-05-09 — Run-7 GAP-009b. `?dest=` is a common short-form
    // alternative to `?destination=` (Slack, GitHub OAuth, several
    // OpenID providers use it). Same phishing surface as the rest.
    "dest",
    "goto",
    "continue",
    "forward",
    "callback",
    "checkout_url",
    "image_url",
    "domain",
];

/// 2026-05-20 (FP review) — HIGH-CONFIDENCE evasion shapes that have
/// NO legitimate use in a redirect param, so they flag regardless of
/// the allowlist (even in the default empty-allowlist mode).
static EVASION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // JavaScript: scheme — XSS pivot via redirect.
        r"(?i)^\s*javascript\s*:",
        // data: scheme — HTML injection via redirect.
        r"(?i)^\s*data\s*:",
        // URL-encoded scheme prefix; catches `%2F%2Fevil.com`,
        // `%6A%61%76%61%73%63%72%69%70%74:` (encoded `javascript:`).
        r"(?i)^\s*(?:%2[fF])(?:%2[fF])?(?:https?|javascript|data)?\s*(?:%3[aA]|:)?",
        // `@`-userinfo trick — the REAL host is after the `@`
        // (`https://trusted.com@evil.com`). No legit redirect uses
        // userinfo in the authority.
        r"(?i)^\s*https?://[^/?#]*@",
        // Backslash tricks — browsers normalise `\` → `/`, so
        // `\/\/evil.com`, `/\evil.com`, `\\evil.com` bypass naive
        // `//` checks. No legit use.
        r"^\s*(?:\\|/\\|\\/)",
        // Protocol-relative — `//evil.com`. Rarely legitimate in a
        // redirect param (HTTPS-everywhere killed protocol-relative
        // redirects) and a textbook open-redirect bypass, so it
        // flags even in the default empty-allowlist mode (subject to
        // the allowlist host-check below for `//cdn.example.com`).
        r"(?i)^\s*//\w",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("evasion regex compiles"))
    .collect()
});

/// AMBIGUOUS absolute / protocol-relative URL shapes. A bare
/// `https://cdn.example.com/img.png` or `//host` is extremely common
/// in legitimate traffic (CDN image proxies, OAuth `redirect_uri`,
/// share links), so these flag ONLY when the operator has configured
/// an `allowed_domains` allowlist AND the destination host is off it.
/// With the default empty allowlist these do NOT fire — the WAF
/// can't know which absolute URLs are malicious without operator
/// context, and the AI classifier + the high-confidence evasion set
/// above cover the unambiguous attacks.
static ABSOLUTE_URL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Absolute external URL with explicit scheme. THIS is the
        // ubiquitous-in-legit-traffic shape (CDN, OAuth) — gated.
        r"(?i)^\s*https?://",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("redirect regex compiles"))
    .collect()
});

/// Open-redirect detector. Stateless apart from the allowed-domain
/// list captured at construction.
pub struct OpenRedirectDetector {
    /// Hostnames considered safe redirect targets. Empty = strict
    /// mode (every external URL in a redirect param flags). Each
    /// entry is either a literal hostname (`example.com`) or a
    /// `*.example.com` glob (matches `foo.example.com`,
    /// `a.b.example.com` — but not bare `example.com`).
    allowed_domains: Vec<String>,
}

impl OpenRedirectDetector {
    pub fn new(allowed_domains: Vec<String>) -> Self {
        Self { allowed_domains }
    }

    /// Empty-allowlist constructor. Strict mode.
    pub fn strict() -> Self {
        Self {
            allowed_domains: Vec::new(),
        }
    }

    /// `true` if `host` is on the allowlist (literal or `*.glob`).
    fn is_allowlisted(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        for entry in &self.allowed_domains {
            let e = entry.to_ascii_lowercase();
            if let Some(suffix) = e.strip_prefix("*.") {
                // `*.example.com` matches `foo.example.com` and
                // `a.b.example.com`, but NOT bare `example.com`
                // (which the operator must add separately if they
                // want it allowed). `.example.com` suffix check.
                let dotted = format!(".{suffix}");
                if h.ends_with(&dotted) {
                    return true;
                }
            } else if h == e {
                return true;
            }
        }
        false
    }
}

impl Default for OpenRedirectDetector {
    fn default() -> Self {
        Self::strict()
    }
}

/// Extract host from a URL-shaped string. Returns `None` for
/// values that don't carry a parseable host (relative paths,
/// `javascript:`/`data:` URLs).
fn extract_host(value: &str) -> Option<&str> {
    // Strip optional scheme + `://`.
    let after_scheme = if let Some(idx) = value.find("://") {
        &value[idx + 3..]
    } else if let Some(rest) = value.strip_prefix("//") {
        rest
    } else {
        return None;
    };

    // Host ends at the first `/`, `?`, `#`, `:` (port), or end.
    let end = after_scheme
        .find(|c: char| matches!(c, '/' | '?' | '#' | ':'))
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..end];
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

impl Detector for OpenRedirectDetector {
    fn id(&self) -> &'static str {
        "open_redirect"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        let query = match req.uri.query() {
            Some(q) if !q.is_empty() => q,
            _ => return signals,
        };

        // Parse `key=value` pairs separated by `&` or `;`. Manual
        // split — cheaper than pulling in `url::form_urlencoded`
        // for a hot-path scan, and we only care about the first
        // matching redirect param per request.
        for pair in query.split(|c| c == '&' || c == ';') {
            let (key, value) = match pair.find('=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => continue,
            };
            if !REDIRECT_PARAM_NAMES.iter().any(|n| key.eq_ignore_ascii_case(n)) {
                continue;
            }
            if value.is_empty() {
                continue;
            }
            // URL-decode once; the encoded-scheme regex still
            // catches double-encoded payloads like `%252F%252Fevil`.
            let decoded = url_decode(value);

            // 1. High-confidence evasion (javascript:/data:/encoded-
            //    scheme/@-userinfo/backslash) — always flag; no legit
            //    use. Allowlist host-check still applies for shapes
            //    that carry a parseable host (so an allowlisted host
            //    reached via a backslash trick isn't double-judged).
            let evasion = EVASION_PATTERNS
                .iter()
                .any(|re| re.is_match(value) || re.is_match(&decoded));

            // 2. Ambiguous absolute / protocol-relative URL — flag
            //    ONLY when an allowlist is configured and the host is
            //    off it. Default (empty allowlist) does NOT flag a
            //    bare `https://cdn…` (legit CDN/OAuth/share links).
            let absolute_offlist = !self.allowed_domains.is_empty()
                && ABSOLUTE_URL_PATTERNS
                    .iter()
                    .any(|re| re.is_match(value) || re.is_match(&decoded))
                && extract_host(&decoded)
                    .map(|h| !self.is_allowlisted(h))
                    .unwrap_or(true);

            if !evasion && !absolute_offlist {
                continue;
            }
            // Allowlist suppression for evasion shapes that carry a
            // host (e.g. protocol-relative behind a backslash) — an
            // explicitly-allowlisted destination shouldn't flag.
            if evasion {
                if let Some(host) = extract_host(&decoded) {
                    if self.is_allowlisted(host) {
                        continue;
                    }
                }
            }
            signals.push(Signal {
                score: SCORE,
                tag: "open_redirect".into(),
                field: "uri".into(),
            });
            // One signal per request — enough for risk
            // accumulation; avoids amplification on multi-param
            // probes.
            break;
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn req_with_uri(uri: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::GET,
            uri.parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        )
    }

    fn make_view<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method: m,
            uri: u,
            version: http::Version::HTTP_11,
            headers: h,
            peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None,
            body: b,
        }
    }

    macro_rules! positive {
        ($name:ident, $uri:expr) => {
            #[test]
            fn $name() {
                let d = OpenRedirectDetector::strict();
                let (m, u, h, b) = req_with_uri($uri);
                let req = make_view(&m, &u, &h, &b);
                let s = d.inspect(&req);
                assert!(
                    s.iter().any(|s| s.tag == "open_redirect"),
                    "expected open_redirect for: {}",
                    $uri,
                );
            }
        };
    }

    // 2026-05-20 FP review — a detector with a configured allowlist
    // that does NOT include the test hosts, so off-list absolute
    // URLs still flag (the operator-opted-in strict behaviour).
    macro_rules! positive_allowlisted {
        ($name:ident, $uri:expr) => {
            #[test]
            fn $name() {
                let d = OpenRedirectDetector::new(vec!["trusted.example".into()]);
                let (m, u, h, b) = req_with_uri($uri);
                let req = make_view(&m, &u, &h, &b);
                let s = d.inspect(&req);
                assert!(
                    s.iter().any(|s| s.tag == "open_redirect"),
                    "expected open_redirect (off-list absolute URL) for: {}",
                    $uri,
                );
            }
        };
    }

    // Evasion shapes — flag in strict (default empty-allowlist) mode.
    positive!(or_redirect_protorel,   "/login?redirect=//evil.com");
    positive!(or_redirect_uri_js,     "/o?redirect_uri=javascript:alert(1)");
    positive!(or_redirect_uri_data,   "/o?redirect_uri=data:text/html,hi");
    positive!(or_url_encoded_slash,   "/r?next=%2F%2Fevil.com");
    positive!(or_url_encoded_js,      "/r?redirect=%6A%61%76%61%73%63%72%69%70%74:alert(1)");
    positive!(or_param_goto,          "/r?goto=//bad.example");
    positive!(or_param_dest_protorel, "/login?dest=//evil.example/path");
    positive!(or_userinfo_trick,      "/r?next=https://trusted.example@evil.com/");
    positive!(or_backslash_trick,     "/r?next=/\\evil.com");

    // Bare absolute URLs — flag only with an allowlist (off-list).
    positive_allowlisted!(or_next_http,         "/login?next=http://evil.com");
    positive_allowlisted!(or_next_https,        "/login?next=https://evil.com/path");
    positive_allowlisted!(or_param_to,          "/r?to=http://attacker.com");
    positive_allowlisted!(or_param_destination, "/r?destination=https://phisher.example");
    positive_allowlisted!(or_param_continue,    "/r?continue=https://x.example");
    positive_allowlisted!(or_param_callback,    "/r?callback=https://attacker.example/c");
    positive_allowlisted!(or_param_return,      "/r?return=https://attacker.example/back");
    positive_allowlisted!(or_param_return_to,   "/r?return_to=https://x.example");
    positive_allowlisted!(or_param_rurl,        "/r?rurl=https://x.example");
    positive_allowlisted!(or_first_pair,        "/r?safe=ok&next=http://evil.com");
    positive_allowlisted!(or_uppercase_key,     "/r?REDIRECT=https://evil.com");
    positive_allowlisted!(or_with_other_params, "/r?from=a&next=http://evil.com&utm=z");
    positive_allowlisted!(or_param_dest,        "/login?dest=http://evil.com");

    // 2026-05-20 FP review — the FP that triggered this: a bare
    // absolute URL in a redirect param with NO allowlist (default)
    // must NOT flag (legit CDN proxy / OAuth redirect_uri).
    #[test]
    fn strict_mode_does_not_flag_bare_absolute_url() {
        let d = OpenRedirectDetector::strict();
        for uri in [
            "/proxy?url=https://cdn.example.com/img/hero.png",
            "/oauth/callback?redirect_uri=https://app.example.com/done",
            "/login?next=https://www.ourshop.com/account",
        ] {
            let (m, u, h, b) = req_with_uri(uri);
            let req = make_view(&m, &u, &h, &b);
            assert!(
                d.inspect(&req).is_empty(),
                "bare absolute URL must not flag in strict mode: {uri}",
            );
        }
    }

    macro_rules! negative {
        ($name:ident, $uri:expr) => {
            #[test]
            fn $name() {
                let d = OpenRedirectDetector::strict();
                let (m, u, h, b) = req_with_uri($uri);
                let req = make_view(&m, &u, &h, &b);
                assert!(
                    d.inspect(&req).is_empty(),
                    "false positive for: {}",
                    $uri,
                );
            }
        };
    }

    negative!(or_relative_path,       "/login?next=/dashboard");
    negative!(or_empty_value,         "/login?next=");
    negative!(or_no_query,            "/login");
    negative!(or_query_no_redirect,   "/login?utm=campaign&id=42");
    negative!(or_value_starts_with_q, "/r?next=?param=value");
    negative!(or_unrelated_param,     "/r?customParam=https://x.example");
    negative!(or_not_a_url_value,     "/r?next=hello-world");
    negative!(or_id_token_value,      "/r?next=eyJhbGciOiJIUzI1NiJ9");

    // Allowlist behaviour.
    #[test]
    fn allowlist_literal_match_skips_signal() {
        let d = OpenRedirectDetector::new(vec!["example.com".into()]);
        let (m, u, h, b) = req_with_uri("/r?next=https://example.com/login");
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn allowlist_glob_subdomain_skips_signal() {
        let d = OpenRedirectDetector::new(vec!["*.example.com".into()]);
        let (m, u, h, b) = req_with_uri("/r?next=https://oauth.example.com/cb");
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn allowlist_glob_does_not_match_bare_apex() {
        // `*.example.com` matches subdomains only, not `example.com`.
        let d = OpenRedirectDetector::new(vec!["*.example.com".into()]);
        let (m, u, h, b) = req_with_uri("/r?next=https://example.com/login");
        let req = make_view(&m, &u, &h, &b);
        assert!(
            !d.inspect(&req).is_empty(),
            "*.example.com should not match bare example.com",
        );
    }

    #[test]
    fn allowlist_offlist_domain_still_flags() {
        let d = OpenRedirectDetector::new(vec!["example.com".into()]);
        let (m, u, h, b) = req_with_uri("/r?next=https://evil.com/x");
        let req = make_view(&m, &u, &h, &b);
        assert!(!d.inspect(&req).is_empty());
    }

    #[test]
    fn allowlist_does_not_apply_to_javascript_scheme() {
        // `javascript:` has no host — allowlist can't suppress it.
        let d = OpenRedirectDetector::new(vec!["example.com".into()]);
        let (m, u, h, b) = req_with_uri("/r?next=javascript:alert(1)");
        let req = make_view(&m, &u, &h, &b);
        assert!(!d.inspect(&req).is_empty());
    }

    #[test]
    fn extract_host_handles_https_url() {
        assert_eq!(extract_host("https://example.com/path"), Some("example.com"));
        assert_eq!(extract_host("https://example.com:8080/x"), Some("example.com"));
        assert_eq!(extract_host("//evil.com/path"), Some("evil.com"));
        assert_eq!(extract_host("/local"), None);
        assert_eq!(extract_host("javascript:alert(1)"), None);
    }
}
