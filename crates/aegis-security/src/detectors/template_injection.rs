//! Server-Side Template Injection (SSTI) detector.
//!
//! 2026-05-08 (Run-5 GAP-006) — closes the gap that AI alone was
//! covering pre-fix. Detects template-engine payloads in URI +
//! body across Jinja2 / Twig / Mako / Freemarker / Velocity /
//! Spring SpEL / Handlebars / Mustache.
//!
//! ## Why a dedicated detector
//!
//! SSTI's syntax (`{{ }}`, `${ }`, `<#...>`, `#set(...)`) is
//! template-engine-specific and distinct from shell-meta cmdi
//! (`$()`, `|cmd`). Bundling would dilute the cmdi pattern set;
//! splitting keeps both detectors' patterns coherent + makes
//! `set_profile { policies: ["template_injection"], mode: "log_only" }`
//! a single-target operator knob.
//!
//! ## Detection logic
//!
//! Each pattern requires **both** the brace/tag syntax AND a
//! suspicious internal — bare matched braces alone do NOT fire.
//! This avoids false positives on legit JSON responses, web-
//! framework debug pages, or template-output APIs that echo
//! the brace syntax in error messages.
//!
//! Score 50 — high-confidence injection tier (same as sqli,
//! cmdi, ssrf). SSTI is RCE-class; the conservative pattern
//! set keeps FP rate at sqli's profile.

use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

pub struct TemplateInjectionDetector;

static SSTI_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Numeric expressions in `{{...}}` — the canonical SSTI
        // proof-of-concept. Allows quoted operands so Twig's
        // `{{7*'7'}}` and Jinja's `{{ '7' * 7 }}` both match
        // (the engine coerces both to numeric and multiplies).
        // GAP-006b (Run-6, 2026-05-09) — extended quote tolerance.
        r#"(?i)\{\{\s*['"]?\d+['"]?\s*\*\s*['"]?\d+['"]?\s*\}\}"#,

        // Python attribute access — Jinja2/Mako sandbox-escape
        // primitives. `__class__.__mro__`, `__subclasses__`, etc.
        r"(?i)\{\{[^}]*\.\s*__\w+__",

        // Jinja2 globals that aren't legit URL/body content.
        r"(?i)\{\{\s*config\s*\}\}",
        r"(?i)\{\{\s*(?:cycler\.|joiner\.|namespace\(|self\.|request\.|lipsum\.|url_for)",

        // Jinja2 / Twig statement tags — execution-side constructs.
        r"(?i)\{%\s*(?:set|for|if|import|extends|include|with)\b",

        // Freemarker directives.
        r"(?i)<#\s*(?:assign|list|if|include|import|setting|escape)\b",

        // Velocity directives.
        r"(?i)#(?:set|if|foreach|parse|include|macro|evaluate)\s*\(",

        // Mako `<%! ... %>` / `<% ... %>` server-block syntax.
        r"(?i)<%[!=]?\s*",

        // Numeric expression in `${...}` — Spring SpEL / Mako /
        // shell-style template POC. Same quote-tolerance as the
        // `{{...}}` form (GAP-006b).
        r#"(?i)\$\{\s*['"]?\d+['"]?\s*\*\s*['"]?\d+['"]?\s*\}"#,

        // Spring SpEL — type / bean / instantiation references.
        r##"(?i)\$\{\s*T\s*\(\s*['"]"##,           // ${T('java.lang.Runtime')...}
        r"(?i)\$\{\s*#root\.|\$\{\s*@\w+\.",       // SpEL bean accessors
        r"(?i)\$\{\s*new\s+\w+",                   // ${new ProcessBuilder(...)}

        // Handlebars / Mustache exec-capable helpers.
        r"(?i)\{\{#with\s|\{\{#each\s",
        r"(?i)\{\{lookup\s+\(",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("ssti regex compiles"))
    .collect()
});

impl Detector for TemplateInjectionDetector {
    fn id(&self) -> &'static str {
        "template_injection"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // URI surface — both raw and url-decoded.
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
    for re in SSTI_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::template_injection::TEMPLATE_INJECTION,
                tag: "template_injection".into(),
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
                let d = TemplateInjectionDetector;
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
                let d = TemplateInjectionDetector;
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

    // --- QA Run-5 reproductions ---
    positive!(ssti_jinja_arithmetic,    "/search?q={{7*7}}");
    positive!(ssti_spel_arithmetic,      "/search?q=${7*7}");

    // --- Jinja2 / Twig classic payloads ---
    positive!(ssti_jinja_config,         "/?q={{config}}");
    positive!(ssti_jinja_class_mro,      "/?q={{x.__class__.__mro__}}");
    positive!(ssti_jinja_subclasses,     "/?q={{x.__class__.__subclasses__()}}");
    positive!(ssti_jinja_cycler,         "/?q={{cycler.next}}");
    positive!(ssti_jinja_request,        "/?q={{request.application}}");
    positive!(ssti_jinja_self,           "/?q={{self.foo}}");
    positive!(ssti_jinja_url_for,        "/?q={{url_for.foo}}");

    // --- Statement tags ---
    positive!(ssti_jinja_set,            "/?q={%set+x=1%}");
    positive!(ssti_jinja_for,            "/?q={%for+i+in+range(10)%}");

    // --- Freemarker / Velocity / Mako ---
    positive!(ssti_freemarker_assign,    "/?q=%3C%23assign+x=1%3E");      // <#assign x=1>
    positive!(ssti_velocity_set,         "/?q=%23set%28%24x=1%29");         // #set($x=1)
    positive!(ssti_velocity_evaluate,    "/?q=%23evaluate%28%24code%29");
    positive!(ssti_mako_block,           "/?q=%3C%25%21+code+%25%3E");      // <%! code %>

    // --- Spring SpEL ---
    positive!(ssti_spel_type_runtime,    "/?q=%24%7BT%28%27java.lang.Runtime%27%29%7D");  // ${T('java.lang.Runtime')}
    positive!(ssti_spel_root_accessor,   "/?q=%24%7B%23root.foo%7D");        // ${#root.foo}
    positive!(ssti_spel_bean_accessor,   "/?q=%24%7B%40beanName.method%7D"); // ${@beanName.method}
    positive!(ssti_spel_new_instance,    "/?q=%24%7Bnew+ProcessBuilder%7D"); // ${new ProcessBuilder

    // --- Handlebars / Mustache ---
    positive!(ssti_handlebars_with,      "/?q={{%23with+ctx%7D");          // {{#with ctx}
    positive!(ssti_handlebars_lookup,    "/?q={{lookup+%28+a+b+%29}}");

    // --- Negatives: brace syntax that's NOT SSTI ---

    // Bare template output — APIs that echo template-style placeholders
    // in JSON error messages or static-asset paths must not FP.
    negative!(clean_bare_brace_var,      "/?q={{user.name}}");

    // Bare ${VAR} envvar — used by shell templates, CI variables.
    // (May still match cmdi at score 50 — that's a separate detector.)
    negative!(clean_bare_envvar,         "/?q=${HOME}");
    negative!(clean_bare_envvar_user,    "/?q=${USER}");

    // Static paths with brace-shaped chars in the URL (rare but
    // not impossible).
    negative!(clean_root,                "/");
    negative!(clean_simple_query,        "/api?q=hello");
    negative!(clean_json_field,          "/api?id=42");
    negative!(clean_url_encoded_brace,   "/?q=%7B%7D");                   // bare {}
    negative!(clean_paren_query,         "/api?expr=(a+b)");
    negative!(clean_curly_in_uuid,       "/api/550e8400-e29b-41d4-a716");

    // --- GAP-006b (Run-6, 2026-05-09) — quote-tolerant SSTI POC ---
    //
    // Twig coerces quoted-string operands to numbers when used in
    // arithmetic (`'7' * 7 == 49`), so the quoted-operand variants
    // are equivalent to bare-numeric POCs. URL-encoded quote
    // variants exercise the URI surface; raw quotes exercise the
    // body surface (URI parser may reject `'` in some shells).
    positive!(ssti_twig_quoted_right,    "/?q=%7B%7B7*%277%27%7D%7D");      // {{7*'7'}}
    positive!(ssti_twig_quoted_left,     "/?q=%7B%7B%277%27*7%7D%7D");      // {{'7'*7}}
    positive!(ssti_twig_double_quoted,   "/?q=%7B%7B%227%22*7%7D%7D");      // {{"7"*7}}
    positive!(ssti_twig_with_spaces,     "/?q=%7B%7B+7+*+%277%27+%7D%7D");  // {{ 7 * '7' }}
    positive!(ssti_spel_quoted,          "/?q=%24%7B%277%27*7%7D");          // ${'7'*7}

    // Freemarker regression coverage — these were reported as
    // "missed" in QA Run-6; verifying via direct tests confirms
    // the patterns added in Run-5 still cover them. URL-encoded
    // forms exercise the realistic transport.
    positive!(ssti_freemarker_assign_alt, "/?q=%3C%23assign+ex=%22runtime%22%3E");  // <#assign ex="runtime">
    positive!(ssti_freemarker_if,         "/?q=%3C%23if+x%3E");                       // <#if x>
    positive!(ssti_freemarker_list,       "/?q=%3C%23list+seq+as+x%3E");              // <#list seq as x>
    positive!(ssti_freemarker_setting,    "/?q=%3C%23setting+locale=%22en%22%3E");    // <#setting locale="en">

    // Negative — quoted strings in non-multiplication contexts
    // must NOT FP.
    negative!(clean_quoted_string_no_mul, "/?q={{name='alice'}}");
    negative!(clean_freemarker_comment,   "/?q=%3C%23--+a+legit+comment+--%3E");      // <#-- comment -->
}
