# Phase 2 — MEDIUM (Run-4)

> **Branch:** all changes target `develop`.

---

## SEC-M002 · Add a dedicated `command_injection` detector

**Source:** Run-4 §SEC-M002.

### Verified state (2026-05-08, on `develop`)

`crates/aegis-security/src/detectors/`:

```
ai/   body_abuse.rs   brute_force.rs   header_injection.rs
mask.rs   mod.rs   path_traversal.rs   recon.rs   sqli.rs   ssrf.rs   xss.rs
```

**No `command_injection.rs` / `cmdi.rs`.** The cmdi patterns (`$()`, `|`, backticks, `;cmd`) currently catch only via:

1. **AI detector** — when enabled, it scores cmdi-shaped payloads above threshold.
2. **Incidental overlap** with other detectors — `$()` in some shapes hits `path_traversal.rs` regex by accident; pipes don't hit anything reliably.

Looking at `path_traversal.rs:10-32`:

```rust
static TRAVERSAL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?:\.\.[\\/])",
        r"(?:%2e%2e[\\/])",
        ...
        r"(?:/etc/(?:passwd|shadow|hosts|resolv\.conf))",
        r"(?:/proc/self/(?:environ|cmdline|fd))",
        ...
    ]
});
```

None match `$()` or `|`. So when AI is disabled (the SEC-C001 / C002 follow-up state), cmdi probes pass through undetected. The QA's `cmdi-002` (pipe in `input` param) and `cmdi-004` (subshell in `arg` param) are real catches that the rule-based pipeline misses.

**The QA's diagnosis "parameter-name sensitivity" is wrong.** All detectors scan the full URI string + body — they're parameter-name-agnostic by construction. The pattern just isn't in any rule. (Why `?cmd=$(id)` got caught: because `cmd` happens to look benign-suspicious to the AI; with AI disabled, none of `cmd`, `q`, `input`, `arg` get caught.)

### Plan

Mirror the existing detector shape (sqli.rs, xss.rs, etc.). Pattern-only Rust; no AI / Hyperscan dependency.

**Step 1 — create `crates/aegis-security/src/detectors/command_injection.rs`.**

```rust
//! Command injection detector. Scans query string + request body
//! for shell-shaped patterns: pipe-to-cmd, dollar subshells,
//! backtick subshells, semicolon-cmd, and well-known shell builtins.
//!
//! Mirror of sqli/xss shape — regex over the URI string +
//! body bytes, with field tagging for the audit log.

use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

pub struct CommandInjectionDetector;

static CMDI_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Subshell forms — $(cmd), `cmd`, ${cmd}.
        r"(?i)\$\([^)]+\)",
        r"(?i)`[^`]+`",
        r"(?i)\$\{[^}]+\}",
        // Pipe-to-shell-cmd: '| whoami', '| nc -e', etc. The
        // shell builtins list is conservative — broad enough to
        // catch the OWASP cmdi sample set, narrow enough to skip
        // bare pipes in regex / base64 payloads.
        r"(?i)\|\s*(?:whoami|id|uname|cat|ls|nc|curl|wget|sh|bash|zsh|ksh|cmd|powershell|python|perl|ruby|php|nslookup|ping)\b",
        // Semicolon-shell-cmd: '; whoami', '; rm -rf'.
        r"(?i);\s*(?:whoami|id|uname|cat|ls|nc|curl|wget|sh|bash|zsh|ksh|cmd|powershell|python|perl|ruby|php|nslookup|ping|rm)\b",
        // && / || command chaining
        r"(?i)(?:&&|\|\|)\s*(?:whoami|id|uname|cat|ls|nc|curl|wget|sh|bash|zsh|ksh|cmd|powershell|python|perl|ruby|php|nslookup|ping|rm)\b",
        // /bin/{sh,bash} direct invocation
        r"(?i)/bin/(?:sh|bash|zsh|ksh|dash)\b",
        // /etc/passwd dump piped through cat (also catches
        // exfil-style cmdi distinct from path_traversal's
        // direct /etc/passwd access).
        r"(?i)cat\s+/etc/passwd",
        // Reverse shell shapes — bash -i, nc -e, mkfifo + nc.
        r"(?i)bash\s+-i\b",
        r"(?i)nc\s+-e\b",
        // Wget / curl exfil to attacker hosts (suspicious only
        // when paired with shell injection context — overlaps
        // with SSRF detector's URL-scan but covers the cmdi
        // shape `; wget http://...`).
        r"(?i)(?:^|;|\|\|?|&&|`)\s*(?:wget|curl)\s+http",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

impl Detector for CommandInjectionDetector {
    fn id(&self) -> &'static str {
        "command_injection"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Decode the URI once; cmdi patterns often arrive %-encoded.
        let raw_uri = req.uri.to_string();
        let decoded_uri = super::url_decode(&raw_uri);
        check(&raw_uri, "uri", &mut signals);
        check(&decoded_uri, "uri", &mut signals);

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
```

Score `50` matches sqli/xss/ssrf weight.

**Step 2 — register in `detectors/mod.rs`.**

```rust
pub mod command_injection;
pub use command_injection::CommandInjectionDetector;
```

**Step 3 — wire into the pipeline boot path.** Find where other detectors are constructed (likely `aegis-bin::main` or `aegis-proxy::run`); add `Box::new(CommandInjectionDetector)` to the detector list. Same place `SqliDetector` etc. are pushed.

**Step 4 — surface in capabilities.** Add `"command_injection"` to the `rules_engine.policies` list in `run.rs:build_interop_runtime` (alongside sqli, xss, ai, etc.). Mirror in the test ctx_v23 fixture in `crates/aegis-control/src/interop/control.rs::tests::ctx_v23`.

**Step 5 — wire into rule_map for `set_profile`.**

```rust
// crates/aegis-control/src/interop/rule_map.rs
match primary {
    ...
    "command_injection" => ("rules_engine", "command_injection"),
    ...
}
```

So the OC harness can `set_profile { policies: ["command_injection"], mode: "log_only" }`.

**Step 6 — add detector mask config field.** `cfg.detectors.command_injection: { enabled: bool }` matching the existing pattern in `crates/aegis-core/src/config.rs::DetectorsConfig`. Default `enabled: true`.

**Step 7 — RED tests** in `command_injection.rs` test module. Mirror `path_traversal.rs:71-130` pattern:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    macro_rules! positive {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = CommandInjectionDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(!d.inspect(&req).is_empty(), "expected detection: {}", $input);
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
                assert!(d.inspect(&req).is_empty(), "false positive: {}", $input);
            }
        };
    }

    // Positive — QA report cases
    positive!(cmdi_pipe_whoami_input,    "/search?input=test|whoami");
    positive!(cmdi_subshell_arg,         "/run?arg=$(id)");
    positive!(cmdi_pipe_q,               "/search?q=test|nc%20-e%20/bin/sh");

    // Positive — broader coverage
    positive!(cmdi_backtick,             "/exec?x=`whoami`");
    positive!(cmdi_brace_subshell,       "/exec?x=${whoami}");
    positive!(cmdi_semicolon_rm,         "/run?cmd=foo;rm -rf /tmp");
    positive!(cmdi_double_pipe_chain,    "/run?cmd=ls||whoami");
    positive!(cmdi_double_amp_chain,     "/run?cmd=ls&&whoami");
    positive!(cmdi_bin_sh,               "/exec?cmd=/bin/sh -c id");
    positive!(cmdi_bash_i,               "/exec?cmd=bash -i");
    positive!(cmdi_cat_passwd,           "/run?cmd=cat /etc/passwd");
    positive!(cmdi_url_encoded,          "/run?x=%24%28id%29");

    // Negative — common FP traps
    negative!(clean_root,                "/");
    negative!(clean_query,               "/search?q=hello%20world");
    negative!(clean_pipe_in_regex,       "/api/regex?p=foo|bar");  // bare pipe, no shell cmd after
    negative!(clean_dollar_var,          "/api?v=${user.name}");    // brace var ref — false-pos risk; we accept some FPs here
    negative!(clean_base64_padding,      "/api?b=YWJjZA%3D%3D");
    negative!(clean_amp_in_query,        "/api?a=1&b=2");
    negative!(clean_semicolon_param_sep, "/api?a=1;b=2");           // legacy ';' separator; no shell cmd after

    // Note: `${user.name}` MAY or MAY NOT trigger depending on
    // pattern strictness. Document the trade-off in the test.
}
```

**Step 8 — manual verification**.

```sh
make bench-dev    # in another terminal
SECRET="waf-hackathon-2026-ctrl"

# Run-4's failing cases
curl -ksi "http://127.0.0.1:8080/search?input=test|whoami"      # → 403 X-WAF-Action: block X-WAF-Rule-Id: command_injection
curl -ksi "http://127.0.0.1:8080/run?arg=\$(id)"                # → 403 X-WAF-Rule-Id: command_injection

# log_only via set_profile (verify the policy toggle works)
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H "content-type: application/json" \
  -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["command_injection"]}' \
  http://127.0.0.1:8080/__waf_control/set_profile

curl -ksi "http://127.0.0.1:8080/run?arg=\$(id)"                # → 200 X-WAF-Action: block X-WAF-Mode: log_only

# Restore enforce
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H "content-type: application/json" \
  -d '{"scope":"all","mode":"enforce"}' \
  http://127.0.0.1:8080/__waf_control/set_profile
```

### Acceptance

- [ ] `command_injection.rs` lands with the detector + 12+ tests
- [ ] `cmdi-002` (`?input=test|whoami`) and `cmdi-004` (`?arg=$(id)`) both detected with `X-WAF-Rule-Id: command_injection`
- [ ] Capabilities response includes `"command_injection"` under `rules_engine.policies`
- [ ] `rule_to_feature("command_injection")` → `Some(("rules_engine", "command_injection"))`
- [ ] `set_profile { policies: ["command_injection"], mode: "log_only" }` works (log_only path: 200 + `X-WAF-Mode: log_only`)
- [ ] Detector mask CRUD via `/api/detectors` toggles cmdi alongside other classes
- [ ] No new false-positives on the existing clean-traffic test set (sweep tests/security/clean_baselines.json or equivalent)

**Effort:** ~1.5 h.

---

## Sequencing

Single PR: `feat(detectors): dedicated command_injection class (SEC-M002)`.
