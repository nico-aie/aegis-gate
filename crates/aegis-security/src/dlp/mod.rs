pub mod fpe;

use regex::Regex;
use std::sync::LazyLock;

/// DLP action to take on a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DlpAction {
    Redact,
    Mask,
    Block,
    Monitor,
}

/// A DLP pattern match.
#[derive(Clone, Debug)]
pub struct DlpMatch {
    pub pattern_name: String,
    pub matched_value: String,
    pub action: DlpAction,
}

/// RF-FP (2026-07-08) — coarse pattern class used by the policy-aware
/// [`redact_with`]. `Token` (jwt whole-match) is skipped on auth paths;
/// `Pii` (email/phone) is opt-in; `Secret`/`Financial` always redact.
/// Structural key-value patterns are `Secret` but carry a per-match
/// token-class check ([`key_is_token_class`]) so an `access_token` value on
/// an auth path survives while a `db_password`/`client_secret` in the same
/// body does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternClass {
    Token,
    Secret,
    Financial,
    Pii,
}

/// DLP pattern definition.
struct DlpPattern {
    name: &'static str,
    class: PatternClass,
    regex: Regex,
    validator: Option<fn(&str) -> bool>,
    /// `redact()` replacement template. Fixed-shape token patterns use the
    /// default `"[REDACTED]"` (whole match). Structural key-value patterns
    /// (RF-1) capture the `KEY<sep>` prefix in a named group `pre` and use
    /// `"${pre}[REDACTED]"` so only the VALUE is scrubbed — the response
    /// keeps valid JSON/YAML structure and the app keeps working.
    replacement: &'static str,
    /// True for the RF-1 key-value patterns: `redact()` uses the closure path
    /// (benign-key / benign-value FP guards + `${pre}` value-only scrub).
    /// False for fixed-shape token patterns (whole-match `[REDACTED]`).
    structural: bool,
}

/// Sensitive key-name stems (RF-1, 2026-07-06). A response field whose key
/// contains one of these, carrying a string value, is a credential leak per
/// contract §5.2. Reused across the env / JSON / YAML / SetEnv shapes.
///
/// RF-FP (2026-07-08) — split into the token stem and the non-token secret
/// stems so the auth-path skip ([`key_is_token_class`]) can keep the intended
/// token payload on token-issuing endpoints while still redacting every other
/// credential. The structural regexes compile against the UNION, so the match
/// surface is byte-for-byte identical to the pre-split single-stem version.
const TOKEN_KEY_STEM: &str = r"token";
const NON_TOKEN_SECRET_STEM: &str = concat!(
    r"password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key",
    r"|credential|db[_-]?pass|passphrase|client[_-]?secret",
);

static DLP_PATTERNS: LazyLock<Vec<DlpPattern>> = LazyLock::new(|| {
    let stem = format!("{NON_TOKEN_SECRET_STEM}|{TOKEN_KEY_STEM}");
    let stem = stem.as_str();
    vec![
        DlpPattern {
            name: "credit_card",
            class: PatternClass::Financial,
            regex: Regex::new(r"\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b").unwrap(),
            validator: Some(luhn_check),
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "ssn",
            class: PatternClass::Financial,
            regex: Regex::new(r"\b(\d{3}-\d{2}-\d{4})\b").unwrap(),
            validator: Some(ssn_validate),
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "iban",
            class: PatternClass::Financial,
            regex: Regex::new(r"\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b").unwrap(),
            validator: Some(iban_mod97),
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "email",
            class: PatternClass::Pii,
            regex: Regex::new(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "phone",
            class: PatternClass::Pii,
            regex: Regex::new(r"\b(\+?\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{4})\b").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "aws_key",
            class: PatternClass::Secret,
            regex: Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "aws_secret",
            class: PatternClass::Secret,
            regex: Regex::new(r"(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "github_token",
            class: PatternClass::Secret,
            regex: Regex::new(r"\b(gh[ps]_[A-Za-z0-9_]{36,})\b").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        // RF-2 (2026-07-06) — stripe/publishable/restricted keys. Loosened
        // from `[A-Za-z0-9]{24,}` to allow `_`/`-` and a 16-char floor: the
        // pre-fix pattern broke on `sk_live_wafhack2026_prod_key` (underscore
        // truncated the run below 24). `sk_live_`/`pk_live_`/`rk_live_` is an
        // unambiguous secret prefix → FP≈0.
        DlpPattern {
            name: "stripe_key",
            class: PatternClass::Secret,
            regex: Regex::new(r"\b((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9_-]{16,})\b").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "slack_token",
            class: PatternClass::Secret,
            regex: Regex::new(r"\b(xox[bpars]-[A-Za-z0-9-]+)\b").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        // RF-2 — Google API key.
        DlpPattern {
            name: "google_api_key",
            class: PatternClass::Secret,
            regex: Regex::new(r"\b(AIza[0-9A-Za-z_-]{35})\b").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        // RF-2 — broadened to include OpenSSH-format private keys.
        DlpPattern {
            name: "pem_private_key",
            class: PatternClass::Secret,
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        // RF-2 — SSH public keys (`ssh-ed25519 AAAA…`, `ssh-rsa …`).
        DlpPattern {
            name: "ssh_public_key",
            class: PatternClass::Secret,
            regex: Regex::new(r"\b(ssh-(?:rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/=]{20,})").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        // RF-2 — Unix password hashes: bcrypt (`$2a/b/x/y$`), argon2, and
        // sha512-crypt (`$6$`). The `$X$` prefix + ≥15 non-space chars is
        // credential-specific. `$1$`/`$5$` md5/sha256-crypt omitted to avoid
        // `$1`-style template collisions.
        DlpPattern {
            name: "password_hash",
            class: PatternClass::Secret,
            regex: Regex::new(r#"(\$(?:2[abxy]|argon2(?:id|i|d)?|6)\$[^\s"']{15,})"#).unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        DlpPattern {
            name: "jwt",
            class: PatternClass::Token,
            regex: Regex::new(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)\b").unwrap(),
            validator: None,
            replacement: "[REDACTED]",
            structural: false,
        },
        // RF-1 (2026-07-06) — structural key-value secret redaction,
        // format-independent + VALUE-preserving. The pre-fix `env_secret`
        // only matched env-file `KEY=VALUE`; the S-Tester 200-leaks were
        // JSON/YAML/.htaccess. Each form captures the `KEY<sep>` prefix in
        // group `pre` so redact() scrubs only the value (`${pre}[REDACTED]`),
        // keeping the body well-formed. `scan()` reports `pre` (key only,
        // never the secret value).
        //
        // env / dotfile: `admin_secret=…`, `DB_PASSWORD=…`. (name kept
        // `env_secret` for audit/back-compat.)
        DlpPattern {
            name: "env_secret",
            class: PatternClass::Secret,
            regex: Regex::new(&format!(
                r"(?im)(?P<pre>^[ \t]*[\w.-]*(?:{stem})[\w.-]*[ \t]*=[ \t]*)\S.*$"
            ))
            .unwrap(),
            validator: None,
            replacement: "${pre}[REDACTED]",
            structural: true,
        },
        // JSON: `"db_password":"…"`. String values only (`:"…"`) — a
        // bool/number (`"has_password":true`) has no opening quote and is
        // left untouched, which drops the biggest FP class.
        DlpPattern {
            name: "json_secret",
            class: PatternClass::Secret,
            regex: Regex::new(&format!(
                r#"(?i)(?P<pre>"[\w.-]*(?:{stem})[\w.-]*"[ \t]*:[ \t]*")(?:[^"\\]|\\.)*""#
            ))
            .unwrap(),
            validator: None,
            replacement: "${pre}[REDACTED]\"",
            structural: true,
        },
        // YAML: `db_password: …` (line-anchored, unquoted key so it can't
        // collide with the JSON form).
        DlpPattern {
            name: "yaml_secret",
            class: PatternClass::Secret,
            regex: Regex::new(&format!(
                r"(?im)(?P<pre>^[ \t]*[\w.-]*(?:{stem})[\w.-]*[ \t]*:[ \t]*)\S.*$"
            ))
            .unwrap(),
            validator: None,
            replacement: "${pre}[REDACTED]",
            structural: true,
        },
        // Apache `.htaccess`: `SetEnv DB_PASS …` (space-separated, may be in
        // a `# comment`).
        DlpPattern {
            name: "htaccess_setenv",
            class: PatternClass::Secret,
            regex: Regex::new(&format!(
                r"(?im)(?P<pre>SetEnv[ \t]+[\w.-]*(?:{stem})[\w.-]*[ \t]+)\S.*$"
            ))
            .unwrap(),
            validator: None,
            replacement: "${pre}[REDACTED]",
            structural: true,
        },
    ]
});

/// Scan text for DLP-sensitive data.
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut matches = Vec::new();
    for pat in DLP_PATTERNS.iter() {
        for cap in pat.regex.captures_iter(text) {
            let value = cap.get(1).map_or(cap.get(0).unwrap().as_str(), |m| m.as_str());
            if let Some(validator) = pat.validator {
                if !validator(value) {
                    continue;
                }
            }
            matches.push(DlpMatch {
                pattern_name: pat.name.into(),
                matched_value: value.into(),
                action: DlpAction::Mask,
            });
        }
    }
    matches
}

/// Mask a credit card: `****-****-****-1234`.
pub fn mask_credit_card(cc: &str) -> String {
    let digits: String = cc.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "****".to_string();
    }
    let last4 = &digits[digits.len() - 4..];
    format!("****-****-****-{last4}")
}

/// Mask an SSN: `***-**-1234`.
pub fn mask_ssn(ssn: &str) -> String {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "***-**-****".to_string();
    }
    let last4 = &digits[digits.len() - 4..];
    format!("***-**-{last4}")
}

/// Mask an email: `j***@example.com`.
pub fn mask_email(email: &str) -> String {
    if let Some(at) = email.find('@') {
        let local = &email[..at];
        let domain = &email[at..];
        if local.len() <= 1 {
            format!("*{domain}")
        } else {
            let first = &local[..1];
            format!("{first}***{domain}")
        }
    } else {
        "***".to_string()
    }
}

/// RF-1 FP guard — benign metadata key suffixes that carry a stem substring
/// but are NOT the credential itself: `token_type` (OAuth), `password_updated_at`,
/// `secret_question_enabled`, `api_key_last_used`, etc. A `pre` (key+separator)
/// matching this is left untouched so we mask credentials, not the metadata
/// around them.
static BENIGN_KEY_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:_at|_on|_date|_time|_ts|_count|_type|_name|_id|_enabled|_disabled|_required|_strength|_hint|_expires?|_expiry|_updated|_changed|_created|_status|_algo|_length|_len|_size|_policy|_version|_ttl|_flag|_present|_set|_masked|_visible|_used|_rotated)[\w.-]*[\s\x22:=]",
    )
    .unwrap()
});

/// RF-1 FP guard — benign values that are never a secret: bool / null / number,
/// or an already-redacted marker (idempotency across overlapping patterns).
static BENIGN_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^(?:true|false|null|~|-?\d+(?:\.\d+)?|\[REDACTED\])$"#).unwrap()
});

/// RF-FP (2026-07-08) — token-key matcher: is this structural `pre` (the
/// captured `KEY<sep>` prefix) a *token-class* key? True iff it carries the
/// `token` stem AND none of the non-token secret stems. Used by
/// [`redact_with`] to keep `access_token` / `refresh_token` / `token` /
/// `csrf_token` on auth paths while still redacting `client_secret`,
/// `db_password`, `api_key`, etc. A key with BOTH (e.g. `secret_token`)
/// is treated as a secret — the safe default is to redact.
fn key_is_token_class(pre: &str) -> bool {
    static TOKEN_KEY_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"(?i)(?:{TOKEN_KEY_STEM})")).unwrap());
    static NON_TOKEN_SECRET_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"(?i)(?:{NON_TOKEN_SECRET_STEM})")).unwrap());
    TOKEN_KEY_RE.is_match(pre) && !NON_TOKEN_SECRET_RE.is_match(pre)
}

/// RF-FP (2026-07-08) — response-body redaction policy. Drives the QC
/// false-positive reduction: `keep_tokens` is set on token-issuing (auth)
/// endpoints so the intended token payload survives; `redact_email` /
/// `redact_phone` gate the broad PII patterns that are off by default.
#[derive(Clone, Copy, Debug)]
pub struct RedactPolicy {
    pub redact_email: bool,
    pub redact_phone: bool,
    pub keep_tokens: bool,
    /// RF-FP (2026-07-09 QC — "full key-first") — run the free-floating
    /// VALUE-shape secret/financial patterns (`aws_key`, `github_token`,
    /// `stripe`, `slack_token`, `google_api`, `pem`, `ssh`, `password_hash`,
    /// `jwt`, `credit_card`, `ssn`, `iban`). When **false** (the default
    /// posture) only the structural KEY-value patterns redact — a value is
    /// scrubbed only when its *key* names a secret (`password`, `secret`,
    /// `token`, `api_key`, …). This is the low-FP "check the key, not the
    /// value" mode: opaque IDs that merely *look* like an IBAN / card / token
    /// are never touched. Trade-off: a KEYLESS secret (an `AKIA…` or a PEM
    /// block dumped bare in a stack trace / URL, with no key beside it) is not
    /// caught in this mode. `email`/`phone` are gated independently by their
    /// own opt-in flags, NOT by this one.
    pub redact_value_shapes: bool,
}

impl RedactPolicy {
    /// The legacy "redact everything, keep nothing" posture that the
    /// back-compat [`redact`] helper uses (email/phone on, tokens redacted,
    /// value-shape patterns on).
    pub const fn all() -> Self {
        Self {
            redact_email: true,
            redact_phone: true,
            keep_tokens: false,
            redact_value_shapes: true,
        }
    }

    /// RF-FP (2026-07-09) — the default "key-first" posture: structural
    /// key-value redaction only; email/phone/value-shapes all off. Mirrors the
    /// data-plane default built from `ResponseFilterConfig`.
    pub const fn key_first() -> Self {
        Self {
            redact_email: false,
            redact_phone: false,
            keep_tokens: false,
            redact_value_shapes: false,
        }
    }
}

impl Default for RedactPolicy {
    fn default() -> Self {
        Self::all()
    }
}

/// Redact text by replacing all DLP matches under the "redact everything"
/// policy ([`RedactPolicy::all`]). Kept for internal callers / tests; the
/// response pipeline uses [`redact_with`] with an operator-tuned policy.
pub fn redact(text: &str) -> String {
    redact_with(text, &RedactPolicy::all())
}

/// RF-FP (2026-07-08) — policy-aware redaction. Fixed-shape patterns replace
/// the whole match with `[REDACTED]`; structural key-value patterns (RF-1)
/// scrub only the VALUE via `${pre}[REDACTED]`, skipping benign metadata
/// keys / bool-number-null values. The `policy` adds three FP-reduction
/// gates on top:
/// - `Pii::email` / `Pii::phone` run only when explicitly enabled (opt-in).
/// - the `Token` whole-match (`jwt`) is skipped when `keep_tokens` (auth path).
/// - structural matches whose key is token-class ([`key_is_token_class`]) are
///   kept when `keep_tokens`, so an auth response keeps its `access_token`
///   while a `db_password` / `client_secret` in the same body still redacts.
pub fn redact_with(text: &str, policy: &RedactPolicy) -> String {
    let mut result = text.to_string();
    for pat in DLP_PATTERNS.iter() {
        // Opt-in PII gates (independent of the value-shape gate below).
        if pat.name == "email" && !policy.redact_email {
            continue;
        }
        if pat.name == "phone" && !policy.redact_phone {
            continue;
        }
        // RF-FP (2026-07-09 QC — "full key-first") — value-shape secret /
        // financial patterns run only when explicitly enabled. Structural
        // key-value patterns (`structural: true`) always run: they are the
        // key-first core. `email`/`phone` are handled by their own gates
        // above, so they are exempt here.
        if !pat.structural
            && pat.name != "email"
            && pat.name != "phone"
            && !policy.redact_value_shapes
        {
            continue;
        }
        // Token whole-match (jwt) — kept intact on auth paths.
        if policy.keep_tokens && pat.class == PatternClass::Token {
            continue;
        }
        result = if pat.structural {
            pat.regex
                .replace_all(&result, |caps: &regex::Captures| {
                    let whole = caps.get(0).unwrap().as_str();
                    let pre = caps.name("pre").map_or("", |m| m.as_str());
                    // Benign metadata key (token_type, password_updated_at…) → keep.
                    if BENIGN_KEY_SUFFIX.is_match(pre) {
                        return whole.to_string();
                    }
                    // Auth path: keep token-class fields (access_token, …); the
                    // non-token secret keys in the same body still fall through.
                    if policy.keep_tokens && key_is_token_class(pre) {
                        return whole.to_string();
                    }
                    // Benign value (bool/number/null/already-redacted) → keep.
                    let value = whole[pre.len()..].trim().trim_matches('"').trim();
                    if BENIGN_VALUE.is_match(value) {
                        return whole.to_string();
                    }
                    let mut dst = String::new();
                    caps.expand(pat.replacement, &mut dst);
                    dst
                })
                .to_string()
        } else {
            // RF-FP (2026-07-08 QC) — honor the per-pattern `validator` on the
            // redaction path exactly like `scan` does. A bare `replace_all`
            // redacted every checksum-SHAPED false positive (IBAN lookalikes
            // that fail mod-97, non-Luhn 16-digit refs, invalid SSNs), which
            // fired the response filter on benign bodies — e.g. Amazon
            // request-IDs (`[A-Z]{2}\d{2}[A-Z0-9]{4,}`) echoed in a 404. When a
            // match fails its validator we return the original text unchanged.
            match pat.validator {
                Some(validator) => pat
                    .regex
                    .replace_all(&result, |caps: &regex::Captures| {
                        let whole = caps.get(0).unwrap().as_str();
                        let value = caps.get(1).map_or(whole, |m| m.as_str());
                        if validator(value) {
                            let mut dst = String::new();
                            caps.expand(pat.replacement, &mut dst);
                            dst
                        } else {
                            whole.to_string()
                        }
                    })
                    .to_string(),
                None => pat.regex.replace_all(&result, pat.replacement).to_string(),
            }
        };
    }
    result
}

/// Luhn check for credit card numbers.
fn luhn_check(cc: &str) -> bool {
    let digits: Vec<u32> = cc
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn ssn_validate(ssn: &str) -> bool {
    let parts: Vec<&str> = ssn.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area: u32 = parts[0].parse().unwrap_or(0);
    let group: u32 = parts[1].parse().unwrap_or(0);
    let serial: u32 = parts[2].parse().unwrap_or(0);
    area > 0 && area != 666 && area < 900 && group > 0 && serial > 0
}

fn iban_mod97(iban: &str) -> bool {
    if iban.len() < 5 {
        return false;
    }
    // Move first 4 chars to end.
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
    // Convert letters to numbers (A=10, B=11, etc.).
    let mut numeric = String::new();
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            numeric.push(ch);
        } else if ch.is_ascii_uppercase() {
            let n = (ch as u32) - ('A' as u32) + 10;
            numeric.push_str(&n.to_string());
        } else {
            return false;
        }
    }
    // Mod 97 check.
    let mut remainder = 0u64;
    for ch in numeric.chars() {
        remainder = (remainder * 10 + ch.to_digit(10).unwrap_or(0) as u64) % 97;
    }
    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    // Credit card tests.
    #[test]
    fn detect_visa() {
        let matches = scan("Card: 4111-1111-1111-1111");
        assert!(matches.iter().any(|m| m.pattern_name == "credit_card"));
    }

    #[test]
    fn detect_mastercard() {
        let matches = scan("Card: 5500 0000 0000 0004");
        assert!(matches.iter().any(|m| m.pattern_name == "credit_card"));
    }

    #[test]
    fn reject_invalid_luhn() {
        let matches = scan("Card: 4111-1111-1111-1112");
        assert!(!matches.iter().any(|m| m.pattern_name == "credit_card"));
    }

    #[test]
    fn mask_cc() {
        assert_eq!(mask_credit_card("4111-1111-1111-1111"), "****-****-****-1111");
        assert_eq!(mask_credit_card("4111111111111111"), "****-****-****-1111");
    }

    // SSN tests.
    #[test]
    fn detect_ssn() {
        let matches = scan("SSN: 123-45-6789");
        assert!(matches.iter().any(|m| m.pattern_name == "ssn"));
    }

    #[test]
    fn reject_invalid_ssn() {
        let matches = scan("SSN: 000-45-6789");
        assert!(!matches.iter().any(|m| m.pattern_name == "ssn"));
    }

    #[test]
    fn mask_ssn_test() {
        assert_eq!(mask_ssn("123-45-6789"), "***-**-6789");
    }

    // IBAN tests.
    #[test]
    fn detect_iban_gb() {
        let matches = scan("IBAN: GB29NWBK60161331926819");
        assert!(matches.iter().any(|m| m.pattern_name == "iban"));
    }

    #[test]
    fn detect_iban_de() {
        let matches = scan("IBAN: DE89370400440532013000");
        assert!(matches.iter().any(|m| m.pattern_name == "iban"));
    }

    // RF-FP (2026-07-08 QC) — the redaction path (`redact_with`) must honor the
    // per-pattern `validator` exactly like `scan` does. Pre-fix `redact_with`
    // ran a bare `replace_all` and skipped the validator, so any checksum-shaped
    // FALSE positive got redacted anyway. The canonical trigger: Amazon
    // request/session IDs (`[A-Z]{2}\d{2}[A-Z0-9]{4,}`) structurally match the
    // IBAN regex but fail mod-97 — they were redacted, firing the response
    // filter (X-WAF-Response-Filtered + `rule: response-filter`) on benign 404
    // telemetry bodies.

    #[test]
    fn redact_skips_iban_shaped_token_that_fails_mod97() {
        // Amazon request-ID shape — matches the iban regex, fails the checksum.
        let token = "VC299VJ9F97G82HEF28Q";
        assert!(!iban_mod97(token), "precondition: token must fail mod-97");
        let body = format!("id={token}&next={token}");
        let out = redact(&body);
        assert_eq!(out, body, "mod-97-invalid IBAN lookalike must NOT be redacted");
        assert!(!out.contains("[REDACTED]"), "no redaction expected: {out}");
    }

    #[test]
    fn redact_still_redacts_valid_iban() {
        let out = redact("account IBAN GB29NWBK60161331926819 here");
        assert!(out.contains("[REDACTED]"), "a checksum-valid IBAN must still redact: {out}");
        assert!(!out.contains("GB29NWBK60161331926819"));
    }

    #[test]
    fn redact_skips_non_luhn_card_shape() {
        // 16-digit card SHAPE that fails the Luhn check → not a real card.
        // Uses the production policy (phone opt-in OFF); the digit-dash shape
        // otherwise overlaps the (validator-less) phone pattern.
        let policy = RedactPolicy { redact_email: false, redact_phone: false, keep_tokens: false, redact_value_shapes: true };
        let out = redact_with("ref 4111-1111-1111-1112 end", &policy);
        assert_eq!(out, "ref 4111-1111-1111-1112 end", "non-Luhn card shape must not redact");
    }

    #[test]
    fn redact_skips_invalid_ssn_shape() {
        // 000 area is an invalid SSN → must not redact (phone opt-in OFF).
        let policy = RedactPolicy { redact_email: false, redact_phone: false, keep_tokens: false, redact_value_shapes: true };
        let out = redact_with("code 000-45-6789 end", &policy);
        assert_eq!(out, "code 000-45-6789 end", "invalid SSN shape must not redact");
    }

    /// End-to-end regression on the exact QC beacon body: the origin's verbose
    /// 404 echoes an Amazon telemetry URL whose request IDs are IBAN-shaped.
    /// Under the production policy (email/phone opt-in OFF) nothing in it is a
    /// real secret, so the response filter must leave it untouched.
    #[test]
    fn redact_leaves_amazon_404_beacon_untouched() {
        let body = "{\"error\":\"not_found\",\"tried\":\"/1/batch/1/OP/\
ATVPDKIKX0DER:134-1400937-8492661:VC299VJ9F97G82HEF28Q$uedata=s:/rd/uedata?\
id=VC299VJ9F97G82HEF28Q&sc0=adplacements:viewablelatency:\
cf81795d-ef39-406a-ad7e-6538fcad65f8&pti=B0CKBX52VG\"}";
        let policy = RedactPolicy::key_first();
        let out = redact_with(body, &policy);
        assert_eq!(out, body, "benign telemetry 404 must not trigger the response filter: {out}");
    }

    // Email tests.
    #[test]
    fn detect_email() {
        let matches = scan("Email: john@example.com");
        assert!(matches.iter().any(|m| m.pattern_name == "email"));
    }

    #[test]
    fn mask_email_test() {
        assert_eq!(mask_email("john@example.com"), "j***@example.com");
        assert_eq!(mask_email("a@b.com"), "*@b.com");
    }

    // API key tests.
    #[test]
    fn detect_aws_key() {
        let matches = scan("Key: AKIAIOSFODNN7EXAMPLE");
        assert!(matches.iter().any(|m| m.pattern_name == "aws_key"));
    }

    #[test]
    fn detect_github_token() {
        let matches = scan("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert!(matches.iter().any(|m| m.pattern_name == "github_token"));
    }

    #[test]
    fn detect_stripe_key() {
        let matches = scan("Key: sk_live_ABCDEFGHIJKLMNOPQRSTUVWx");
        assert!(matches.iter().any(|m| m.pattern_name == "stripe_key"));
    }

    #[test]
    fn detect_slack_token() {
        let matches = scan("Token: xoxb-123456789012-ABCDEFGHIJKL");
        assert!(matches.iter().any(|m| m.pattern_name == "slack_token"));
    }

    #[test]
    fn detect_pem_key() {
        let matches = scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----");
        assert!(matches.iter().any(|m| m.pattern_name == "pem_private_key"));
    }

    #[test]
    fn detect_jwt() {
        let matches = scan("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456");
        assert!(matches.iter().any(|m| m.pattern_name == "jwt"));
    }

    // Redact test.
    #[test]
    fn redact_credit_card() {
        let text = "Card: 4111-1111-1111-1111 was charged";
        let redacted = redact(text);
        assert!(!redacted.contains("4111"));
        assert!(redacted.contains("[REDACTED]"));
    }

    // 2026-05-25 — env-file / config-dump secret leak (the `.env` leak case:
    // upstream served `DB_PASSWORD=…` and the WAF must not pass the value
    // through). redact() runs on response bodies via Pipeline::on_body_frame.
    #[test]
    fn detect_and_redact_env_secret() {
        let leak = "DB_PASSWORD=sup3r-s3cret-value\nAPI_KEY=AKIA-not-real-1234\n";
        let matches = scan(leak);
        assert!(
            matches.iter().any(|m| m.pattern_name == "env_secret"),
            "env-style secret assignment must be detected"
        );
        // scan() captures the KEY only, never the secret value.
        assert!(
            matches.iter().all(|m| !m.matched_value.contains("sup3r-s3cret-value")),
            "scan must not echo the secret value"
        );
        let redacted = redact(leak);
        assert!(!redacted.contains("sup3r-s3cret-value"), "DB_PASSWORD value must be redacted");
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn env_secret_no_false_positive_on_js_or_nonstring() {
        // RF-1 (2026-07-06) — the JSON structural rung redacts STRING
        // secret-field values (contract §5.2), but must leave benign shapes
        // alone: non-string values (bool/number → not a credential) and JS
        // assignments (key not in `KEY=VALUE` line form).
        let non_string = r#"{"has_password": true, "password_strength": 3}"#;
        assert_eq!(
            redact(non_string), non_string,
            "non-string secret-key values must pass through (no opening quote)",
        );
        // `var token = …` — key not at line start in KEY=VALUE form — must NOT match.
        let js = "var token = computeToken();";
        assert!(scan(js).iter().all(|m| m.pattern_name != "env_secret"));
        assert_eq!(redact(js), js);
    }

    // ===== RF-1..3 (2026-07-06 S-Tester `SUSPICIOUS_200`) — response leak
    // redaction. Upstream served 200s leaking real credentials with BTC
    // markers (`__V22_ADMIN_ACL__`, `__V23_CONFIG_LEAK__`). `redact()` runs
    // on every 200 body via `Pipeline::on_body_frame`. =====

    #[test]
    fn rf1_env_assignment_secret_redacted() {
        for (body, secret) in [
            ("admin_secret=__V22_ADMIN_ACL__", "__V22_ADMIN_ACL__"),
            ("secret_key=sk_live_wafhack2026_prod_key", "wafhack2026"),
            ("DB_PASSWORD=sup3r-s3cret-value", "sup3r-s3cret-value"),
        ] {
            let out = redact(body);
            assert!(!out.contains(secret), "env secret leaked: {out}");
            assert!(out.contains("[REDACTED]"), "no redaction marker: {out}");
        }
    }

    #[test]
    fn rf1_json_secret_field_redacted_structure_preserved() {
        let body = r#"{"db_password":"__V23_CONFIG_LEAK__","user":"alice"}"#;
        let out = redact(body);
        assert!(!out.contains("__V23_CONFIG_LEAK__"), "json secret leaked: {out}");
        assert!(out.contains(r#""db_password":"[REDACTED]""#), "key+structure preserved: {out}");
        assert!(out.contains(r#""user":"alice""#), "benign field untouched: {out}");
    }

    #[test]
    fn rf1_yaml_secret_field_redacted() {
        let body = "db_password: __V23_CONFIG_LEAK__\nport: 5432\n";
        let out = redact(body);
        assert!(!out.contains("__V23_CONFIG_LEAK__"), "yaml secret leaked: {out}");
        assert!(out.contains("port: 5432"), "benign yaml key untouched: {out}");
    }

    #[test]
    fn rf1_htaccess_setenv_redacted() {
        let body = "# SetEnv DB_PASS wafhack2026_staging";
        let out = redact(body);
        assert!(!out.contains("wafhack2026_staging"), "htaccess secret leaked: {out}");
    }

    #[test]
    fn rf2_stripe_key_with_underscores_redacted() {
        // The pre-fix stripe pattern (`[A-Za-z0-9]{24,}`) broke on underscores.
        let out = redact("secret_key=sk_live_wafhack2026_prod_key");
        assert!(!out.contains("sk_live_wafhack2026_prod_key"), "stripe-ish key leaked: {out}");
    }

    #[test]
    fn rf2_bcrypt_hash_redacted() {
        let body = r#"{"user":"admin","hash":"$2b$12$LJ3m4ksTUVabcdefghij.klmnopqrstuvwxyz0123456789AB"}"#;
        let out = redact(body);
        assert!(!out.contains("$2b$12$"), "bcrypt hash leaked: {out}");
    }

    #[test]
    fn rf2_ssh_public_key_redacted() {
        let body = "ssh_keys=[ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij admin@novabet]";
        let out = redact(body);
        assert!(!out.contains("AAAAC3NzaC1lZDI1NTE5"), "ssh key material leaked: {out}");
    }

    #[test]
    fn rf2_openssh_private_key_redacted() {
        let out = redact("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...\n");
        assert!(out.contains("[REDACTED]"), "openssh private key must redact: {out}");
    }

    // FP guards — genuine benign data must survive.
    #[test]
    fn rf1_benign_fields_not_redacted() {
        let body = r#"{"username":"alice","balance":140526,"token_count":5,"status":"active"}"#;
        assert_eq!(redact(body), body, "benign business fields must pass through: {body}");
    }

    #[test]
    fn rf1_oauth_response_preserves_metadata_redacts_tokens() {
        // Real OAuth token response: access_token/refresh_token MUST redact,
        // but token_type/expires_in/scope must survive (metadata, not secrets).
        let body = r#"{"access_token":"eyJreal.secret.value","token_type":"Bearer","expires_in":3600,"refresh_token":"rt_abcdefghijklmnop","scope":"read write"}"#;
        let out = redact(body);
        assert!(!out.contains("eyJreal.secret.value"), "access_token must redact: {out}");
        assert!(!out.contains("rt_abcdefghijklmnop"), "refresh_token must redact: {out}");
        assert!(out.contains(r#""token_type":"Bearer""#), "token_type is metadata, keep: {out}");
        assert!(out.contains(r#""expires_in":3600"#), "expires_in must survive: {out}");
        assert!(out.contains(r#""scope":"read write""#), "scope must survive: {out}");
    }

    #[test]
    fn rf1_password_metadata_fields_not_redacted() {
        // Profile/security fields ABOUT a credential are not the credential.
        let body = r#"{"password_updated_at":"2026-01-01T00:00:00Z","has_password":true,"password_strength":"strong","secret_question_enabled":true}"#;
        assert_eq!(redact(body), body, "credential-metadata fields must survive: {body}");
    }

    // Clean text.
    #[test]
    fn clean_text_no_matches() {
        let matches = scan("Hello world, nothing sensitive here.");
        assert!(matches.is_empty());
    }

    #[test]
    fn luhn_valid() {
        assert!(luhn_check("4111111111111111"));
        assert!(luhn_check("5500000000000004"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234"));
    }

    #[test]
    fn iban_valid() {
        assert!(iban_mod97("GB29NWBK60161331926819"));
        assert!(iban_mod97("DE89370400440532013000"));
    }

    #[test]
    fn iban_invalid() {
        assert!(!iban_mod97("GB00NWBK60161331926819"));
        assert!(!iban_mod97("XX"));
    }

    // ===== RF-FP (2026-07-08 QC) — policy-aware redaction for FP reduction.
    // On token-issuing endpoints (auth paths) the response legitimately
    // carries tokens; `keep_tokens` skips the token-class patterns (jwt +
    // structural access_token/refresh_token/token) WITHOUT relaxing the
    // non-token secret / financial rungs. email + phone are opt-in. =====

    #[test]
    fn auth_policy_keeps_tokens_but_redacts_other_secrets_in_same_body() {
        let body = r#"{"access_token":"eyJreal.secret.value","refresh_token":"rt_abcdefghijklmnop","db_password":"sup3rs3cret","aws":"AKIAIOSFODNN7EXAMPLE"}"#;
        let policy = RedactPolicy { redact_email: false, redact_phone: false, keep_tokens: true, redact_value_shapes: true };
        let out = redact_with(body, &policy);
        // Token fields survive on an auth endpoint (the intended payload).
        assert!(out.contains("eyJreal.secret.value"), "access_token must survive on auth path: {out}");
        assert!(out.contains("rt_abcdefghijklmnop"), "refresh_token must survive on auth path: {out}");
        // Non-token secrets are STILL redacted even on an auth path.
        assert!(!out.contains("sup3rs3cret"), "db_password must still redact on auth path: {out}");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "aws key must still redact on auth path: {out}");
    }

    #[test]
    fn auth_policy_keeps_bare_jwt_only_when_keep_tokens() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456";
        let body = format!("token issued: {jwt}");
        let keep = RedactPolicy { redact_email: false, redact_phone: false, keep_tokens: true, redact_value_shapes: true };
        assert!(redact_with(&body, &keep).contains(jwt), "bare JWT must survive on auth path");
        let no_keep = RedactPolicy { redact_email: false, redact_phone: false, keep_tokens: false, redact_value_shapes: true };
        assert!(!redact_with(&body, &no_keep).contains(jwt), "bare JWT redacted off auth path");
    }

    #[test]
    fn email_phone_opt_in_off_by_default_policy() {
        let body = "contact alice@example.com or +1 415 555 1234";
        let off = RedactPolicy { redact_email: false, redact_phone: false, keep_tokens: false, redact_value_shapes: false };
        assert_eq!(redact_with(body, &off), body, "email/phone must pass through when off");
        // value-shapes OFF here proves email/phone are gated INDEPENDENTLY of it.
        let on = RedactPolicy { redact_email: true, redact_phone: true, keep_tokens: false, redact_value_shapes: false };
        let out = redact_with(body, &on);
        assert!(!out.contains("alice@example.com"), "email redacts when enabled: {out}");
        assert!(!out.contains("415 555 1234"), "phone redacts when enabled: {out}");
    }

    #[test]
    fn key_is_token_class_boundaries() {
        assert!(key_is_token_class(r#""access_token":""#));
        assert!(key_is_token_class(r#""refresh_token":""#));
        assert!(key_is_token_class(r#""csrf_token":""#));
        assert!(key_is_token_class("token="));
        // Non-token secret keys are NOT token-class → they still redact.
        assert!(!key_is_token_class(r#""client_secret":""#), "client_secret is not token-class");
        assert!(!key_is_token_class(r#""db_password":""#));
        assert!(!key_is_token_class(r#""api_key":""#));
        // Mixed key with a non-token stem is treated as a secret (safe default).
        assert!(!key_is_token_class(r#""secret_token":""#), "secret+token → redact (safe)");
    }

    #[test]
    fn legacy_redact_unchanged_all_on_keep_nothing() {
        // `redact()` == the all-on / keep-nothing policy used OFF the auth path:
        // tokens AND email still redact, so every pre-existing test stays green.
        let body = r#"{"access_token":"eyJreal.secret.value"}"#;
        assert!(!redact(body).contains("eyJreal.secret.value"), "off-auth token still redacts");
        assert!(redact("mail alice@example.com").contains("[REDACTED]"), "email still redacts by default helper");
    }
}
