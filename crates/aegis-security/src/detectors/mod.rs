pub mod body_abuse;
pub mod brute_force;
pub mod command_injection;
pub mod header_injection;
pub mod mask;
pub mod nosql_injection;
pub mod open_redirect;
pub mod path_traversal;
pub mod recon;
pub mod scores;
pub mod sqli;
pub mod ssrf;
pub mod template_injection;
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
    for d in detectors {
        if !mask.is_enabled_id(d.id()) {
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
    ]
}

#[cfg(test)]
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

    #[test]
    fn default_detectors_count() {
        let d = default_detectors();
        // sqli + xss + path_traversal + ssrf + header_injection
        // + body_abuse + recon + brute_force + command_injection
        // + template_injection + nosql_injection + open_redirect.
        assert_eq!(d.len(), 12);
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
