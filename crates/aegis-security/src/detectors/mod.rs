pub mod body_abuse;
pub mod header_injection;
pub mod mask;
pub mod path_traversal;
pub mod recon;
pub mod sqli;
pub mod ssrf;
pub mod xss;

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

/// Create the default set of detectors.
pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(sqli::SqliDetector),
        Box::new(xss::XssDetector),
        Box::new(path_traversal::PathTraversalDetector),
        Box::new(ssrf::SsrfDetector),
        Box::new(header_injection::HeaderInjectionDetector),
        Box::new(body_abuse::BodyAbuseDetector::default()),
        Box::new(recon::ReconDetector),
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
        assert_eq!(d.len(), 7);
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
}
