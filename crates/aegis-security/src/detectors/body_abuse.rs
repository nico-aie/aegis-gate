use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

/// Body abuse detector: oversize + deep nesting.
pub struct BodyAbuseDetector {
    /// Max body size in bytes before flagging.
    pub max_body_bytes: u64,
    /// Max JSON nesting depth.
    pub max_nesting_depth: usize,
}

impl Default for BodyAbuseDetector {
    fn default() -> Self {
        Self {
            max_body_bytes: 10 * 1024 * 1024, // 10 MiB
            max_nesting_depth: 20,
        }
    }
}

impl Detector for BodyAbuseDetector {
    fn id(&self) -> &'static str {
        "body_abuse"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // 1. Check Content-Length for oversize.
        if let Some(cl) = req.body.content_length() {
            if cl > self.max_body_bytes {
                signals.push(Signal {
                    score: 30,
                    tag: "body_oversize".into(),
                    field: "body".into(),
                });
            }
        }

        // 2. Check JSON nesting depth (peek first 8KiB).
        let peek = req.body.peek(8192);
        if !peek.is_empty() {
            if let Ok(text) = std::str::from_utf8(peek) {
                let trimmed = text.trim_start();
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    let depth = json_nesting_depth(trimmed);
                    if depth > self.max_nesting_depth {
                        signals.push(Signal {
                            score: 35,
                            tag: "body_deep_nesting".into(),
                            field: "body".into(),
                        });
                    }
                }
            }
        }

        signals
    }
}

/// Count max nesting depth of JSON-like text.
fn json_nesting_depth(text: &str) -> usize {
    let mut max_depth = 0usize;
    let mut current = 0usize;
    let mut in_string = false;
    let mut escape = false;

    for ch in text.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match ch {
            '{' | '[' => {
                current += 1;
                if current > max_depth {
                    max_depth = current;
                }
            }
            '}' | ']' => {
                current = current.saturating_sub(1);
            }
            _ => {}
        }
    }
    max_depth
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn make_view_with_body(body: &[u8], content_length: Option<u64>) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::POST,
            "/api/data".parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::new(body.to_vec(), content_length, false),
        )
    }

    fn view<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method: m, uri: u, version: http::Version::HTTP_11,
            headers: h, peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None, body: b,
        }
    }

    #[test]
    fn normal_body_no_signal() {
        let body = br#"{"name": "test", "value": 42}"#;
        let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
        let req = view(&m, &u, &h, &b);
        let d = BodyAbuseDetector::default();
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn oversize_body_flagged() {
        let d = BodyAbuseDetector {
            max_body_bytes: 100,
            max_nesting_depth: 20,
        };
        let (m, u, h, b) = make_view_with_body(b"small peek", Some(5000));
        let req = view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert!(signals.iter().any(|s| s.tag == "body_oversize"));
    }

    #[test]
    fn deep_nesting_flagged() {
        let d = BodyAbuseDetector {
            max_body_bytes: 10_000_000,
            max_nesting_depth: 5,
        };
        let body = r#"{"a":{"b":{"c":{"d":{"e":{"f":"deep"}}}}}}"#;
        let (m, u, h, b) = make_view_with_body(body.as_bytes(), Some(body.len() as u64));
        let req = view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert!(signals.iter().any(|s| s.tag == "body_deep_nesting"));
    }

    #[test]
    fn normal_nesting_ok() {
        let d = BodyAbuseDetector::default();
        let body = r#"{"a": [1, 2, {"b": true}]}"#;
        let (m, u, h, b) = make_view_with_body(body.as_bytes(), Some(body.len() as u64));
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn empty_body_no_signal() {
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) = make_view_with_body(b"", Some(0));
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn non_json_body_no_nesting() {
        let d = BodyAbuseDetector {
            max_body_bytes: 10_000_000,
            max_nesting_depth: 2,
        };
        let body = b"Hello this is plain text not json at all";
        let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn json_nesting_depth_simple() {
        assert_eq!(json_nesting_depth(r#"{"a": 1}"#), 1);
    }

    #[test]
    fn json_nesting_depth_nested() {
        assert_eq!(json_nesting_depth(r#"{"a": {"b": {"c": 1}}}"#), 3);
    }

    #[test]
    fn json_nesting_depth_array() {
        assert_eq!(json_nesting_depth(r#"[[[1]]]"#), 3);
    }

    #[test]
    fn json_nesting_depth_string_braces() {
        // Braces inside strings should be ignored.
        assert_eq!(json_nesting_depth(r#"{"a": "{{{}"}"#), 1);
    }
}
