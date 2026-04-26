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

    // ---- Positive: oversize body (≥15 cases) ----
    macro_rules! oversize {
        ($name:ident, $size:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector { max_body_bytes: 100, max_nesting_depth: 20 };
                let (m, u, h, b) = make_view_with_body(b"x", Some($size));
                let req = view(&m, &u, &h, &b);
                assert!(d.inspect(&req).iter().any(|s| s.tag == "body_oversize"));
            }
        };
    }
    oversize!(oversize_200, 200);
    oversize!(oversize_1k, 1024);
    oversize!(oversize_5k, 5000);
    oversize!(oversize_10k, 10_000);
    oversize!(oversize_50k, 50_000);
    oversize!(oversize_100k, 100_000);
    oversize!(oversize_1m, 1_000_000);
    oversize!(oversize_5m, 5_000_000);
    oversize!(oversize_10m, 10_000_000);
    oversize!(oversize_50m, 50_000_000);
    oversize!(oversize_100m, 100_000_000);
    oversize!(oversize_500m, 500_000_000);
    oversize!(oversize_1g, 1_000_000_000);
    oversize!(oversize_101, 101);
    oversize!(oversize_999, 999);

    // ---- Positive: deep nesting (≥15 cases) ----
    macro_rules! deep {
        ($name:ident, $depth:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector { max_body_bytes: 10_000_000, max_nesting_depth: 5 };
                let open: String = "{\"a\":".repeat($depth);
                let close: String = "}".repeat($depth);
                let body = format!("{open}1{close}");
                let (m, u, h, b) = make_view_with_body(body.as_bytes(), Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                assert!(d.inspect(&req).iter().any(|s| s.tag == "body_deep_nesting"));
            }
        };
    }
    deep!(deep_6, 6);
    deep!(deep_7, 7);
    deep!(deep_8, 8);
    deep!(deep_10, 10);
    deep!(deep_12, 12);
    deep!(deep_15, 15);
    deep!(deep_20, 20);
    deep!(deep_25, 25);
    deep!(deep_30, 30);
    deep!(deep_50, 50);
    deep!(deep_100, 100);
    deep!(deep_200, 200);
    deep!(deep_9, 9);
    deep!(deep_11, 11);
    deep!(deep_13, 13);

    // ---- Negative: normal bodies (≥30 cases) ----
    macro_rules! normal_body {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let body = $body.as_bytes();
                let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                assert!(d.inspect(&req).is_empty());
            }
        };
    }
    normal_body!(normal_simple_obj, r#"{"key":"value"}"#);
    normal_body!(normal_array, r#"[1,2,3,4,5]"#);
    normal_body!(normal_nested_2, r#"{"a":{"b":1}}"#);
    normal_body!(normal_nested_3, r#"{"a":{"b":{"c":1}}}"#);
    normal_body!(normal_array_of_obj, r#"[{"a":1},{"b":2}]"#);
    normal_body!(normal_string_val, r#"{"name":"John Doe"}"#);
    normal_body!(normal_bool_val, r#"{"active":true}"#);
    normal_body!(normal_null_val, r#"{"data":null}"#);
    normal_body!(normal_number_val, r#"{"count":42}"#);
    normal_body!(normal_float_val, r#"{"price":9.99}"#);
    normal_body!(normal_empty_obj, r#"{}"#);
    normal_body!(normal_empty_arr, r#"[]"#);
    normal_body!(normal_text, "Hello, this is plain text");
    normal_body!(normal_xml, "<root><item>value</item></root>");
    normal_body!(normal_form, "name=John&email=john%40example.com");
    normal_body!(normal_csv, "name,age\nAlice,30\nBob,25");
    normal_body!(normal_html, "<html><body><p>Hello</p></body></html>");
    normal_body!(normal_multiline, "line1\nline2\nline3");
    normal_body!(normal_unicode, r#"{"msg":"héllo wörld"}"#);
    normal_body!(normal_escaped_quotes, r#"{"val":"he said \"hi\""}"#);
    normal_body!(normal_large_array, r#"[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]"#);
    normal_body!(normal_mixed_types, r#"{"s":"a","n":1,"b":true,"x":null}"#);
    normal_body!(normal_nested_arr, r#"{"data":[[1,2],[3,4]]}"#);
    normal_body!(normal_long_str, r#"{"text":"abcdefghijklmnopqrstuvwxyz0123456789"}"#);
    normal_body!(normal_api_resp, r#"{"status":"ok","code":200}"#);
    normal_body!(normal_list_resp, r#"{"items":[{"id":1},{"id":2}],"total":2}"#);
    normal_body!(normal_empty_string, r#"{"val":""}"#);
    normal_body!(normal_whitespace_json, "  { \"a\" : 1 } ");
    normal_body!(normal_binary_like, "some random bytes 0xFF 0x00");
    normal_body!(normal_single_val, "42");
}
