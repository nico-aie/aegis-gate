use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use hyper::{Method, Request, Response, StatusCode};

/// Per-route CORS configuration.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins. `["*"]` means any origin.
    pub allowed_origins: Vec<String>,
    /// Allowed methods.
    pub allowed_methods: Vec<String>,
    /// Allowed request headers.
    pub allowed_headers: Vec<String>,
    /// Whether to allow credentials.
    pub allow_credentials: bool,
    /// Max age for preflight cache (seconds).
    pub max_age: u64,
    /// If true, preflight is forwarded to upstream instead of answered locally.
    pub passthrough: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".into()],
            allowed_methods: vec![
                "GET".into(),
                "POST".into(),
                "PUT".into(),
                "DELETE".into(),
                "OPTIONS".into(),
            ],
            allowed_headers: vec!["*".into()],
            allow_credentials: false,
            max_age: 86400,
            passthrough: false,
        }
    }
}

/// Returns `true` if this is an OPTIONS preflight request.
pub fn is_preflight<B>(req: &Request<B>) -> bool {
    req.method() == Method::OPTIONS
        && req.headers().contains_key(ORIGIN)
        && req.headers().contains_key(ACCESS_CONTROL_REQUEST_METHOD)
}

/// Handle a CORS preflight request directly, returning a 204 response.
pub fn handle_preflight<B>(req: &Request<B>, cfg: &CorsConfig) -> Response<Full<Bytes>> {
    let origin = req
        .headers()
        .get(ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let mut resp = Response::builder().status(StatusCode::NO_CONTENT);

    // Origin
    let allow_origin = if cfg.allowed_origins.contains(&"*".to_string()) {
        if cfg.allow_credentials {
            origin.to_string()
        } else {
            "*".to_string()
        }
    } else if cfg.allowed_origins.iter().any(|o| o == origin) {
        origin.to_string()
    } else {
        String::new()
    };

    if !allow_origin.is_empty() {
        resp = resp.header(ACCESS_CONTROL_ALLOW_ORIGIN, &allow_origin);
    }

    // Methods
    resp = resp.header(
        ACCESS_CONTROL_ALLOW_METHODS,
        cfg.allowed_methods.join(", "),
    );

    // Headers — echo back the requested headers or use config.
    let allow_headers = if cfg.allowed_headers.contains(&"*".to_string()) {
        req.headers()
            .get(ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("*")
            .to_string()
    } else {
        cfg.allowed_headers.join(", ")
    };
    resp = resp.header(ACCESS_CONTROL_ALLOW_HEADERS, allow_headers);

    // Credentials
    if cfg.allow_credentials {
        resp = resp.header(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
    }

    // Max-Age
    resp = resp.header(ACCESS_CONTROL_MAX_AGE, cfg.max_age.to_string());

    // Vary
    resp = resp.header(VARY, "Origin");

    resp.body(Full::new(Bytes::new())).unwrap()
}

/// Apply CORS headers to a normal (non-preflight) response.
pub fn apply_cors_headers(
    resp: &mut Response<Full<Bytes>>,
    origin: Option<&str>,
    cfg: &CorsConfig,
) {
    let origin = origin.unwrap_or("");
    if origin.is_empty() {
        return;
    }

    let allow_origin = if cfg.allowed_origins.contains(&"*".to_string()) {
        if cfg.allow_credentials {
            origin.to_string()
        } else {
            "*".to_string()
        }
    } else if cfg.allowed_origins.iter().any(|o| o == origin) {
        origin.to_string()
    } else {
        return;
    };

    let headers = resp.headers_mut();
    headers.insert(
        ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_str(&allow_origin).unwrap(),
    );

    if cfg.allow_credentials {
        headers.insert(
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    headers.insert(VARY, HeaderValue::from_static("Origin"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_preflight(origin: &str, method: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(Method::OPTIONS)
            .header(ORIGIN, origin)
            .header(ACCESS_CONTROL_REQUEST_METHOD, method)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    #[test]
    fn detects_preflight() {
        let req = build_preflight("https://example.com", "POST");
        assert!(is_preflight(&req));
    }

    #[test]
    fn non_options_not_preflight() {
        let req = Request::builder()
            .method(Method::GET)
            .header(ORIGIN, "https://example.com")
            .body(Full::<Bytes>::new(Bytes::new()))
            .unwrap();
        assert!(!is_preflight(&req));
    }

    #[test]
    fn options_without_origin_not_preflight() {
        let req = Request::builder()
            .method(Method::OPTIONS)
            .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Full::<Bytes>::new(Bytes::new()))
            .unwrap();
        assert!(!is_preflight(&req));
    }

    #[test]
    fn preflight_wildcard_origin() {
        let req = build_preflight("https://app.io", "POST");
        let cfg = CorsConfig::default();
        let resp = handle_preflight(&req, &cfg);
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "*"
        );
    }

    #[test]
    fn preflight_specific_origin() {
        let req = build_preflight("https://app.io", "PUT");
        let cfg = CorsConfig {
            allowed_origins: vec!["https://app.io".into()],
            ..Default::default()
        };
        let resp = handle_preflight(&req, &cfg);
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.io"
        );
    }

    #[test]
    fn preflight_rejected_origin() {
        let req = build_preflight("https://evil.io", "POST");
        let cfg = CorsConfig {
            allowed_origins: vec!["https://app.io".into()],
            ..Default::default()
        };
        let resp = handle_preflight(&req, &cfg);
        assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }

    #[test]
    fn preflight_with_credentials() {
        let req = build_preflight("https://app.io", "POST");
        let cfg = CorsConfig {
            allow_credentials: true,
            ..Default::default()
        };
        let resp = handle_preflight(&req, &cfg);
        // With credentials, wildcard is replaced by the actual origin.
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.io"
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );
    }

    #[test]
    fn preflight_max_age() {
        let req = build_preflight("https://app.io", "GET");
        let cfg = CorsConfig {
            max_age: 3600,
            ..Default::default()
        };
        let resp = handle_preflight(&req, &cfg);
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_MAX_AGE).unwrap(),
            "3600"
        );
    }

    #[test]
    fn preflight_echoes_requested_headers() {
        let req = Request::builder()
            .method(Method::OPTIONS)
            .header(ORIGIN, "https://app.io")
            .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(ACCESS_CONTROL_REQUEST_HEADERS, "X-Custom, Authorization")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let cfg = CorsConfig::default();
        let resp = handle_preflight(&req, &cfg);
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
            "X-Custom, Authorization"
        );
    }

    #[test]
    fn apply_cors_to_normal_response() {
        let cfg = CorsConfig::default();
        let mut resp = Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("ok")))
            .unwrap();
        apply_cors_headers(&mut resp, Some("https://app.io"), &cfg);
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "*"
        );
        assert_eq!(resp.headers().get(VARY).unwrap(), "Origin");
    }

    #[test]
    fn apply_cors_no_origin_header_noop() {
        let cfg = CorsConfig::default();
        let mut resp = Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("ok")))
            .unwrap();
        apply_cors_headers(&mut resp, None, &cfg);
        assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }
}
