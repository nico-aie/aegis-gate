use aegis_core::config::QuotaConfig;
use hyper::StatusCode;

/// Reason a quota was breached, naming the specific limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaViolation {
    /// Request body exceeds `client_max_body_size` → 413.
    BodyTooLarge { limit: u64, actual: u64 },
    /// Total header size exceeds `max_header_size` → 431.
    HeadersTooLarge { limit: usize, actual: usize },
    /// URI length exceeds `max_uri_length` → 414.
    UriTooLong { limit: usize, actual: usize },
}

impl QuotaViolation {
    /// Map the violation to the appropriate HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            QuotaViolation::BodyTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,       // 413
            QuotaViolation::HeadersTooLarge { .. } => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, // 431
            QuotaViolation::UriTooLong { .. } => StatusCode::URI_TOO_LONG,              // 414
        }
    }

    /// Human-readable message for audit events.
    pub fn audit_message(&self) -> String {
        match self {
            QuotaViolation::BodyTooLarge { limit, actual } => {
                format!("body too large: {actual} bytes exceeds limit of {limit}")
            }
            QuotaViolation::HeadersTooLarge { limit, actual } => {
                format!("headers too large: {actual} bytes exceeds limit of {limit}")
            }
            QuotaViolation::UriTooLong { limit, actual } => {
                format!("URI too long: {actual} chars exceeds limit of {limit}")
            }
        }
    }
}

/// Check a request against the quota config.  Returns the first violation found.
pub fn check_request_quota<B>(
    req: &hyper::Request<B>,
    quota: &QuotaConfig,
) -> Option<QuotaViolation> {
    // 1. URI length.
    let uri_len = req.uri().to_string().len();
    if uri_len > quota.max_uri_length {
        return Some(QuotaViolation::UriTooLong {
            limit: quota.max_uri_length,
            actual: uri_len,
        });
    }

    // 2. Total header size (sum of name + value bytes for all headers).
    let header_size: usize = req
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len())
        .sum();
    if header_size > quota.max_header_size {
        return Some(QuotaViolation::HeadersTooLarge {
            limit: quota.max_header_size,
            actual: header_size,
        });
    }

    // 3. Body size — check Content-Length header (streaming check is deferred
    //    to the proxy handler since the body isn't fully available here).
    if let Some(cl) = req.headers().get(hyper::header::CONTENT_LENGTH) {
        if let Ok(len) = cl.to_str().unwrap_or("0").parse::<u64>() {
            if len > quota.client_max_body_size {
                return Some(QuotaViolation::BodyTooLarge {
                    limit: quota.client_max_body_size,
                    actual: len,
                });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;

    fn default_quota() -> QuotaConfig {
        QuotaConfig::default()
    }

    #[test]
    fn passes_valid_request() {
        let req = hyper::Request::builder()
            .uri("/api/test")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(check_request_quota(&req, &default_quota()).is_none());
    }

    #[test]
    fn rejects_uri_too_long() {
        let mut quota = default_quota();
        quota.max_uri_length = 10;

        let req = hyper::Request::builder()
            .uri("/this/is/a/very/long/uri/that/exceeds/the/limit")
            .body(Full::<Bytes>::default())
            .unwrap();
        let v = check_request_quota(&req, &quota).unwrap();
        assert_eq!(v.status_code(), StatusCode::URI_TOO_LONG);
        assert!(v.audit_message().contains("URI too long"));
    }

    #[test]
    fn rejects_headers_too_large() {
        let mut quota = default_quota();
        quota.max_header_size = 20;

        let req = hyper::Request::builder()
            .header("x-big-header", "a]".repeat(50))
            .body(Full::<Bytes>::default())
            .unwrap();
        let v = check_request_quota(&req, &quota).unwrap();
        assert_eq!(v.status_code(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }

    #[test]
    fn rejects_body_too_large() {
        let mut quota = default_quota();
        quota.client_max_body_size = 1024;

        let req = hyper::Request::builder()
            .header("content-length", "999999")
            .body(Full::<Bytes>::default())
            .unwrap();
        let v = check_request_quota(&req, &quota).unwrap();
        assert_eq!(v.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(v.audit_message().contains("body too large"));
    }

    #[test]
    fn uri_check_has_priority_over_headers() {
        let mut quota = default_quota();
        quota.max_uri_length = 5;
        quota.max_header_size = 5;

        let req = hyper::Request::builder()
            .uri("/very/long/uri")
            .header("x-big", "value")
            .body(Full::<Bytes>::default())
            .unwrap();
        // URI checked first.
        let v = check_request_quota(&req, &quota).unwrap();
        assert_eq!(v.status_code(), StatusCode::URI_TOO_LONG);
    }

    #[test]
    fn body_within_limit_passes() {
        let mut quota = default_quota();
        quota.client_max_body_size = 1024;

        let req = hyper::Request::builder()
            .header("content-length", "512")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(check_request_quota(&req, &quota).is_none());
    }
}
