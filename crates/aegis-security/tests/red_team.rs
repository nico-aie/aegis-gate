/// Red-team integration test suite.
///
/// Verifies that all OWASP detectors fully block known attack vectors:
/// SQLi, XSS, SSRF, path-traversal, header-injection, body-abuse, and recon.
use aegis_core::pipeline::{BodyPeek, RequestView};
use aegis_security::detectors::{
    body_abuse::BodyAbuseDetector,
    header_injection::HeaderInjectionDetector,
    path_traversal::PathTraversalDetector,
    recon::ReconDetector,
    sqli::SqliDetector,
    ssrf::SsrfDetector,
    xss::XssDetector,
    Detector,
};

fn make_view(
    method: http::Method,
    uri: &str,
    body: &[u8],
) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
    (
        method,
        uri.parse().unwrap(),
        http::HeaderMap::new(),
        BodyPeek::new(body.to_vec(), Some(body.len() as u64), false),
    )
}

fn req<'a>(
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

fn must_detect(detector: &dyn Detector, method: http::Method, uri: &str, body: &[u8]) {
    let (m, u, h, b) = make_view(method, uri, body);
    let r = req(&m, &u, &h, &b);
    let signals = detector.inspect(&r);
    assert!(
        !signals.is_empty(),
        "{} should detect attack in: {}",
        detector.id(),
        uri,
    );
}

// ---- SQLi red team ----
#[test]
fn redteam_sqli_union() {
    must_detect(&SqliDetector, http::Method::GET, "/api?id=1+UNION+SELECT+*+FROM+users", b"");
}

#[test]
fn redteam_sqli_or_bypass() {
    must_detect(&SqliDetector, http::Method::GET, "/login?user=admin%27+OR+%271%27%3D%271", b"");
}

#[test]
fn redteam_sqli_drop_table() {
    must_detect(&SqliDetector, http::Method::POST, "/api", b"id=1; DROP TABLE users;--");
}

#[test]
fn redteam_sqli_sleep() {
    must_detect(&SqliDetector, http::Method::GET, "/api?id=1+AND+SLEEP(5)", b"");
}

#[test]
fn redteam_sqli_benchmark() {
    must_detect(&SqliDetector, http::Method::GET, "/api?id=1+AND+BENCHMARK(1000,SHA1(%27test%27))", b"");
}

// ---- XSS red team ----
#[test]
fn redteam_xss_script() {
    must_detect(&XssDetector, http::Method::GET, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", b"");
}

#[test]
fn redteam_xss_onerror() {
    must_detect(&XssDetector, http::Method::GET, "/page?name=%3Cimg+onerror%3Dalert%281%29%3E", b"");
}

#[test]
fn redteam_xss_body() {
    must_detect(&XssDetector, http::Method::POST, "/api", b"<script>document.cookie</script>");
}

#[test]
fn redteam_xss_fromcharcode() {
    must_detect(&XssDetector, http::Method::GET, "/api?q=String.fromCharCode(88,83,83)", b"");
}

#[test]
fn redteam_xss_javascript_uri() {
    must_detect(&XssDetector, http::Method::GET, "/redir?url=javascript:alert(1)", b"");
}

// ---- SSRF red team ----
#[test]
fn redteam_ssrf_localhost() {
    must_detect(&SsrfDetector, http::Method::GET, "/proxy?url=http://127.0.0.1/admin", b"");
}

#[test]
fn redteam_ssrf_metadata() {
    must_detect(&SsrfDetector, http::Method::GET, "/fetch?url=http://169.254.169.254/latest/meta-data/", b"");
}

#[test]
fn redteam_ssrf_internal() {
    must_detect(&SsrfDetector, http::Method::GET, "/api?url=http://10.0.0.1:8080/internal", b"");
}

#[test]
fn redteam_ssrf_body() {
    must_detect(&SsrfDetector, http::Method::POST, "/api", b"url=http://192.168.1.1/admin");
}

#[test]
fn redteam_ssrf_file() {
    must_detect(&SsrfDetector, http::Method::GET, "/api?url=file:///etc/passwd", b"");
}

// ---- Path traversal red team ----
#[test]
fn redteam_traversal_dotdot() {
    must_detect(&PathTraversalDetector, http::Method::GET, "/files?path=../../etc/passwd", b"");
}

#[test]
fn redteam_traversal_encoded() {
    must_detect(&PathTraversalDetector, http::Method::GET, "/files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd", b"");
}

#[test]
fn redteam_traversal_etc_shadow() {
    must_detect(&PathTraversalDetector, http::Method::GET, "/api?file=../../../etc/shadow", b"");
}

#[test]
fn redteam_traversal_win() {
    must_detect(&PathTraversalDetector, http::Method::GET, "/api?p=..%5c..%5cwindows%5csystem32", b"");
}

#[test]
fn redteam_traversal_proc() {
    must_detect(&PathTraversalDetector, http::Method::GET, "/read?f=../../../../proc/self/environ", b"");
}

// ---- Header injection red team ----
#[test]
fn redteam_header_crlf() {
    must_detect(&HeaderInjectionDetector, http::Method::GET, "/?q=%0d%0aSet-Cookie:+evil=1", b"");
}

#[test]
fn redteam_header_location() {
    must_detect(&HeaderInjectionDetector, http::Method::GET, "/?q=%0D%0ALocation:+http://evil.com", b"");
}

#[test]
fn redteam_header_http_split() {
    must_detect(&HeaderInjectionDetector, http::Method::GET, "/?q=HTTP/1.1+200+OK", b"");
}

#[test]
fn redteam_header_xff() {
    must_detect(&HeaderInjectionDetector, http::Method::GET, "/?q=X-Forwarded-For:+127.0.0.1", b"");
}

#[test]
fn redteam_header_content_type() {
    must_detect(&HeaderInjectionDetector, http::Method::GET, "/?q=Content-Type:+text/html", b"");
}

// ---- Body abuse red team ----
#[test]
fn redteam_body_oversize() {
    let d = BodyAbuseDetector { max_body_bytes: 100, max_nesting_depth: 20 };
    let (m, u, h, b) = make_view(http::Method::POST, "/api", b"x");
    let bp = BodyPeek::new(b"x".to_vec(), Some(50_000_000), false);
    let r = RequestView {
        method: &m,
        uri: &u,
        version: http::Version::HTTP_11,
        headers: &h,
        peer: "127.0.0.1:1234".parse().unwrap(),
        tls: None,
        body: &bp,
    };
    assert!(!d.inspect(&r).is_empty());
}

#[test]
fn redteam_body_deep_json() {
    let d = BodyAbuseDetector { max_body_bytes: 10_000_000, max_nesting_depth: 5 };
    let open: String = "{\"a\":".repeat(10);
    let close: String = "}".repeat(10);
    let body_str = format!("{open}1{close}");
    let body = body_str.as_bytes();
    let (m, u, h, _) = make_view(http::Method::POST, "/api", body);
    let bp = BodyPeek::new(body.to_vec(), Some(body.len() as u64), false);
    let r = RequestView {
        method: &m,
        uri: &u,
        version: http::Version::HTTP_11,
        headers: &h,
        peer: "127.0.0.1:1234".parse().unwrap(),
        tls: None,
        body: &bp,
    };
    assert!(!d.inspect(&r).is_empty());
}

// ---- Recon red team ----
#[test]
fn redteam_recon_wp_login() {
    must_detect(&ReconDetector, http::Method::GET, "/wp-login.php", b"");
}

#[test]
fn redteam_recon_phpmyadmin() {
    must_detect(&ReconDetector, http::Method::GET, "/phpmyadmin/index.php", b"");
}

#[test]
fn redteam_recon_env() {
    must_detect(&ReconDetector, http::Method::GET, "/.env", b"");
}

#[test]
fn redteam_recon_git() {
    must_detect(&ReconDetector, http::Method::GET, "/.git/config", b"");
}

#[test]
fn redteam_recon_admin() {
    must_detect(&ReconDetector, http::Method::GET, "/wp-admin/setup-config.php", b"");
}
