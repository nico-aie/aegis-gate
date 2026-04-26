/// Benign corpus — false positive rate test.
///
/// Ensures that normal, legitimate requests are NOT flagged by any detector.
/// Target: FP rate < 1%.
use aegis_core::pipeline::{BodyPeek, RequestView};
use aegis_security::detectors::{
    header_injection::HeaderInjectionDetector,
    path_traversal::PathTraversalDetector,
    recon::ReconDetector,
    sqli::SqliDetector,
    ssrf::SsrfDetector,
    xss::XssDetector,
    Detector,
};

fn make_view(uri: &str, body: &[u8]) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
    (
        http::Method::GET,
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

/// All detectors that check URIs.
fn uri_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(SqliDetector),
        Box::new(XssDetector),
        Box::new(PathTraversalDetector),
        Box::new(SsrfDetector),
        Box::new(HeaderInjectionDetector),
        Box::new(ReconDetector),
    ]
}

const BENIGN_URIS: &[&str] = &[
    "/",
    "/index.html",
    "/api/users",
    "/api/users?page=1&limit=25",
    "/api/users/123",
    "/api/users/123/posts",
    "/api/products?category=electronics&sort=price&order=asc",
    "/search?q=rust+programming+language",
    "/search?q=best+restaurants+near+me",
    "/search?q=how+to+cook+pasta",
    "/blog/2024/01/my-first-post",
    "/blog?tag=rust&tag=webdev",
    "/assets/css/main.css",
    "/assets/js/app.js",
    "/assets/images/hero.jpg",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/api/v2/orders?status=pending",
    "/api/v2/orders/ORD-2024-001",
    "/dashboard",
    "/settings/profile",
    "/settings/notifications",
    "/auth/login",
    "/auth/register",
    "/auth/forgot-password",
    "/api/analytics?from=2024-01-01&to=2024-01-31",
    "/api/reports/monthly?year=2024&month=1",
    "/api/health",
    "/api/metrics",
    "/docs/getting-started",
    "/docs/api-reference",
    "/api/users?search=john%40example.com",
    "/api/items?filter=name%3Dtest",
    "/api/data?format=json&pretty=true",
    "/api/data?callback=jsonp_callback_123",
    "/api/users?fields=id,name,email",
    "/api/events?after=2024-01-01T00:00:00Z",
    "/api/products/abc-def-123",
    "/api/i18n?locale=en-US",
    "/api/i18n?locale=fr-FR",
    "/files/documents/report.pdf",
    "/files/documents/summary.docx",
    "/api/upload?type=image&max_size=5242880",
    "/api/webhooks?event=order.created",
    "/api/config?env=production",
    "/api/users?role=admin&active=true",
    "/api/search?q=C%2B%2B+programming",
    "/api/search?q=O%27Brien",
    "/api/items?price_min=10&price_max=100",
    "/page/about-us",
    "/page/contact",
    "/page/terms-of-service",
    "/page/privacy-policy",
    "/api/notifications?unread=true",
    "/api/comments?post_id=456&page=2",
    "/feed.xml",
    "/feed.rss",
    "/api/geo?lat=40.7128&lon=-74.0060",
    "/api/weather?city=New+York&units=metric",
    "/api/currency?from=USD&to=EUR&amount=100",
    "/checkout/cart",
    "/checkout/payment",
    "/checkout/confirmation",
    "/api/inventory?warehouse=US-EAST",
    "/api/shipping?zip=10001",
    "/api/reviews?product_id=789&rating=5",
    "/api/recommendations?user_id=u123",
    "/status",
    "/api/batch?ids=1,2,3,4,5",
    "/api/export?format=csv",
    "/api/import",
    "/api/diff?version=1.2.3",
    "/api/changelog",
    "/legal/compliance",
    "/support/tickets?status=open",
    "/support/faq",
    "/api/teams/engineering/members",
    "/api/projects/aegis/milestones",
    "/api/audit-log?from=2024-01-01",
    "/api/rate-limits",
    "/cdn/assets/bundle.js",
    "/cdn/assets/vendor.css",
    "/api/token/refresh",
    "/api/session/validate",
    "/api/integrations/slack",
    "/api/integrations/github",
    "/api/flags?feature=dark_mode",
    "/api/experiments?group=control",
    "/api/usage?period=monthly",
    "/api/billing/invoices",
    "/api/billing/subscription",
    "/api/domains?verified=true",
    "/api/dns?type=A&name=example.com",
    "/api/certificates?domain=example.com",
    "/api/logs?level=error&limit=100",
    "/api/traces?service=api-gateway",
    "/api/alerts?severity=critical",
    "/api/dashboards/overview",
    "/api/widgets?dashboard_id=d1",
];

#[test]
fn benign_corpus_fp_rate_below_1_percent() {
    let detectors = uri_detectors();
    let total = BENIGN_URIS.len();
    let mut fp_count = 0;

    for uri in BENIGN_URIS {
        let (m, u, h, b) = make_view(uri, b"");
        let r = req(&m, &u, &h, &b);

        for detector in &detectors {
            if !detector.inspect(&r).is_empty() {
                eprintln!("FP: {} flagged by {}", uri, detector.id());
                fp_count += 1;
                break; // Count each URI only once.
            }
        }
    }

    let fp_rate = (fp_count as f64 / total as f64) * 100.0;
    eprintln!(
        "Benign corpus: {total} URIs, {fp_count} false positives, FP rate: {fp_rate:.2}%"
    );
    assert!(
        fp_rate < 1.0,
        "FP rate {fp_rate:.2}% exceeds 1% threshold ({fp_count}/{total})"
    );
}
