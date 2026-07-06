use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// SSRF detector.
pub struct SsrfDetector;

static SSRF_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?:https?://(?:127\.0\.0\.1|localhost))",
        r"(?i)(?:https?://0\.0\.0\.0)",
        r"(?i)(?:https?://\[::1?\])",
        r"(?i)(?:https?://169\.254\.169\.254)",
        r"(?i)(?:https?://metadata\.google\.internal)",
        r"(?i)(?:https?://100\.100\.100\.200)",
        r"(?i)(?:https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        r"(?i)(?:https?://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
        r"(?i)(?:https?://192\.168\.\d{1,3}\.\d{1,3})",
        r"(?i)(?:file://)",
        r"(?i)(?:gopher://)",
        r"(?i)(?:dict://)",
        r"(?i)(?:ftp://(?:127|10|192\.168|172\.(?:1[6-9]|2\d|3[01])))",
        r"(?i)(?:https?://0x[0-9a-f]+)",
        r"(?i)(?:https?://\d{8,10})",
        r"(?i)(?:https?://0[0-7]+\.)",
        // SG-1 (2026-07-06 S-Tester) — internal-host SSRF in PLAIN URL form
        // (no userinfo `@`). Pre-fix these three shapes matched no pattern;
        // all 14 `MISSED_attacks_serious` SSRF payloads arrive as a JSON
        // body `email`/`url` value at `PUT /api/profile` /
        // `POST /api/integrations/preview`.
        //
        // (a) Full loopback `127.0.0.0/8` shorthand — `127.1`, `127.0.1`
        //     resolve to 127.0.0.1 via inet_aton. `\b` bounds it so
        //     `127degrees.com` (no dotted-octet after 127) doesn't match.
        //     FP≈0: `127.x` never appears in a valid public URL value.
        r"(?i)https?://127(?:\.\d{1,3}){1,3}\b",
        // (b) Internal service-discovery TLDs in a plain URL (lifted out of
        //     the userinfo-only branch below). `.svc`/`.cluster.local` are
        //     K8s-internal, `.internal` is cloud-internal, `.local` is mDNS
        //     — none are publicly routable.
        r"(?i)https?://[a-z0-9.-]+\.(?:internal|local|svc|cluster\.local)\b",
        // (c) Single-label host + internal-infrastructure port. Public URLs
        //     use multi-label FQDNs on 80/443; a bare single label
        //     (`redis`, `database`, `internal-service`) on a service port is
        //     anomalous. `[a-z0-9-]+` matches ONE label only (a dot ends it),
        //     so `api.example.com:8080` does NOT match.
        r"(?i)https?://[a-z0-9-]+:(?:22|3306|5432|6379|9200|9300|27017|11211|2379|5601|15672|8080|9000)\b",
        // GAP-004 (Run-5, 2026-05-09) — SSRF via URL-userinfo.
        // The `://[^@/]*@` shape catches http://user@host/,
        // http://user:pass@host/, etc. Some URL parsers split on
        // the FIRST `@` they see; others on the LAST. Attackers
        // exploit the discrepancy: a naive WAF allowlist that
        // sees `http://evil.com:80@internal-svc/` and matches
        // "starts with http:// and contains evil.com" would let
        // the request through, even though the parser fetches
        // `internal-svc:8080/path` (interpreting `evil.com:80@`
        // as userinfo, not host). HTTP basic-auth in URL form is
        // RFC 3986-deprecated and rare in modern apps; flagging
        // URL-userinfo matches Chrome / major-WAF behaviour.
        // 2026-06-18 (round-2 FP fix): the old `[^@/\s]+@` was far too
        // broad. It (a) crossed JSON string boundaries — `…"https://
        // schema.org","@type":…` matched at the `@type` of JSON-LD
        // microdata — and (b) fired on Sentry DSNs
        // (`https://<key>@oNNN.ingest.sentry.io`). Now the userinfo is a
        // tight RFC-3986 userinfo charclass (no quote/comma/backslash/
        // brace/angle — none valid in real userinfo), AND the host AFTER
        // the `@` must be internal-looking: an internal/private/metadata
        // IP, a single-label host (`internal`, `internal-svc`), or an
        // internal TLD (`.internal`/`.local`/`.svc`/`.cluster.local`). A
        // bare `user@public.example.com` is NOT SSRF.
        concat!(
            r"(?i)https?://[A-Za-z0-9._~%:!$&'()*+;=-]+@(?:",
            r"127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1?\]|169\.254\.169\.254",
            r"|metadata\.google\.internal|100\.100\.100\.200",
            r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
            r"|192\.168\.\d{1,3}\.\d{1,3}",
            r"|0x[0-9a-f]+|\d{8,10}|0[0-7]+\.",
            r"|[a-z0-9-]+\.(?:internal|local|svc|cluster\.local)\b",
            r"|[a-z0-9-]+(?:[:/?#]|$)",
            r")",
        ),
        // BYPASS-03f (Run-6 l-tester cross-check, 2026-05-09) —
        // IPv4-mapped IPv6 (`[::ffff:<ipv4>]`). Browsers and many
        // HTTP clients resolve `[::ffff:127.0.0.1]` natively as
        // `127.0.0.1`, so attackers use this form to bypass naive
        // allowlists that only check dotted-decimal RFC 1918 /
        // loopback. Same internal-network targets as the dotted-
        // decimal patterns above, just wearing the IPv4-mapped
        // IPv6 prefix.
        //
        // Dotted-decimal payload form: `[::ffff:127.0.0.1]`,
        // `[::ffff:10.0.0.1]`, `[::ffff:169.254.169.254]`, etc.
        r"(?i)(?:https?://\[::ffff:(?:127|10|0|169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.)",
        // Hex-colon payload form: `[::ffff:7f00:1]` (= 127.0.0.1),
        // `[::ffff:0a00:1]` (= 10.0.0.1), `[::ffff:a9fe:a9fe]`
        // (= 169.254.169.254 AWS metadata), `[::ffff:c0a8:1]` (=
        // 192.168.0.1), `[::ffff:ac10:1]` (= 172.16.0.1).
        r"(?i)(?:https?://\[::ffff:(?:7f00|0a[0-9a-f]{2}|a9fe|c0a8|ac1[0-9a-f]):)",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

impl Detector for SsrfDetector {
    fn id(&self) -> &'static str {
        "ssrf"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // SSRF lives in attacker-controlled URL strings: query params,
        // body, and forwarding headers. Do NOT scan `req.uri.to_string()`
        // — over HTTP/2 the request URI serialises to absolute form
        // (`https://<authority>/<path>`) which would self-trip on every
        // request whose authority is `localhost` / `127.0.0.1` / etc.
        // The path component is also covered by the query+path scan
        // below where the URL fragment lives.
        if let Some(query) = req.uri.query() {
            check_ssrf(&super::url_decode(query), "query", &mut signals);
        }
        if !req.uri.path().is_empty() {
            check_ssrf(&super::url_decode(req.uri.path()), "path", &mut signals);
        }

        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        // S-B (2026-06-18 round-2) — skip bot-management sensor beacons
        // (form-urlencoded/text-plain single huge high-entropy value). The
        // blob coincidentally matches internal-host/userinfo URL shapes.
        // Mirrors the cmdi/sqli body gate.
        if !body.is_empty() && !super::form_body_is_opaque_beacon(req.headers, body) {
            check_ssrf(&super::url_decode(body), "body", &mut signals);
        }

        // 2026-05-07 — `Referer` dropped (H001). It's set by the
        // browser to the page origin; SSRF exploits never travel via
        // Referer. Loopback Referer values trip the detector on any
        // localhost-deployed dashboard, which self-blocks every
        // sub-resource fetch. Reverse-proxy override headers still
        // scan because operators sometimes pass attacker-controlled
        // URLs through them.
        for name in &["x-original-url", "x-rewrite-url"] {
            if let Some(val) = req.headers.get(*name).and_then(|v| v.to_str().ok()) {
                check_ssrf(val, name, &mut signals);
            }
        }

        signals
    }
}

fn check_ssrf(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in SSRF_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::ssrf::SSRF,
                tag: "ssrf".into(),
                field: field.into(),
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn view_with_uri(uri: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::GET,
            uri.parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        )
    }

    fn make_view<'a>(
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

    macro_rules! positive {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = SsrfDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(!d.inspect(&req).is_empty(), "expected SSRF for: {}", $input);
            }
        };
    }

    macro_rules! negative {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = SsrfDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(d.inspect(&req).is_empty(), "false positive for: {}", $input);
            }
        };
    }

    positive!(ssrf_localhost, "/proxy?url=http://localhost/admin");
    positive!(ssrf_127, "/proxy?url=http://127.0.0.1/secret");
    positive!(ssrf_metadata, "/proxy?url=http://169.254.169.254/latest/meta-data/");
    positive!(ssrf_google_meta, "/proxy?url=http://metadata.google.internal/");
    positive!(ssrf_ipv6_loop, "/proxy?url=http://[::1]/");
    positive!(ssrf_10_net, "/proxy?url=http://10.0.0.1/");
    positive!(ssrf_172, "/proxy?url=http://172.16.0.1/");
    positive!(ssrf_192, "/proxy?url=http://192.168.1.1/");
    positive!(ssrf_file, "/proxy?url=file:///etc/passwd");
    positive!(ssrf_gopher, "/proxy?url=gopher://evil/");
    positive!(ssrf_dict, "/proxy?url=dict://evil/");
    positive!(ssrf_zero, "/proxy?url=http://0.0.0.0/");
    positive!(ssrf_hex_ip, "/proxy?url=http://0x7f000001/");
    positive!(ssrf_decimal_ip, "/proxy?url=http://2130706433/");
    positive!(ssrf_octal, "/proxy?url=http://0177.0.0.1/");
    positive!(ssrf_https_localhost, "/proxy?url=https://localhost/");
    positive!(ssrf_https_127, "/proxy?url=https://127.0.0.1:8080/");
    positive!(ssrf_alibaba, "/proxy?url=http://100.100.100.200/");
    positive!(ssrf_10_deep, "/proxy?url=http://10.255.255.255/");
    positive!(ssrf_172_31, "/proxy?url=http://172.31.255.255/");
    positive!(ssrf_192_168, "/proxy?url=http://192.168.255.255/");
    positive!(ssrf_ftp_internal, "/proxy?url=ftp://10.0.0.1/");
    positive!(ssrf_ipv6_bracket, "/proxy?url=http://[::]/");
    positive!(ssrf_localhost_port, "/proxy?url=http://localhost:9200/");
    positive!(ssrf_file_win, "/proxy?url=file:///c:/windows/win.ini");
    positive!(ssrf_127_port, "/proxy?url=http://127.0.0.1:3306/");
    positive!(ssrf_meta_path, "/proxy?url=http://169.254.169.254/latest/api/token");
    positive!(ssrf_172_20, "/proxy?url=http://172.20.0.1/internal");
    positive!(ssrf_10_1, "/proxy?url=http://10.1.2.3/secret");
    positive!(ssrf_192_168_0, "/proxy?url=http://192.168.0.1/router");
    // GAP-004 (Run-5) — URL-userinfo positives.
    positive!(ssrf_userinfo_user_pass, "/proxy?url=http://user:pass@10.0.0.1/secret");
    positive!(ssrf_userinfo_parser_split,
        "/proxy?url=https://evil.example.com:80@internal-svc/path");
    positive!(ssrf_userinfo_at_127, "/proxy?u=http://x@127.0.0.1");
    positive!(ssrf_userinfo_no_pass, "/proxy?url=http://admin@internal/admin");

    // S-D (2026-06-18 round-2) — userinfo SSRF FPs. The old `[^@/\s]+@`
    // shape crossed JSON string boundaries and fired on Sentry DSNs. It now
    // requires (a) a tight RFC-3986 userinfo charclass and (b) an
    // internal-looking host AFTER the `@`. Bare userinfo to a public host is
    // not SSRF.
    fn ssrf_body_json(body: &str) -> Vec<Signal> {
        let mut h = http::HeaderMap::new();
        h.insert("content-type", "application/json".parse().unwrap());
        let m = http::Method::POST;
        let u: http::Uri = "/ingest".parse().unwrap();
        let b = BodyPeek::new(body.as_bytes().to_vec(), Some(body.len() as u64), false);
        SsrfDetector.inspect(&make_view(&m, &u, &h, &b))
    }

    #[test]
    fn ssrf_clean_jsonld_at_context() {
        // JSON-LD microdata: `schema.org","@type` must NOT trip userinfo.
        let body = r#"{"@context":"https://schema.org","@type":"Product","name":"x"}"#;
        assert!(ssrf_body_json(body).is_empty(), "JSON-LD @context must not SSRF");
    }

    #[test]
    fn ssrf_clean_sentry_dsn() {
        // Sentry DSN `https://<key>@oNNN.ingest.sentry.io` is benign config.
        let body = r#"{"dsn":"https://abc123def4567890abcdef@o212024.ingest.sentry.io/42"}"#;
        assert!(ssrf_body_json(body).is_empty(), "Sentry DSN must not SSRF");
    }

    #[test]
    fn ssrf_clean_userinfo_public_host() {
        // Bare basic-auth URL to a PUBLIC host is not SSRF.
        let body = r#"{"u":"https://user:pass@api.public-example.com/v1"}"#;
        assert!(ssrf_body_json(body).is_empty(), "userinfo to public host must not SSRF");
    }

    #[test]
    fn ssrf_userinfo_internal_target_still_fires_via_body() {
        // The parser-confusion attack must still fire: real host is internal.
        let body = r#"{"u":"http://evil.com@169.254.169.254/latest/meta-data/"}"#;
        assert!(!ssrf_body_json(body).is_empty(), "userinfo to metadata IP must SSRF");
    }
    // BYPASS-03f (Run-6 l-tester cross-check, 2026-05-09) —
    // IPv4-mapped IPv6 SSRF. Browsers resolve `[::ffff:127.0.0.1]`
    // natively as `127.0.0.1`, so attackers use this form to
    // bypass naive allowlists that only check dotted-decimal.
    // Dotted-decimal payload form.
    positive!(ssrf_ipv4_mapped_loopback,    "/proxy?url=http://[::ffff:127.0.0.1]/secret");
    positive!(ssrf_ipv4_mapped_rfc1918_10,  "/proxy?url=http://[::ffff:10.0.0.1]/internal");
    positive!(ssrf_ipv4_mapped_rfc1918_192, "/proxy?url=http://[::ffff:192.168.1.1]/admin");
    positive!(ssrf_ipv4_mapped_rfc1918_172, "/proxy?url=http://[::ffff:172.16.0.1]/secrets");
    positive!(ssrf_ipv4_mapped_aws_metadata,
        "/proxy?url=http://[::ffff:169.254.169.254]/latest/meta-data/");
    positive!(ssrf_ipv4_mapped_zero,        "/proxy?url=http://[::ffff:0.0.0.0]/bind");
    // Hex-colon payload form.
    positive!(ssrf_ipv4_mapped_hex_loopback, "/proxy?url=http://[::ffff:7f00:1]/");
    positive!(ssrf_ipv4_mapped_hex_aws_meta, "/proxy?url=http://[::ffff:a9fe:a9fe]/");
    positive!(ssrf_ipv4_mapped_hex_192_168,  "/proxy?url=http://[::ffff:c0a8:1]/");
    positive!(ssrf_ipv4_mapped_hex_172_16,   "/proxy?url=http://[::ffff:ac10:1]/");
    positive!(ssrf_ipv4_mapped_hex_10_0,     "/proxy?url=http://[::ffff:0a00:1]/");

    negative!(clean_root, "/");
    negative!(clean_api, "/api/users");
    negative!(clean_external, "/proxy?url=https://example.com/");
    negative!(clean_google, "/proxy?url=https://google.com/");
    negative!(clean_no_url, "/search?q=hello");
    negative!(clean_path, "/products/123");
    negative!(clean_version, "/v2/api");
    negative!(clean_static, "/static/main.js");
    negative!(clean_health, "/health");
    negative!(clean_query, "/items?page=1&sort=name");
    negative!(clean_cdn, "/proxy?url=https://cdn.example.com/image.jpg");
    negative!(clean_docs, "/proxy?url=https://docs.rust-lang.org/");
    negative!(clean_github, "/proxy?url=https://github.com/owner/repo");
    negative!(clean_blog, "/blog/post-1");
    negative!(clean_webhook, "/webhooks/handler");
    negative!(clean_numeric, "/items/42");
    negative!(clean_encoded, "/path?name=hello%20world");
    negative!(clean_json, "/api/data.json");
    negative!(clean_robots, "/robots.txt");
    negative!(clean_sitemap, "/sitemap.xml");
    negative!(clean_feed, "/feed.xml");
    negative!(clean_image, "/images/photo.jpg");
    negative!(clean_css, "/styles/main.css");
    negative!(clean_long_path, "/a/b/c/d/e/f/g/h");
    negative!(clean_uuid, "/api/550e8400-e29b-41d4-a716-446655440000");
    negative!(clean_download, "/download/file.zip");
    negative!(clean_manifest, "/manifest.json");
    negative!(clean_sw, "/sw.js");
    negative!(clean_favicon, "/favicon.ico");
    negative!(clean_mailto, "/contact?email=user@example.com");
    negative!(clean_auth, "/auth/callback");
    // BYPASS-03f negatives — public IPv6 + non-internal IPv4-mapped
    // forms must NOT FP. The pattern only matches the documented
    // internal target prefixes (127, 10, 169.254, 192.168, 172.16-31,
    // 0) in dotted-decimal, plus their hex-colon equivalents.
    // SG-1 (2026-07-06 S-Tester `MISSED_attacks_serious`) — internal-host
    // SSRF in PLAIN URL form (no userinfo `@`). Pre-fix these matched NO
    // pattern: short-loopback `127.1`, single-label internal host + infra
    // port (`redis:6379`), and internal-TLD outside the `@` branch
    // (`…svc.cluster.local`). All arrive in a JSON body `email`/`url` field.
    positive!(ssrf_loopback_short_127_1,   "/proxy?url=http://127.1/");
    positive!(ssrf_loopback_short_127_0_1, "/proxy?url=http://127.0.1/");
    positive!(ssrf_singlelabel_redis,      "/proxy?url=http://redis:6379/");
    positive!(ssrf_singlelabel_database,   "/proxy?url=http://database:3306/");
    positive!(ssrf_singlelabel_es,         "/proxy?url=http://elasticsearch:9200/");
    positive!(ssrf_singlelabel_internal_svc_port, "/proxy?url=http://internal-service:8080/");
    positive!(ssrf_internal_tld_k8s,
        "/proxy?url=http://kubernetes.default.svc.cluster.local/");

    #[test]
    fn ssrf_body_internal_hosts_all_fire() {
        // The 14 `MISSED_attacks_serious` SSRF payloads land in a JSON body
        // (`PUT /api/profile` email, `POST /api/integrations/preview` url).
        for body in [
            r#"{"email":"http://127.1","display_name":"x"}"#,
            r#"{"email":"http://127.0.1","display_name":"x"}"#,
            r#"{"email":"http://internal-service:8080","display_name":"x"}"#,
            r#"{"email":"http://database:3306","display_name":"x"}"#,
            r#"{"email":"http://redis:6379","display_name":"x"}"#,
            r#"{"email":"http://elasticsearch:9200","display_name":"x"}"#,
            r#"{"email":"http://kubernetes.default.svc.cluster.local","display_name":"x"}"#,
            r#"{"url":"http://127.1"}"#,
            r#"{"url":"http://redis:6379"}"#,
        ] {
            assert!(!ssrf_body_json(body).is_empty(), "body must SSRF: {body}");
        }
    }

    // SG-1 FP guards — the new patterns must NOT fire on public URLs.
    // A multi-label FQDN carrying a port is ordinary (`api.example.com:8080`);
    // pattern #3 only matches SINGLE-label hosts. A public host on a
    // non-infra port is fine. `127degrees.com` is not loopback.
    negative!(clean_fqdn_with_port,      "/proxy?url=http://api.example.com:8080/v1");
    negative!(clean_fqdn_https_port,     "/proxy?url=https://cdn.example.com:8443/asset.js");
    negative!(clean_host_word_127,       "/proxy?url=http://127degrees.com/");
    negative!(clean_singlelabel_web_port, "/proxy?url=http://example:443/");
    negative!(clean_public_ipv6,         "/proxy?url=http://[2001:db8::1]/");
    negative!(clean_ipv4_mapped_public,  "/proxy?url=http://[::ffff:8.8.8.8]/dns");
    negative!(clean_ipv4_mapped_172_32,  "/proxy?url=http://[::ffff:172.32.0.1]/");  // 172.32 is outside RFC 1918
    negative!(clean_ipv4_mapped_hex_public, "/proxy?url=http://[::ffff:0808:0808]/");  // 8.8.8.8 in hex pairs

    // Regression: prior to 2026-05-02 the detector scanned
    // `req.uri.to_string()` which over HTTP/2 returns the absolute
    // form `https://<authority>/<path>` — every request whose
    // authority resolved to `localhost` / `127.0.0.1` / a private IP
    // self-tripped (false positive that broke `make smoke`).
    // The detector now scans query / path / body / forwarding
    // headers only — not the request URL itself.
    #[test]
    fn does_not_self_trip_on_localhost_authority_via_uri() {
        let d = SsrfDetector;
        // Simulate what http::Uri::to_string() produces under HTTP/2
        // when authority + path are both present.
        let u: http::Uri = "https://localhost:8443/".parse().unwrap();
        let m = http::Method::GET;
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).is_empty(),
            "self-targeting request should NOT trip SSRF (authority is the WAF itself)"
        );
    }

    #[test]
    fn does_not_self_trip_on_127_authority() {
        let d = SsrfDetector;
        let u: http::Uri = "http://127.0.0.1:8080/api/profile".parse().unwrap();
        let m = http::Method::GET;
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty(), "self-targeting 127.0.0.1 must not SSRF");
    }

    // 2026-05-07 — `Referer` is browser-set to the page's own origin.
    // A dashboard hosted at 127.0.0.1:8080 sets Referer on every
    // sub-resource fetch, which used to trip the loopback pattern.
    // SSRF exploits go through query / body / X-Original-URL /
    // X-Rewrite-URL — never via Referer.
    #[test]
    fn clean_request_with_loopback_referer_does_not_trip() {
        let d = SsrfDetector;
        let u: http::Uri = "/api/data".parse().unwrap();
        let m = http::Method::GET;
        let mut h = http::HeaderMap::new();
        h.insert("referer", "http://127.0.0.1:8080/".parse().unwrap());
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).is_empty(),
            "loopback Referer must not trigger SSRF (browser-set, not attacker-controlled)",
        );
    }

    #[test]
    fn x_original_url_with_loopback_still_blocks() {
        // Regression guard — H001 only drops Referer; reverse-proxy
        // override headers must still trigger SSRF.
        let d = SsrfDetector;
        let u: http::Uri = "/api/data".parse().unwrap();
        let m = http::Method::GET;
        let mut h = http::HeaderMap::new();
        h.insert(
            "x-original-url",
            "http://127.0.0.1:8080/admin".parse().unwrap(),
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert_eq!(signals.len(), 1, "X-Original-URL with loopback must still SSRF");
        assert_eq!(signals[0].tag, "ssrf");
    }

    #[test]
    fn x_rewrite_url_with_loopback_still_blocks() {
        let d = SsrfDetector;
        let u: http::Uri = "/api/data".parse().unwrap();
        let m = http::Method::GET;
        let mut h = http::HeaderMap::new();
        h.insert(
            "x-rewrite-url",
            "http://127.0.0.1:8080/admin".parse().unwrap(),
        );
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert_eq!(signals.len(), 1, "X-Rewrite-URL with loopback must still SSRF");
        assert_eq!(signals[0].tag, "ssrf");
    }

    // ===== S-B (2026-06-18 round-2) — beacon gate on the body scan =====

    fn ssrf_blob() -> String {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .chars()
            .cycle()
            .take(320)
            .collect()
    }

    fn body_view_ct(ct: &str, body: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        let mut h = http::HeaderMap::new();
        h.insert("content-type", ct.parse().unwrap());
        (
            http::Method::POST,
            "/tr/".parse().unwrap(),
            h,
            BodyPeek::new(body.as_bytes().to_vec(), Some(body.len() as u64), false),
        )
    }

    #[test]
    fn text_plain_sensor_beacon_with_coincidental_ssrf_is_skipped() {
        // 2026-06-18 r2: a text/plain sensor beacon whose high-entropy blob
        // coincidentally contains an internal-host URL must be skipped.
        let d = SsrfDetector;
        let body = format!("{{\"sensor_data\":\"{}http://127.0.0.1/x\"}}", ssrf_blob());
        let (m, u, h, b) = body_view_ct("text/plain;charset=UTF-8", &body);
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty(), "text/plain sensor beacon must be skipped by ssrf");
    }

    #[test]
    fn real_ssrf_in_short_body_still_fires() {
        // Same internal URL in a short body → NOT a beacon → fires.
        let d = SsrfDetector;
        let (m, u, h, b) = body_view_ct("text/plain", "url=http://169.254.169.254/latest/meta-data/");
        let req = make_view(&m, &u, &h, &b);
        assert!(!d.inspect(&req).is_empty(), "real ssrf in a normal body must still fire");
    }
}
