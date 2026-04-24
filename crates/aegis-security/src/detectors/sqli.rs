use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// SQL injection detector.
pub struct SqliDetector;

static SQLI_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?:UNION\s+(?:ALL\s+)?SELECT)",
        r"(?i)(?:SELECT\s+.+\s+FROM\s+)",
        r"(?i)(?:INSERT\s+INTO\s+)",
        r"(?i)(?:UPDATE\s+.+\s+SET\s+)",
        r"(?i)(?:DELETE\s+FROM\s+)",
        r"(?i)(?:DROP\s+TABLE\s+)",
        r"(?i)(?:ALTER\s+TABLE\s+)",
        r"(?i)(?:OR\s+1\s*=\s*1)",
        r"(?i)(?:AND\s+1\s*=\s*1)",
        r"(?i)(?:'\s*OR\s+'[^']*'\s*=\s*')",
        r"(?i)(?:'\s*;\s*(?:DROP|DELETE|UPDATE|INSERT))",
        r"(?i)(?:--\s*$)",
        r"(?i)(?:/\*.*\*/)",
        r"(?i)(?:WAITFOR\s+DELAY)",
        r"(?i)(?:BENCHMARK\s*\()",
        r"(?i)(?:SLEEP\s*\()",
        r"(?i)(?:LOAD_FILE\s*\()",
        r"(?i)(?:INTO\s+(?:OUT|DUMP)FILE)",
        r"(?i)(?:EXEC(?:UTE)?\s+)",
        r"(?i)(?:xp_cmdshell)",
        r"(?i)(?:information_schema)",
        r"(?i)(?:sys\.(?:objects|columns|tables))",
        r"(?i)(?:0x[0-9a-f]{8,})",
        r"(?i)(?:CHAR\s*\(\s*\d+\s*\))",
        r"(?i)(?:CONCAT\s*\()",
        r"(?i)(?:GROUP\s+BY\s+.+\s+HAVING)",
        r"(?i)(?:ORDER\s+BY\s+\d+)",
        r"(?i)(?:CASE\s+WHEN\s+)",
        r"(?i)(?:EXTRACTVALUE\s*\()",
        r"(?i)(?:UPDATEXML\s*\()",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

impl Detector for SqliDetector {
    fn id(&self) -> &'static str {
        "sqli"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Check URI (path + query), URL-decoded.
        let uri_str = super::url_decode(&req.uri.to_string());
        check_patterns(&uri_str, "uri", &mut signals);

        // Check body.
        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        if !body.is_empty() {
            check_patterns(&super::url_decode(body), "body", &mut signals);
        }

        // Check selected headers.
        for name in &["cookie", "referer", "x-forwarded-for", "user-agent"] {
            if let Some(val) = req.headers.get(*name).and_then(|v| v.to_str().ok()) {
                check_patterns(val, name, &mut signals);
            }
        }

        signals
    }
}

fn check_patterns(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in SQLI_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: 40,
                tag: "sqli".into(),
                field: field.into(),
            });
            return; // One signal per field is enough.
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
            method: m,
            uri: u,
            version: http::Version::HTTP_11,
            headers: h,
            peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None,
            body: b,
        }
    }

    // === Positive fixtures (should detect) ===

    macro_rules! positive_test {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = SqliDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                let s = d.inspect(&req);
                assert!(!s.is_empty(), "expected SQLi detection for: {}", $input);
            }
        };
    }

    positive_test!(sqli_union_select, "/?q=1+UNION+SELECT+*+FROM+users");
    positive_test!(sqli_or_1_eq_1, "/?id=1+OR+1=1");
    positive_test!(sqli_single_quote_or, "/?id='+OR+'1'='1");
    positive_test!(sqli_drop_table, "/?q=';+DROP+TABLE+users");
    positive_test!(sqli_select_from, "/?q=SELECT+name+FROM+users");
    positive_test!(sqli_insert_into, "/?q=INSERT+INTO+logs+VALUES(1)");
    positive_test!(sqli_update_set, "/?q=UPDATE+users+SET+admin=1");
    positive_test!(sqli_delete_from, "/?q=DELETE+FROM+sessions");
    positive_test!(sqli_alter_table, "/?q=ALTER+TABLE+users+ADD+col+INT");
    positive_test!(sqli_comment, "/?id=1--");
    positive_test!(sqli_c_comment, "/?id=1/**/");
    positive_test!(sqli_waitfor, "/?id=1;WAITFOR+DELAY+'0:0:5'");
    positive_test!(sqli_benchmark, "/?id=BENCHMARK(1000,MD5('a'))");
    positive_test!(sqli_sleep, "/?id=SLEEP(5)");
    positive_test!(sqli_load_file, "/?id=LOAD_FILE('/etc/passwd')");
    positive_test!(sqli_into_outfile, "/?q=INTO+OUTFILE+'/tmp/out'");
    positive_test!(sqli_exec, "/?q=EXEC+sp_help");
    positive_test!(sqli_xp_cmdshell, "/?q=xp_cmdshell+'dir'");
    positive_test!(sqli_information_schema, "/?q=information_schema.tables");
    positive_test!(sqli_sys_objects, "/?q=sys.objects");
    positive_test!(sqli_hex_encoded, "/?q=0x4142434445464748");
    positive_test!(sqli_char_func, "/?q=CHAR(65)");
    positive_test!(sqli_concat, "/?q=CONCAT('a','b')");
    positive_test!(sqli_group_by_having, "/?q=GROUP+BY+id+HAVING+1=1");
    positive_test!(sqli_order_by_num, "/?q=ORDER+BY+5");
    positive_test!(sqli_case_when, "/?q=CASE+WHEN+1=1+THEN+1");
    positive_test!(sqli_extractvalue, "/?q=EXTRACTVALUE(1,1)");
    positive_test!(sqli_updatexml, "/?q=UPDATEXML(1,1,1)");
    positive_test!(sqli_and_1_eq_1, "/?id=1+AND+1=1");
    positive_test!(sqli_into_dumpfile, "/?q=INTO+DUMPFILE+'/tmp/x'");
    positive_test!(sqli_union_all_select, "/?q=UNION+ALL+SELECT+1,2,3");

    // === Negative fixtures (should NOT detect) ===

    macro_rules! negative_test {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = SqliDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                let s = d.inspect(&req);
                assert!(s.is_empty(), "false positive for: {} — got {:?}", $input, s);
            }
        };
    }

    negative_test!(clean_root, "/");
    negative_test!(clean_api, "/api/users?page=1&limit=10");
    negative_test!(clean_search, "/search?q=hello+world");
    negative_test!(clean_path, "/products/123/details");
    negative_test!(clean_query_string, "/items?category=shoes&color=red");
    negative_test!(clean_uuid, "/api/v1/objects/550e8400-e29b-41d4-a716-446655440000");
    negative_test!(clean_json_api, "/api/data?format=json&fields=name,email");
    negative_test!(clean_pagination, "/blog/posts?page=2&per_page=20");
    negative_test!(clean_auth_token, "/api/resource?token=abc123def456");
    negative_test!(clean_download, "/files/report-2024.pdf");
    negative_test!(clean_webhook, "/webhooks/github");
    negative_test!(clean_health, "/health/ready");
    negative_test!(clean_metrics, "/metrics");
    negative_test!(clean_static, "/static/js/main.js");
    negative_test!(clean_images, "/images/logo.png");
    negative_test!(clean_css, "/css/style.css");
    negative_test!(clean_sitemap, "/sitemap.xml");
    negative_test!(clean_robots, "/robots.txt");
    negative_test!(clean_favicon, "/favicon.ico");
    negative_test!(clean_deep_path, "/a/b/c/d/e/f");
    negative_test!(clean_encoded_space, "/search?q=hello%20world");
    negative_test!(clean_numeric_id, "/users/42");
    negative_test!(clean_query_bool, "/api/items?active=true&sort=name");
    negative_test!(clean_fragment, "/page#section");
    negative_test!(clean_locale, "/en-US/docs/getting-started");
    negative_test!(clean_versioned, "/v2/api/resource");
    negative_test!(clean_dash_path, "/my-resource/sub-item");
    negative_test!(clean_underscore, "/my_resource/list_all");
    negative_test!(clean_date, "/archive/2024/01/15");
    negative_test!(clean_empty_query, "/path?");
    negative_test!(clean_anchor, "/docs/intro#overview");
}
