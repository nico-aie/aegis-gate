use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// SQL injection detector.
pub struct SqliDetector;

// FP-2026-07-07 (SQ-2) — two tiers. HIGH patterns are unambiguous SQLi and
// block on a single hit (score 70). AMBIGUOUS patterns (function-name-only and
// clause-bridge shapes) collide with benign analytics / GraphQL / YQL, so they
// block ONLY when corroborated by a SQL line-comment (`--`) in the same field;
// a lone benign `concat(` / `char(` / `SELECT…FROM` emits no signal at all.
static SQLI_HIGH: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?:UNION\s+(?:ALL\s+)?SELECT)",
        r"(?i)(?:INSERT\s+INTO\s+)",
        r"(?i)(?:DELETE\s+FROM\s+)",
        r"(?i)(?:DROP\s+TABLE\s+)",
        r"(?i)(?:ALTER\s+TABLE\s+)",
        r"(?i)(?:OR\s+1\s*=\s*1)",
        r"(?i)(?:AND\s+1\s*=\s*1)",
        r"(?i)(?:'\s*OR\s+'[^']*'\s*=\s*')",
        r"(?i)(?:'\s*;\s*(?:DROP|DELETE|UPDATE|INSERT))",
        // 2026-05-24 (FP fix) — the comment marker must follow a quote
        // (string breakout). Bare trailing `--` matched any value ending
        // in `--`, e.g. the IAB US-Privacy string `us_privacy=1---`. Real
        // comment SQLi breaks out of a quoted string (`admin'--`, `' OR
        // 1=1--`); numeric injections are caught by the OR/UNION rules
        // regardless of the trailing `--`.
        // FP-2026-07-07 (SQ-1): bound the gap. The unbounded `'[^']*--`
        // matched an apostrophe early in a value and a `--` far later
        // (contractions + a dashed separator in the same JSON/query field).
        // Real breakout comments are short (`admin'--`, `' OR 1=1--`).
        r"(?i)(?:'[^']{0,32}--)",
        // FP-2026-07-07 (SQ-1): bounded, non-greedy. A long benign C-style
        // comment block (license header / doc block > 64 chars) no longer
        // matches; the short evasion `/**/` and MySQL `/*!…*/` still fire.
        r"(?i)(?:/\*.{0,64}?\*/)",
        r"(?i)(?:WAITFOR\s+DELAY)",
        // SQ-2 (2026-07-07): a time/heavy function in an injection context — a
        // SQL boolean operator, statement boundary, or closing paren directly
        // before it — is high-confidence blind SQLi (`1 AND SLEEP(5)`,
        // `1) OR BENCHMARK(…)`, `;SLEEP(5)`). The BARE `sleep(`/`benchmark(`
        // (benign analytics) stays AMBIGUOUS below.
        r"(?i)(?:\bAND\b|\bOR\b|;|\))\s*(?:SLEEP|BENCHMARK|PG_SLEEP)\s*\(",
        r"(?i)(?:LOAD_FILE\s*\()",
        r"(?i)(?:INTO\s+(?:OUT|DUMP)FILE)",
        r"(?i)(?:xp_cmdshell)",
        r"(?i)(?:information_schema)",
        r"(?i)(?:sys\.(?:objects|columns|tables))",
        r"(?i)(?:GROUP\s+BY\s+.+\s+HAVING)",
        r"(?i)(?:CASE\s+WHEN\s+)",
        r"(?i)(?:EXTRACTVALUE\s*\()",
        r"(?i)(?:UPDATEXML\s*\()",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

// AMBIGUOUS — function-name-only + clause-bridge shapes. These are the sqli FP
// drivers (YQL `SELECT…FROM…ORDER BY`, analytics `concat(`/`char(`/`sleep(`).
// 2026-05-24: `0x[0-9a-f]{8,}` was already removed (GPU-id FP). Block only with
// a `--` corroborator (see `check_patterns`).
static SQLI_AMBIGUOUS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?:SELECT\s+.+\s+FROM\s+)",
        r"(?i)(?:UPDATE\s+.+\s+SET\s+)",
        r"(?i)(?:BENCHMARK\s*\()",
        r"(?i)(?:SLEEP\s*\()",
        r"(?i)(?:EXEC(?:UTE)?\s+)",
        r"(?i)(?:CHAR\s*\(\s*\d+\s*\))",
        r"(?i)(?:CONCAT\s*\()",
        r"(?i)(?:ORDER\s+BY\s+\d+)",
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

        // S1 (2026-05-18) — multi-variant decoder pipeline. Catches
        // double-URL-encoded payloads (`%2527+OR+1=1`), HTML-entity
        // encoded (`&apos; OR 1=1`), and unicode-escape (`'`)
        // forms that the single-pass `url_decode` missed.
        let raw_uri = req.uri.to_string();
        for variant in super::normalize_for_detection(&raw_uri) {
            check_patterns(&variant, "uri", &mut signals);
            if !signals.is_empty() {
                break;
            }
        }

        // Check body — only when it's structured text the origin will
        // parse (JSON / form / XML / text). Opaque/binary beacon bodies
        // are skipped (2026-05-24 FP fix — see `body_is_scannable`); they
        // were the source of ~all captured body false positives.
        if signals.is_empty() && super::body_is_scannable(req.headers) {
            let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
            // S2 (2026-06-18) — skip bot-management sensor beacons posted
            // as form-urlencoded/text-plain (single huge high-entropy
            // value); they coincidentally match injection shapes.
            if !body.is_empty() && !super::body_is_opaque(req.headers, body) {
                for variant in super::normalize_for_detection(body) {
                    check_patterns(&variant, "body", &mut signals);
                    if !signals.is_empty() {
                        break;
                    }
                }
            }
        }

        // 2026-05-24 (FP fix) — baseline sqli header scanning (cookie /
        // referer / x-forwarded-for / user-agent) was REMOVED. It
        // false-positived on adtech cookies + telemetry user-agents (huge
        // token blobs), and header-borne sqli only matters when the app
        // interpolates a header into SQL — rare and app-specific. URL +
        // structured-body scanning remain.

        signals
    }
}

fn check_patterns(input: &str, field: &str, signals: &mut Vec<Signal>) {
    // HIGH — unambiguous SQLi, single-hit block.
    let hit = SQLI_HIGH.iter().any(|re| re.is_match(input))
        // AMBIGUOUS — only with a SQL line-comment corroborator in the same
        // field. `--` is the discriminator: a benign `concat(a,b)` / YQL
        // `SELECT…FROM` carries none, a real `1 ORDER BY 5--` does. (The
        // quoted-comment `'…--` form is already a HIGH pattern.)
        || (input.contains("--") && SQLI_AMBIGUOUS.iter().any(|re| re.is_match(input)));
    if hit {
        signals.push(Signal {
            score: super::scores::sqli::SQLI,
            tag: "sqli".into(),
            field: field.into(),
        });
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
    // SQ-2 (2026-07-07): `SELECT…FROM` / `UPDATE…SET` are AMBIGUOUS — the
    // realistic injection forms carry a `--` comment or a `';` stacked query,
    // so they still block; a bare `SELECT name FROM users` (analytics/YQL) no
    // longer does (see clean_select_from / clean_yql_select).
    positive_test!(sqli_select_from, "/?q=SELECT+name+FROM+users--");
    positive_test!(sqli_insert_into, "/?q=INSERT+INTO+logs+VALUES(1)");
    positive_test!(sqli_update_set, "/?q=1';UPDATE+users+SET+admin=1--");
    positive_test!(sqli_delete_from, "/?q=DELETE+FROM+sessions");
    positive_test!(sqli_alter_table, "/?q=ALTER+TABLE+users+ADD+col+INT");
    positive_test!(sqli_comment, "/?id=1'--");
    positive_test!(sqli_c_comment, "/?id=1/**/");
    positive_test!(sqli_waitfor, "/?id=1;WAITFOR+DELAY+'0:0:5'");
    // SQ-2: BENCHMARK/SLEEP/CHAR/CONCAT/EXEC/ORDER BY are AMBIGUOUS — the
    // realistic time-based / union / stacked forms carry a quote-comment or
    // `--`, so they still block; the bare function call no longer does.
    positive_test!(sqli_benchmark, "/?id=1'+AND+BENCHMARK(1000000,MD5(1))--");
    positive_test!(sqli_sleep, "/?id=1'+AND+SLEEP(5)--");
    positive_test!(sqli_load_file, "/?id=LOAD_FILE('/etc/passwd')");
    positive_test!(sqli_into_outfile, "/?q=INTO+OUTFILE+'/tmp/out'");
    positive_test!(sqli_exec, "/?q=1';EXEC+sp_help--");
    positive_test!(sqli_xp_cmdshell, "/?q=xp_cmdshell+'dir'");
    positive_test!(sqli_information_schema, "/?q=information_schema.tables");
    positive_test!(sqli_sys_objects, "/?q=sys.objects");
    positive_test!(sqli_char_func, "/?q=1+UNION+SELECT+CHAR(65)--");
    positive_test!(sqli_concat, "/?q=1+UNION+SELECT+CONCAT(u,p)--");
    positive_test!(sqli_group_by_having, "/?q=GROUP+BY+id+HAVING+1=1");
    positive_test!(sqli_order_by_num, "/?q=1+ORDER+BY+5--");
    positive_test!(sqli_case_when, "/?q=CASE+WHEN+1=1+THEN+1");
    positive_test!(sqli_extractvalue, "/?q=EXTRACTVALUE(1,1)");
    positive_test!(sqli_updatexml, "/?q=UPDATEXML(1,1,1)");
    positive_test!(sqli_and_1_eq_1, "/?id=1+AND+1=1");
    positive_test!(sqli_into_dumpfile, "/?q=INTO+DUMPFILE+'/tmp/x'");
    positive_test!(sqli_union_all_select, "/?q=UNION+ALL+SELECT+1,2,3");
    // S1 (2026-05-18) — decoder-evasion positives.
    // Each row is a payload that the single-pass `url_decode`
    // missed and `normalize_for_detection` now catches.
    positive_test!(sqli_double_url_encoded_union, "/?q=%2520UNION%2520SELECT%2520*%2520FROM%2520users");
    positive_test!(sqli_html_entity_quote, "/?q=&apos;+OR+1=1--");
    positive_test!(sqli_unicode_escape_quote, "/?q=\\u0027+OR+1=1--");
    positive_test!(sqli_hex_escape_quote, "/?q=\\x27+OR+1=1--");
    // 2026-06-16 (sec-regression §3a) — hex-string SQLi. The `0x…` blob
    // decodes to printable SQL that trips an existing rule once
    // `normalize_for_detection` runs the hex-blob pass. sqli-0096..0099.
    // `0x27206f7220313d31` = `' or 1=1`.
    positive_test!(sqli_hex_blob_or, "/?id=0x27206f7220313d31");
    // `0x27204f5220313d313d3d31` = `' OR 1=1==1` — quote + OR 1=1.
    positive_test!(sqli_hex_blob_or_upper, "/?id=0x27204f5220313d31");
    // 2026-06-16 (sec-regression §3a Evidence B) — trace fixtures for the
    // mixed-case / path-segment FNs. These confirm the DETECTOR fires for
    // the exact slipped shapes (the `(?i)` patterns + `+`/`%20` decode);
    // if they pass, any live FN is upstream (route/tier/decode), not here.
    positive_test!(sqli_mixed_case_or_page, "/api/list?page=1+oR+1=1");
    positive_test!(sqli_mixed_case_union_limit, "/api/list?limit=1+UnIoN+SeLeCt+1,2,3");
    positive_test!(sqli_mixed_case_order_by, "/api/list?sort=1+OrDeR+By+8--");
    positive_test!(sqli_path_segment_union, "/game/1%20uNiOn%20sElEcT%20pwd%20FROM%20users");
    positive_test!(sqli_mixed_case_waitfor, "/api?id=1;wAiTfOr+dElAy+'0:0:5'");

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
    // 2026-05-24 (FP fix) — corpus regressions.
    // Trailing `--` without a quote (IAB US-Privacy string) is data.
    negative_test!(clean_usp_string, "/sync?UICR=k-v21zQAxC5PD&us_privacy=1---");
    // `0x…` hex run (GPU id / hash / token) is no longer flagged.
    negative_test!(clean_hex_blob, "/sync?gpu=0x0000C0DE");
    negative_test!(clean_hash_param, "/t?sig=0xdeadbeefcafebabe");

    // FP-2026-07-07 (SQ-2) — function-name / clause-bridge patterns are now
    // AMBIGUOUS: they block only when corroborated by a SQL line-comment
    // (`--`) in the same field, so a benign standalone `concat(` / `char(` /
    // `sleep(` / `SELECT…FROM` (analytics, GraphQL, YQL) emits NO signal.
    negative_test!(clean_concat_func,   "/?q=CONCAT(first_name,last_name)");
    negative_test!(clean_char_func,     "/?q=CHAR(65)");
    negative_test!(clean_sleep_func,    "/?wait=sleep(100)");
    negative_test!(clean_order_by_num,  "/?p=ORDER+BY+2");
    negative_test!(clean_select_from,   "/?q=SELECT+title+FROM+catalog");
    negative_test!(clean_yql_select,    "/v2/public/yql?q=SELECT+*+FROM+weather+ORDER+BY+1");
    negative_test!(clean_exec_verb,     "/?q=EXEC+the+report");
    negative_test!(clean_benchmark,     "/?score=BENCHMARK(fast)");

    // FP-2026-07-07 (SQ-1) — bound the two greedy comment regexes.
    // A benign apostrophe (contraction/possessive) far from a later `--`
    // must not bridge into a string-breakout match; real breakout comments
    // (`admin'--`, `' OR 1=1--`) are short and still fire.
    negative_test!(clean_apostrophe_far_from_dashes,
        "/?comment=it%27s+a+long+benign+note+ending+in+a+dashed+separator+line+--");
    // A long C-style comment block (license header / doc block > 64 chars)
    // must not match; the short evasion `/**/` and `/*!…*/` still fire.
    negative_test!(clean_long_c_comment_block,
        "/?css=/*+long+license+header+block+that+exceeds+sixty+four+characters+of+comment+text+here+*/");

    // 2026-06-17 — the detector inspects an ORIGIN-FORM target (path+query);
    // the WAF strips the reconstructed `scheme://host` before detectors run.
    // The `sys.objects` label is a valid hostname token (dots only) AND a SQLi
    // pattern, so it proves the surface boundary: scanning the absolute URI
    // would flag the HOST (wrong surface / noise), but the origin-form target
    // the WAF hands the detector carries no host, so a clean host adds no
    // signal. A real payload in the path is still caught.
    #[test]
    fn host_is_not_part_of_the_inspected_target() {
        let d = SqliDetector;

        // The bug we prevent: the host token leaks into `uri.to_string()` when
        // the absolute URI is scanned.
        let (m, abs, h, b) =
            view_with_uri("https://sys.objects.evil.example/clean/path");
        assert!(
            !d.inspect(&make_view(&m, &abs, &h, &b)).is_empty(),
            "host token trips sqli when the absolute URI is scanned (the leak)",
        );

        // What the WAF actually hands the detector: origin-form, host stripped.
        let origin: http::Uri = abs
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .parse()
            .unwrap();
        assert!(
            !origin.to_string().contains("://"),
            "inspected target must carry no scheme://host prefix",
        );
        assert!(
            d.inspect(&make_view(&m, &origin, &h, &b)).is_empty(),
            "clean host adds no signal once stripped to origin-form",
        );
    }

    // 2026-05-24 (FP fix) — content-type gated body scanning.
    fn body_view(ct: Option<&str>, body: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        let mut h = http::HeaderMap::new();
        if let Some(ct) = ct {
            h.insert("content-type", ct.parse().unwrap());
        }
        (
            http::Method::POST,
            "/api/x".parse().unwrap(),
            h,
            BodyPeek::new(body.as_bytes().to_vec(), Some(body.len() as u64), false),
        )
    }

    #[test]
    fn body_scanned_when_json() {
        let d = SqliDetector;
        let (m, u, h, b) = body_view(Some("application/json"), r#"{"q":"1 UNION SELECT * FROM users"}"#);
        let req = make_view(&m, &u, &h, &b);
        assert!(!d.inspect(&req).is_empty(), "JSON body sqli must fire");
    }

    #[test]
    fn body_skipped_when_octet_stream() {
        let d = SqliDetector;
        let (m, u, h, b) = body_view(Some("application/octet-stream"), "x 0x0000C0DE UNION SELECT 1 FROM t");
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty(), "binary beacon body must be skipped");
    }

    #[test]
    fn body_skipped_when_no_content_type() {
        let d = SqliDetector;
        let (m, u, h, b) = body_view(None, "1 UNION SELECT * FROM users");
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty(), "missing content-type body must be skipped");
    }

    // ---- S2 (2026-06-18) form-body opaque-beacon gate ----

    fn blob() -> String {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .chars()
            .cycle()
            .take(320)
            .collect()
    }

    #[test]
    fn form_beacon_with_coincidental_sqli_is_skipped() {
        // A single huge opaque form value that coincidentally trips the
        // `'…--` string-breakout-comment rule — a bot sensor beacon, not
        // injection surface.
        let d = SqliDetector;
        let body = format!("sensor_data={}'z--", blob());
        let (m, u, h, b) = body_view(Some("application/x-www-form-urlencoded"), &body);
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty(), "opaque form beacon must be skipped");
    }

    #[test]
    fn real_sqli_in_normal_form_still_fires() {
        // Same trigger in a short, multi-field form → NOT a beacon →
        // still scanned and blocked.
        let d = SqliDetector;
        let (m, u, h, b) =
            body_view(Some("application/x-www-form-urlencoded"), "name=alice&q='z--");
        let req = make_view(&m, &u, &h, &b);
        assert!(!d.inspect(&req).is_empty(), "real sqli in normal form must fire");
    }

    #[test]
    fn text_plain_sensor_beacon_with_backtick_is_skipped() {
        // 2026-06-18 round-2 FP: text/plain `sensor_data` beacons contain
        // stray backticks (which made the gate's fast-path bail) AND a
        // coincidental `'…--` string-breakout-comment shape. The gate must
        // still classify the single-dominant high-entropy blob as a beacon.
        let d = SqliDetector;
        let body = format!("{{\"sensor_data\":\"{}q`x`w'z--\"}}", blob());
        let (m, u, h, b) = body_view(Some("text/plain;charset=UTF-8"), &body);
        let req = make_view(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).is_empty(),
            "text/plain sensor beacon with stray backtick must be skipped",
        );
    }

    /// LT-P2 (2026-07-03) — evaluated `RegexSet` single-pass as a
    /// replacement for the shipped `Vec<Regex>` + `.iter().any(is_match)`
    /// loop, and **rejected it**: on the dominant benign traffic the
    /// `regex` crate's per-`Regex` literal prefilter (memchr /
    /// Aho-Corasick) rejects each pattern in ~one pass, and a combined
    /// `RegexSet` automaton is measurably *slower* (~0.74× on a ~10 KB
    /// benign input). See `PLAN-ltester-perf-and-hardening-2026-07-03.md`
    /// LT-P2.
    ///
    /// This is an ignored regression guard, not a CI test — run
    /// explicitly to re-measure before anyone reopens LT-P2:
    ///   `cargo test -p aegis-security --release -- --ignored --nocapture regexset`
    /// It asserts only *correctness equivalence* (the two forms agree on
    /// every input) so it can never flake on timing; the ns/scan numbers
    /// are printed as evidence.
    #[test]
    #[ignore = "LT-P2 perf guard; run explicitly with --ignored --release"]
    fn regexset_evaluated_and_rejected_slower_than_vec_loop() {
        use regex::{Regex, RegexSet};
        use std::time::Instant;

        // Subset of the shipped sqli pattern source (representative).
        const SRC: &[&str] = &[
            r"(?i)(?:UNION\s+(?:ALL\s+)?SELECT)",
            r"(?i)(?:SELECT\s+.+\s+FROM\s+)",
            r"(?i)(?:INSERT\s+INTO\s+)",
            r"(?i)(?:DELETE\s+FROM\s+)",
            r"(?i)(?:DROP\s+TABLE\s+)",
            r"(?i)(?:OR\s+1\s*=\s*1)",
            r"(?i)(?:AND\s+1\s*=\s*1)",
            r"(?i)(?:WAITFOR\s+DELAY)",
            r"(?i)(?:BENCHMARK\s*\()",
            r"(?i)(?:SLEEP\s*\()",
            r"(?i)(?:information_schema)",
            r"(?i)(?:CHAR\s*\(\s*\d+\s*\))",
            r"(?i)(?:ORDER\s+BY\s+\d+)",
            r"(?i)(?:CASE\s+WHEN\s+)",
        ];
        let vec_re: Vec<Regex> = SRC.iter().map(|p| Regex::new(p).unwrap()).collect();
        let set = RegexSet::new(SRC).unwrap();

        // Correctness: the two forms agree on benign AND malicious inputs.
        for probe in [
            "María José München café resume text",          // benign
            "id=1 UNION SELECT * FROM users",                // union
            "q=1 OR 1=1",                                    // boolean
            "name=alice&note=hello world",                   // benign
            "x=BENCHMARK(1000,MD5('a'))",                    // timing
        ] {
            let vec_hit = vec_re.iter().any(|r| r.is_match(probe));
            assert_eq!(vec_hit, set.is_match(probe), "disagreement on {probe:?}");
        }

        // Timing evidence (printed, never asserted → no flake).
        let input = "María José München café ".repeat(400); // ~10 KB benign
        let iters = 20_000u32;
        let _ = vec_re.iter().any(|r| r.is_match(&input));
        let _ = set.is_match(&input);

        let t0 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(vec_re.iter().any(|r| r.is_match(std::hint::black_box(&input))));
        }
        let vec_ns = t0.elapsed().as_nanos() / iters as u128;

        let t1 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(set.is_match(std::hint::black_box(&input)));
        }
        let set_ns = t1.elapsed().as_nanos() / iters as u128;

        println!(
            "LT-P2 guard (~10KB benign, {} patterns, {iters} iters): \
             Vec<Regex> loop = {vec_ns} ns/scan, RegexSet = {set_ns} ns/scan, \
             RegexSet is {:.2}x the Vec-loop time (>1.0 = slower → keep Vec)",
            SRC.len(),
            set_ns as f64 / vec_ns.max(1) as f64,
        );
    }
}
