//! TAXII 2.1 client + background fetcher loop.
//!
//! Pulls STIX 2.1 indicator objects from a TAXII 2.1 collection
//! and feeds them into [`ThreatIntelStore`]. Lossy by design:
//! patterns we can't decode are skipped (logged, not erroring).
//!
//! # Lease gating
//!
//! The fetcher loop is **not** lease-gated by this module. The
//! wrap belongs at the boot site (`aegis-bin` / `aegis-proxy`
//! `run`) — same pattern as ACME and the gitops poll driver.
//! Only one node per cluster should fetch.
//!
//! # Pattern decoding
//!
//! STIX 2.1 patterns we recognise:
//! - `[ipv4-addr:value = '1.2.3.4']`         → IP
//! - `[ipv6-addr:value = '2001:db8::1']`     → IP
//! - `[domain-name:value = 'evil.test']`     → Domain
//! - `[url:value = 'http://evil.test/x']`    → URL
//! - `[file:hashes.'SHA-256' = '<hex>']`     → SHA-256
//! - `[file:hashes.SHA256 = '<hex>']`        → SHA-256 (alt)
//!
//! Composite patterns (`AND` / `OR`) are decoded by extracting
//! every recognised leaf, so a single STIX object may yield
//! multiple [`Indicator`]s.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{Indicator, IndicatorType, Severity, ThreatIntelStore};

/// Authentication for the TAXII server.
#[derive(Clone, Debug)]
pub enum TaxiiAuth {
    /// No authentication header — public collection.
    None,
    /// HTTP Basic — `Authorization: Basic base64(user:pass)`.
    Basic { username: String, password: String },
    /// HTTP Bearer — `Authorization: Bearer <token>`.
    Bearer { token: String },
}

/// Configuration for one TAXII feed.
#[derive(Clone, Debug)]
pub struct TaxiiConfig {
    /// API root URL — e.g. `https://taxii.example.org/api/`.
    /// Trailing slash is normalised by the client.
    pub api_root: String,
    /// Collection ID inside the API root.
    pub collection_id: String,
    /// Auth header.
    pub auth: TaxiiAuth,
    /// Poll interval. Default 15min.
    pub poll_interval: Duration,
    /// Per-call HTTP timeout. Default 30s.
    pub request_timeout: Duration,
    /// Confidence assigned to indicators that don't carry one.
    pub default_confidence: u8,
    /// Severity assigned to indicators that don't carry one.
    pub default_severity: Severity,
    /// TTL for indicators ingested from this feed.
    pub default_ttl: Duration,
    /// Feed ID stamped on every ingested [`Indicator`].
    pub feed_id: String,
}

impl Default for TaxiiConfig {
    fn default() -> Self {
        Self {
            api_root: String::new(),
            collection_id: String::new(),
            auth: TaxiiAuth::None,
            poll_interval: Duration::from_secs(900),
            request_timeout: Duration::from_secs(30),
            default_confidence: 75,
            default_severity: Severity::Medium,
            default_ttl: Duration::from_secs(86_400),
            feed_id: "taxii".to_string(),
        }
    }
}

/// Errors surfaced by the TAXII client + fetcher.
#[derive(Debug)]
pub enum TaxiiError {
    /// Config invalid — missing field or unparseable.
    Config(String),
    /// HTTP request failed (network, TLS, etc.).
    Http(String),
    /// Server returned a non-2xx status with this body excerpt.
    Status { code: u16, body: String },
    /// Response body was not valid TAXII 2.1 JSON.
    Decode(String),
}

impl std::fmt::Display for TaxiiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaxiiError::Config(m) => write!(f, "taxii config error: {m}"),
            TaxiiError::Http(m) => write!(f, "taxii http error: {m}"),
            TaxiiError::Status { code, body } => {
                write!(f, "taxii server returned {code}: {body}")
            }
            TaxiiError::Decode(m) => write!(f, "taxii decode error: {m}"),
        }
    }
}

impl std::error::Error for TaxiiError {}

/// One page of TAXII objects.
#[derive(Debug, Clone)]
pub struct TaxiiPage {
    /// Raw STIX objects.
    pub objects: Vec<Value>,
    /// `true` if the server has more pages for this query.
    pub more: bool,
    /// Opaque pagination cursor — pass to the next call.
    pub next: Option<String>,
}

/// TAXII 2.1 client.
pub struct TaxiiClient {
    cfg: TaxiiConfig,
    http: reqwest::Client,
}

impl TaxiiClient {
    pub fn new(cfg: TaxiiConfig) -> Result<Self, TaxiiError> {
        if cfg.api_root.is_empty() {
            return Err(TaxiiError::Config("api_root is empty".into()));
        }
        if cfg.collection_id.is_empty() {
            return Err(TaxiiError::Config("collection_id is empty".into()));
        }
        let http = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .user_agent("aegis-gate-taxii/1.0")
            .build()
            .map_err(|e| TaxiiError::Http(e.to_string()))?;
        Ok(Self { cfg, http })
    }

    /// Fetch one page of objects.
    ///
    /// `added_after` filters server-side to objects added strictly
    /// after the given timestamp; `next` carries the pagination
    /// cursor between calls.
    pub async fn fetch_page(
        &self,
        added_after: Option<DateTime<Utc>>,
        next: Option<&str>,
    ) -> Result<TaxiiPage, TaxiiError> {
        let url = build_objects_url(&self.cfg.api_root, &self.cfg.collection_id, added_after, next);
        let mut req = self
            .http
            .get(&url)
            .header("Accept", "application/taxii+json;version=2.1");
        req = match &self.cfg.auth {
            TaxiiAuth::None => req,
            TaxiiAuth::Basic { username, password } => req.basic_auth(username, Some(password)),
            TaxiiAuth::Bearer { token } => req.bearer_auth(token),
        };
        let resp = req
            .send()
            .await
            .map_err(|e| TaxiiError::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(TaxiiError::Status {
                code: status.as_u16(),
                body: truncate(&body, 512),
            });
        }
        let body = resp
            .text()
            .await
            .map_err(|e| TaxiiError::Http(e.to_string()))?;
        parse_envelope(&body)
    }
}

/// Build the GET URL for the `objects/` endpoint.
pub fn build_objects_url(
    api_root: &str,
    collection_id: &str,
    added_after: Option<DateTime<Utc>>,
    next: Option<&str>,
) -> String {
    let trimmed = api_root.trim_end_matches('/');
    let mut url = format!("{trimmed}/collections/{collection_id}/objects/");
    let mut params: Vec<String> = Vec::new();
    if let Some(ts) = added_after {
        params.push(format!(
            "added_after={}",
            ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ));
    }
    if let Some(token) = next {
        if !token.is_empty() {
            params.push(format!("next={}", urlencode_param(token)));
        }
    }
    if !params.is_empty() {
        url.push('?');
        url.push_str(&params.join("&"));
    }
    url
}

/// Decode the TAXII envelope `{ objects, more, next }`.
pub fn parse_envelope(body: &str) -> Result<TaxiiPage, TaxiiError> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| TaxiiError::Decode(format!("invalid json: {e}")))?;
    let objects = v
        .get("objects")
        .and_then(|o| o.as_array())
        .cloned()
        .unwrap_or_default();
    let more = v.get("more").and_then(|m| m.as_bool()).unwrap_or(false);
    let next = v
        .get("next")
        .and_then(|n| n.as_str())
        .map(|s| s.to_string());
    Ok(TaxiiPage {
        objects,
        more,
        next,
    })
}

/// Parsed leaf indicator extracted from a STIX 2.1 pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedIoc {
    Ip(String),
    Domain(String),
    Url(String),
    Sha256(String),
}

/// Extract every recognised IoC from a STIX 2.1 pattern string.
///
/// Lossy: patterns we don't recognise yield an empty vec rather
/// than erroring. The TAXII contract is "skip what you can't
/// understand, ingest what you can".
pub fn parse_pattern(pattern: &str) -> Vec<ParsedIoc> {
    let mut out = Vec::new();
    // Each leaf inside [ ... ] is parsed independently. We scan
    // for `[ ... ]` segments rather than a full lexer because
    // STIX 2.1 patterns range from trivial to very deeply nested
    // and a regex catches the common cases without dragging in
    // a dedicated parser dep.
    let mut rest = pattern;
    while let Some(start) = rest.find('[') {
        let after = &rest[start + 1..];
        let Some(end_rel) = after.find(']') else { break };
        let inner = &after[..end_rel];
        for leaf in inner.split(" OR ").flat_map(|s| s.split(" AND ")) {
            if let Some(ioc) = parse_leaf(leaf.trim()) {
                out.push(ioc);
            }
        }
        rest = &after[end_rel + 1..];
    }
    out
}

/// Parse a single STIX leaf, e.g. `ipv4-addr:value = '1.2.3.4'`.
pub fn parse_leaf(leaf: &str) -> Option<ParsedIoc> {
    let (path, raw_value) = leaf.split_once('=')?;
    let path = path.trim();
    let value = unquote(raw_value.trim())?;
    if path.eq_ignore_ascii_case("ipv4-addr:value")
        || path.eq_ignore_ascii_case("ipv6-addr:value")
    {
        return Some(ParsedIoc::Ip(value));
    }
    if path.eq_ignore_ascii_case("domain-name:value") {
        return Some(ParsedIoc::Domain(value));
    }
    if path.eq_ignore_ascii_case("url:value") {
        return Some(ParsedIoc::Url(value));
    }
    // file:hashes.'SHA-256' = '<hex>' or file:hashes.SHA256 = '<hex>'
    if path.starts_with("file:hashes") && is_sha256_path(path) {
        return Some(ParsedIoc::Sha256(value));
    }
    None
}

fn is_sha256_path(path: &str) -> bool {
    let tail = path.trim_start_matches("file:hashes");
    let tail = tail.trim_start_matches('.');
    let tail = tail.trim_matches('\'').trim_matches('"');
    tail.eq_ignore_ascii_case("sha-256") || tail.eq_ignore_ascii_case("sha256")
}

fn unquote(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && (bytes[0] == b'\'' || bytes[0] == b'"') && bytes[0] == bytes[bytes.len() - 1] {
        Some(s[1..s.len() - 1].to_string())
    } else {
        None
    }
}

/// Turn a STIX 2.1 indicator object into one or more [`Indicator`]s.
///
/// Only objects with `type = "indicator"` and a parseable
/// `pattern` produce output; everything else (relationships,
/// identities, malware, …) is dropped silently.
pub fn stix_object_to_indicators(obj: &Value, cfg: &TaxiiConfig) -> Vec<Indicator> {
    if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
        return Vec::new();
    }
    let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) else {
        return Vec::new();
    };
    let confidence = obj
        .get("confidence")
        .and_then(|c| c.as_u64())
        .map(|c| c.min(100) as u8)
        .unwrap_or(cfg.default_confidence);
    // STIX `severity` is x-mitre-attack-spec only; map STIX 2.1
    // labels (low / medium / high / critical) when present.
    let severity = obj
        .get("severity")
        .and_then(|s| s.as_str())
        .and_then(parse_severity_label)
        .unwrap_or(cfg.default_severity);
    let now = Instant::now();
    let expires_at = now + cfg.default_ttl;
    let mut out = Vec::new();
    for ioc in parse_pattern(pattern) {
        let (value, indicator_type) = match ioc {
            ParsedIoc::Ip(v) => (v, IndicatorType::Ip),
            ParsedIoc::Domain(v) => (v, IndicatorType::Domain),
            ParsedIoc::Url(v) => (v, IndicatorType::Url),
            ParsedIoc::Sha256(v) => (v, IndicatorType::Sha256),
        };
        out.push(Indicator {
            value,
            indicator_type,
            confidence,
            severity,
            feed_id: cfg.feed_id.clone(),
            expires_at,
        });
    }
    out
}

fn parse_severity_label(label: &str) -> Option<Severity> {
    match label.to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Spawn a background task that polls one TAXII collection on
/// `cfg.poll_interval` and ingests every yielded indicator into
/// the supplied store. Returns immediately. Drop the returned
/// [`tokio::task::JoinHandle`] to detach; abort it to stop the
/// loop.
///
/// Cancellation: this function honours `tokio::select!` style
/// shutdown if you wrap it externally — the loop itself runs
/// until aborted. Network and decode errors are logged and
/// retried on the next interval; transient 5xx triggers a short
/// exponential backoff (capped at the poll interval).
pub fn spawn_fetcher(
    store: Arc<ThreatIntelStore>,
    cfg: TaxiiConfig,
) -> Result<tokio::task::JoinHandle<()>, TaxiiError> {
    let client = TaxiiClient::new(cfg.clone())?;
    Ok(tokio::spawn(async move {
        run_fetch_loop(client, store, cfg).await;
    }))
}

async fn run_fetch_loop(
    client: TaxiiClient,
    store: Arc<ThreatIntelStore>,
    cfg: TaxiiConfig,
) {
    let mut backoff = Duration::from_secs(1);
    let mut added_after: Option<DateTime<Utc>> = None;
    loop {
        match drain_all_pages(&client, added_after).await {
            Ok(objects) => {
                let count = ingest_objects(&objects, &cfg, &store);
                tracing::info!(
                    feed = %cfg.feed_id,
                    fetched = objects.len(),
                    ingested = count,
                    "taxii poll cycle done"
                );
                added_after = Some(Utc::now());
                backoff = Duration::from_secs(1);
                tokio::time::sleep(cfg.poll_interval).await;
            }
            Err(e) => {
                tracing::warn!(feed = %cfg.feed_id, error = %e, "taxii poll cycle failed");
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff, cfg.poll_interval);
            }
        }
    }
}

async fn drain_all_pages(
    client: &TaxiiClient,
    added_after: Option<DateTime<Utc>>,
) -> Result<Vec<Value>, TaxiiError> {
    let mut all = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let page = client.fetch_page(added_after, next.as_deref()).await?;
        all.extend(page.objects);
        if !page.more {
            break;
        }
        match page.next {
            Some(n) if !n.is_empty() => next = Some(n),
            _ => break,
        }
    }
    Ok(all)
}

/// Convert every recognised STIX object in `objects` into
/// indicators and ingest them into the store. Returns the count
/// of indicators ingested (may be larger than `objects.len()`
/// when one STIX pattern carries multiple IoCs).
pub fn ingest_objects(
    objects: &[Value],
    cfg: &TaxiiConfig,
    store: &ThreatIntelStore,
) -> usize {
    let mut count = 0;
    for obj in objects {
        for ind in stix_object_to_indicators(obj, cfg) {
            store.ingest(ind);
            count += 1;
        }
    }
    count
}

fn next_backoff(current: Duration, ceiling: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > ceiling {
        ceiling
    } else {
        doubled
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

fn urlencode_param(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TaxiiConfig {
        TaxiiConfig {
            api_root: "https://taxii.example.org/api".into(),
            collection_id: "abc-123".into(),
            feed_id: "test-feed".into(),
            ..Default::default()
        }
    }

    // ---- URL building ----

    #[test]
    fn build_url_no_params() {
        let url = build_objects_url("https://taxii.example.org/api/", "abc", None, None);
        assert_eq!(
            url,
            "https://taxii.example.org/api/collections/abc/objects/"
        );
    }

    #[test]
    fn build_url_strips_trailing_slash_from_root() {
        let url = build_objects_url("https://taxii.example.org/api/", "abc", None, None);
        let url2 = build_objects_url("https://taxii.example.org/api", "abc", None, None);
        assert_eq!(url, url2);
    }

    #[test]
    fn build_url_with_added_after() {
        let ts = DateTime::parse_from_rfc3339("2024-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&Utc);
        let url = build_objects_url("https://t/api", "c", Some(ts), None);
        assert!(url.ends_with("?added_after=2024-01-02T03:04:05Z"), "{url}");
    }

    #[test]
    fn build_url_encodes_next_token() {
        let url = build_objects_url("https://t/api", "c", None, Some("a/b c=d"));
        assert!(url.ends_with("?next=a%2Fb%20c%3Dd"), "{url}");
    }

    #[test]
    fn build_url_combines_added_after_and_next() {
        let ts = DateTime::parse_from_rfc3339("2024-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&Utc);
        let url = build_objects_url("https://t/api", "c", Some(ts), Some("page2"));
        assert!(url.contains("added_after="), "{url}");
        assert!(url.contains("&next=page2"), "{url}");
    }

    // ---- Envelope decode ----

    #[test]
    fn parse_envelope_minimal() {
        let body = r#"{"objects":[],"more":false}"#;
        let page = parse_envelope(body).unwrap();
        assert!(page.objects.is_empty());
        assert!(!page.more);
        assert!(page.next.is_none());
    }

    #[test]
    fn parse_envelope_with_more_and_next() {
        let body =
            r#"{"objects":[{"type":"indicator","id":"a"}],"more":true,"next":"cursor-2"}"#;
        let page = parse_envelope(body).unwrap();
        assert_eq!(page.objects.len(), 1);
        assert!(page.more);
        assert_eq!(page.next.as_deref(), Some("cursor-2"));
    }

    #[test]
    fn parse_envelope_invalid_json_errors() {
        let err = parse_envelope("not-json").unwrap_err();
        match err {
            TaxiiError::Decode(_) => {}
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[test]
    fn parse_envelope_missing_objects_yields_empty() {
        let page = parse_envelope("{}").unwrap();
        assert!(page.objects.is_empty());
    }

    // ---- Pattern parsing ----

    #[test]
    fn parse_leaf_ipv4() {
        assert_eq!(
            parse_leaf("ipv4-addr:value = '1.2.3.4'"),
            Some(ParsedIoc::Ip("1.2.3.4".into()))
        );
    }

    #[test]
    fn parse_leaf_ipv6() {
        assert_eq!(
            parse_leaf("ipv6-addr:value = '2001:db8::1'"),
            Some(ParsedIoc::Ip("2001:db8::1".into()))
        );
    }

    #[test]
    fn parse_leaf_domain() {
        assert_eq!(
            parse_leaf("domain-name:value = 'evil.example.com'"),
            Some(ParsedIoc::Domain("evil.example.com".into()))
        );
    }

    #[test]
    fn parse_leaf_url() {
        assert_eq!(
            parse_leaf("url:value = 'http://evil.test/x'"),
            Some(ParsedIoc::Url("http://evil.test/x".into()))
        );
    }

    #[test]
    fn parse_leaf_sha256_quoted() {
        let h = "a".repeat(64);
        assert_eq!(
            parse_leaf(&format!("file:hashes.'SHA-256' = '{h}'")),
            Some(ParsedIoc::Sha256(h))
        );
    }

    #[test]
    fn parse_leaf_sha256_unquoted_alt() {
        let h = "b".repeat(64);
        assert_eq!(
            parse_leaf(&format!("file:hashes.SHA256 = '{h}'")),
            Some(ParsedIoc::Sha256(h))
        );
    }

    #[test]
    fn parse_leaf_unknown_path_yields_none() {
        assert!(parse_leaf("network-traffic:src_ref.value = '1.2.3.4'").is_none());
    }

    #[test]
    fn parse_leaf_double_quoted_value() {
        assert_eq!(
            parse_leaf(r#"ipv4-addr:value = "1.2.3.4""#),
            Some(ParsedIoc::Ip("1.2.3.4".into()))
        );
    }

    #[test]
    fn parse_leaf_unquoted_value_yields_none() {
        // STIX values must be quoted; a bare token is invalid.
        assert!(parse_leaf("ipv4-addr:value = 1.2.3.4").is_none());
    }

    #[test]
    fn parse_pattern_simple_bracket() {
        let pat = "[ipv4-addr:value = '1.2.3.4']";
        assert_eq!(
            parse_pattern(pat),
            vec![ParsedIoc::Ip("1.2.3.4".into())]
        );
    }

    #[test]
    fn parse_pattern_or_inside_brackets() {
        let pat = "[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']";
        let got = parse_pattern(pat);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&ParsedIoc::Ip("1.2.3.4".into())));
        assert!(got.contains(&ParsedIoc::Ip("5.6.7.8".into())));
    }

    #[test]
    fn parse_pattern_ignores_unknown_fields() {
        let pat = "[file:size = 1234 AND file:hashes.SHA256 = 'aa']";
        assert_eq!(parse_pattern(pat), vec![ParsedIoc::Sha256("aa".into())]);
    }

    #[test]
    fn parse_pattern_empty_returns_empty() {
        assert!(parse_pattern("").is_empty());
    }

    #[test]
    fn parse_pattern_unbalanced_bracket_safe() {
        // Unbalanced `[` must not panic; we just stop scanning.
        assert!(parse_pattern("[ipv4-addr:value = '1.2.3.4'").is_empty());
    }

    // ---- STIX object → Indicator ----

    #[test]
    fn stix_object_indicator_basic() {
        let obj: Value = serde_json::from_str(
            r#"{
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "confidence": 90,
                "severity": "high"
            }"#,
        )
        .unwrap();
        let inds = stix_object_to_indicators(&obj, &cfg());
        assert_eq!(inds.len(), 1);
        let ind = &inds[0];
        assert_eq!(ind.value, "1.2.3.4");
        assert_eq!(ind.indicator_type, IndicatorType::Ip);
        assert_eq!(ind.confidence, 90);
        assert_eq!(ind.severity, Severity::High);
        assert_eq!(ind.feed_id, "test-feed");
    }

    #[test]
    fn stix_object_uses_defaults_when_missing() {
        let obj: Value = serde_json::from_str(
            r#"{"type":"indicator","id":"x","pattern":"[domain-name:value = 'a.test']"}"#,
        )
        .unwrap();
        let mut c = cfg();
        c.default_confidence = 60;
        c.default_severity = Severity::Low;
        let inds = stix_object_to_indicators(&obj, &c);
        assert_eq!(inds.len(), 1);
        assert_eq!(inds[0].confidence, 60);
        assert_eq!(inds[0].severity, Severity::Low);
    }

    #[test]
    fn stix_non_indicator_objects_skipped() {
        let obj: Value = serde_json::from_str(
            r#"{"type":"identity","id":"identity--1","name":"Acme"}"#,
        )
        .unwrap();
        assert!(stix_object_to_indicators(&obj, &cfg()).is_empty());
    }

    #[test]
    fn stix_indicator_without_pattern_skipped() {
        let obj: Value =
            serde_json::from_str(r#"{"type":"indicator","id":"x"}"#).unwrap();
        assert!(stix_object_to_indicators(&obj, &cfg()).is_empty());
    }

    #[test]
    fn stix_compound_pattern_yields_multiple_indicators() {
        let obj: Value = serde_json::from_str(
            r#"{
                "type": "indicator",
                "id": "indicator--c",
                "pattern": "[ipv4-addr:value = '1.1.1.1' OR domain-name:value = 'x.test']"
            }"#,
        )
        .unwrap();
        let inds = stix_object_to_indicators(&obj, &cfg());
        assert_eq!(inds.len(), 2);
    }

    #[test]
    fn stix_confidence_clamped_to_100() {
        let obj: Value = serde_json::from_str(
            r#"{"type":"indicator","id":"x","pattern":"[ipv4-addr:value = '1.2.3.4']","confidence":250}"#,
        )
        .unwrap();
        let inds = stix_object_to_indicators(&obj, &cfg());
        assert_eq!(inds[0].confidence, 100);
    }

    // ---- Ingest pipeline ----

    #[test]
    fn ingest_objects_writes_to_store() {
        let store = ThreatIntelStore::default();
        let objs: Vec<Value> = vec![
            serde_json::from_str(
                r#"{"type":"indicator","id":"a","pattern":"[ipv4-addr:value = '1.2.3.4']"}"#,
            )
            .unwrap(),
            serde_json::from_str(
                r#"{"type":"indicator","id":"b","pattern":"[domain-name:value = 'evil.test']"}"#,
            )
            .unwrap(),
        ];
        let n = ingest_objects(&objs, &cfg(), &store);
        assert_eq!(n, 2);
        assert_eq!(store.indicator_count(), 2);
        assert!(store.check_ip("1.2.3.4".parse().unwrap()).is_some());
        assert!(store.check_domain("evil.test").is_some());
    }

    #[test]
    fn ingest_objects_skips_non_indicator() {
        let store = ThreatIntelStore::default();
        let objs: Vec<Value> = vec![
            serde_json::from_str(r#"{"type":"identity","id":"id--1","name":"a"}"#).unwrap(),
        ];
        assert_eq!(ingest_objects(&objs, &cfg(), &store), 0);
        assert_eq!(store.indicator_count(), 0);
    }

    // ---- Backoff ----

    #[test]
    fn next_backoff_doubles() {
        assert_eq!(
            next_backoff(Duration::from_secs(2), Duration::from_secs(60)),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn next_backoff_caps_at_ceiling() {
        assert_eq!(
            next_backoff(Duration::from_secs(40), Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    // ---- urlencode ----

    #[test]
    fn urlencode_passes_unreserved() {
        assert_eq!(urlencode_param("AZaz09-_.~"), "AZaz09-_.~");
    }

    #[test]
    fn urlencode_encodes_special() {
        assert_eq!(urlencode_param("a/b c=d&e"), "a%2Fb%20c%3Dd%26e");
    }

    // ---- Client construction ----

    #[test]
    fn client_rejects_empty_api_root() {
        let c = TaxiiConfig {
            api_root: "".into(),
            collection_id: "x".into(),
            ..Default::default()
        };
        let err = TaxiiClient::new(c).err().expect("should error");
        assert!(matches!(err, TaxiiError::Config(_)), "got {err}");
    }

    #[test]
    fn client_rejects_empty_collection() {
        let c = TaxiiConfig {
            api_root: "https://t/api".into(),
            collection_id: "".into(),
            ..Default::default()
        };
        let err = TaxiiClient::new(c).err().expect("should error");
        assert!(matches!(err, TaxiiError::Config(_)), "got {err}");
    }

    // ---- Live test (gated) ----

    /// Live integration test. Run with:
    ///
    ///   AEGIS_TAXII_INTEGRATION_TEST=1 \
    ///   AEGIS_TAXII_API_ROOT=https://... \
    ///   AEGIS_TAXII_COLLECTION_ID=... \
    ///   cargo test -p aegis-security --features taxii --lib \
    ///       threat_intel::taxii::tests::live_taxii_fetch -- --nocapture
    #[tokio::test]
    async fn live_taxii_fetch() {
        if std::env::var("AEGIS_TAXII_INTEGRATION_TEST").is_err() {
            eprintln!("skipping live_taxii_fetch — set AEGIS_TAXII_INTEGRATION_TEST=1 to run");
            return;
        }
        let api_root = std::env::var("AEGIS_TAXII_API_ROOT")
            .expect("AEGIS_TAXII_API_ROOT must be set for live test");
        let collection_id = std::env::var("AEGIS_TAXII_COLLECTION_ID")
            .expect("AEGIS_TAXII_COLLECTION_ID must be set for live test");
        let auth = match (
            std::env::var("AEGIS_TAXII_USERNAME").ok(),
            std::env::var("AEGIS_TAXII_PASSWORD").ok(),
            std::env::var("AEGIS_TAXII_BEARER").ok(),
        ) {
            (_, _, Some(t)) => TaxiiAuth::Bearer { token: t },
            (Some(u), Some(p), _) => TaxiiAuth::Basic {
                username: u,
                password: p,
            },
            _ => TaxiiAuth::None,
        };
        let cfg = TaxiiConfig {
            api_root,
            collection_id,
            auth,
            feed_id: "live".into(),
            ..Default::default()
        };
        let client = TaxiiClient::new(cfg).expect("client builds");
        let page = client.fetch_page(None, None).await.expect("page fetched");
        eprintln!("live: got {} objects, more={}", page.objects.len(), page.more);
    }
}
