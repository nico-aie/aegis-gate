//! etcd v3 service discovery watcher (B2-T6 — Phase B).
//!
//! Polls a key prefix via etcd's REST gateway and emits
//! [`DiscoveryEvent`]s as members come and go.
//!
//! ## Why range polling, not gRPC Watch
//!
//! etcd's native API is gRPC. Pulling `tonic` + `prost` for one
//! Watch RPC would dominate the dep tree the same way the
//! google-cloud gRPC SDK would for B2-T3 (gcp). The v3 REST
//! gateway exposes the same operations over JSON; we POST to
//! `/v3/kv/range` every `poll_interval` (default 5s) and diff
//! the result against our last view. The trade-off is up to
//! `poll_interval` extra latency on a member change versus the
//! cleaner dep tree.
//!
//! A future task can add a streaming watcher under `etcd_grpc`
//! if real-time membership changes start mattering.
//!
//! ## Wire shape
//!
//! Each member is stored as `<prefix>/<id>` → `<addr>:<port>`.
//! Operators are responsible for writing the entries (typically
//! from each upstream member's startup hook). We read the
//! prefix range, parse `addr:port` from each value, and diff.
//!
//! ## Config (env)
//!
//! | Env | Required | Purpose |
//! |---|---|---|
//! | `AEGIS_ETCD_ENDPOINTS` | no (default `http://127.0.0.1:2379`) | Comma-separated list of etcd client URLs |
//! | `AEGIS_ETCD_USER` | no | Username for basic / token auth |
//! | `AEGIS_ETCD_PASSWORD` | no | Password (or token) for auth |
//! | `AEGIS_ETCD_CA_CERT_PATH` | no | PEM CA bundle for TLS |
//! | `AEGIS_ETCD_CLIENT_CERT_PATH` | no | Client cert for mTLS |
//! | `AEGIS_ETCD_CLIENT_KEY_PATH` | no | Client key for mTLS |
//! | `AEGIS_ETCD_POLL_INTERVAL_MS` | no (default 5000) | How often to range-poll, in milliseconds |

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{diff_members, DiscoveryEvent};

/// Default poll interval. 5s is the sweet spot — fast enough for
/// human-scale membership churn, slow enough that 100 nodes
/// querying the same etcd cluster don't hot-spot it.
const DEFAULT_POLL_MS: u64 = 5000;

/// Backoff bounds for transient errors.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Channel capacity for emitted events.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Resolved watcher config.
#[derive(Debug, Clone)]
pub struct EtcdConfig {
    pub endpoints: Vec<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub poll_interval: Duration,
}

impl EtcdConfig {
    /// Build from environment.
    pub fn from_env() -> Self {
        let endpoints = std::env::var("AEGIS_ETCD_ENDPOINTS")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.split(',')
                    .map(|e| e.trim().to_string())
                    .filter(|e| !e.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec!["http://127.0.0.1:2379".to_string()]);

        let poll_interval = std::env::var("AEGIS_ETCD_POLL_INTERVAL_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_millis(DEFAULT_POLL_MS));

        Self {
            endpoints,
            user: std::env::var("AEGIS_ETCD_USER")
                .ok()
                .filter(|s| !s.is_empty()),
            password: std::env::var("AEGIS_ETCD_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty()),
            ca_cert_path: std::env::var("AEGIS_ETCD_CA_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            client_cert_path: std::env::var("AEGIS_ETCD_CLIENT_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            client_key_path: std::env::var("AEGIS_ETCD_CLIENT_KEY_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            poll_interval,
        }
    }
}

/// Spawn a watcher task that observes `<prefix>/...` keys and
/// emits a discovery event for each value-shaped change.
/// `prefix` is the leading slash-separated path operators write
/// member entries under (e.g. `upstream/`). Trailing slash is
/// optional — the watcher inserts one if missing.
///
/// Returns the receiver half of the event channel; drop it to
/// stop the watcher (the task exits the next time it tries to
/// send).
pub fn watch(prefix: impl Into<String>) -> mpsc::Receiver<DiscoveryEvent> {
    let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let cfg = EtcdConfig::from_env();
    let mut prefix = prefix.into();
    if !prefix.ends_with('/') {
        prefix.push('/');
    }

    tokio::spawn(async move {
        if let Err(e) = run_watcher(cfg, prefix.clone(), tx).await {
            tracing::warn!(
                prefix = %prefix,
                error = %e,
                "etcd watcher exited",
            );
        }
    });

    rx
}

async fn run_watcher(
    cfg: EtcdConfig,
    prefix: String,
    tx: mpsc::Sender<DiscoveryEvent>,
) -> Result<(), String> {
    let http = build_client(&cfg)?;
    let mut last_members: HashSet<SocketAddr> = HashSet::new();
    let mut backoff = BACKOFF_MIN;
    let mut auth_token: Option<String> = None;

    loop {
        if tx.is_closed() {
            return Ok(());
        }

        match poll_once(&http, &cfg, &prefix, auth_token.as_deref()).await {
            Ok((members, refreshed_token)) => {
                let next: HashSet<SocketAddr> = members.into_iter().collect();
                for evt in diff_members(&last_members, &next) {
                    if tx.send(evt).await.is_err() {
                        return Ok(());
                    }
                }
                last_members = next;
                if let Some(t) = refreshed_token {
                    auth_token = Some(t);
                }
                backoff = BACKOFF_MIN;
                tokio::time::sleep(cfg.poll_interval).await;
            }
            Err(WatcherError::Auth(msg)) => {
                return Err(format!("etcd auth error (stopping): {msg}"));
            }
            Err(WatcherError::Transient(msg)) => {
                tracing::debug!(
                    prefix = %prefix,
                    backoff_ms = backoff.as_millis() as u64,
                    error = %msg,
                    "etcd poll transient error; backing off",
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

#[derive(Debug)]
enum WatcherError {
    Auth(String),
    Transient(String),
}

impl std::fmt::Display for WatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatcherError::Auth(m) => write!(f, "auth: {m}"),
            WatcherError::Transient(m) => write!(f, "transient: {m}"),
        }
    }
}

/// One range-query round-trip. Returns the parsed members + an
/// optional refreshed auth token (set on first successful auth).
async fn poll_once(
    http: &reqwest::Client,
    cfg: &EtcdConfig,
    prefix: &str,
    cached_token: Option<&str>,
) -> Result<(Vec<SocketAddr>, Option<String>), WatcherError> {
    // First call (no cached token, but creds set) — authenticate.
    let mut current_token = cached_token.map(|s| s.to_string());
    let refreshed_token = if current_token.is_none()
        && cfg.user.is_some()
        && cfg.password.is_some()
    {
        let token = authenticate(http, cfg).await?;
        current_token = Some(token.clone());
        Some(token)
    } else {
        None
    };

    let endpoint = cfg
        .endpoints
        .first()
        .ok_or_else(|| WatcherError::Transient("no endpoints configured".into()))?;

    let url = format!("{}/v3/kv/range", endpoint.trim_end_matches('/'));

    let body = RangeRequest {
        key: base64::engine::general_purpose::STANDARD.encode(prefix.as_bytes()),
        range_end: base64::engine::general_purpose::STANDARD
            .encode(prefix_to_range_end(prefix)),
    };

    let mut req = http.post(&url).json(&body);
    if let Some(token) = &current_token {
        req = req.header("Authorization", token);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| WatcherError::Transient(format!("transport: {e}")))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
    {
        let body = resp.text().await.unwrap_or_default();
        return Err(WatcherError::Auth(format!(
            "etcd returned {status}: {body} (check AEGIS_ETCD_USER + AEGIS_ETCD_PASSWORD)"
        )));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(WatcherError::Transient(format!(
            "etcd returned {status}: {body}"
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| WatcherError::Transient(format!("read body: {e}")))?;

    let members = parse_response(&body)
        .map_err(|e| WatcherError::Transient(format!("parse: {e}")))?;

    Ok((members, refreshed_token))
}

/// Authenticate against `/v3/auth/authenticate`. Returns the
/// token to send in subsequent requests' `Authorization` header.
async fn authenticate(
    http: &reqwest::Client,
    cfg: &EtcdConfig,
) -> Result<String, WatcherError> {
    let endpoint = cfg
        .endpoints
        .first()
        .ok_or_else(|| WatcherError::Transient("no endpoints configured".into()))?;

    let url = format!(
        "{}/v3/auth/authenticate",
        endpoint.trim_end_matches('/')
    );

    let body = AuthRequest {
        name: cfg.user.clone().unwrap_or_default(),
        password: cfg.password.clone().unwrap_or_default(),
    };

    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| WatcherError::Transient(format!("auth transport: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(WatcherError::Auth(format!(
            "etcd /authenticate returned {status}: {body}"
        )));
    }

    let parsed: AuthResponse = resp
        .json()
        .await
        .map_err(|e| WatcherError::Auth(format!("auth response not JSON: {e}")))?;
    Ok(parsed.token)
}

/// Compute the range-end for a prefix scan.
///
/// etcd's range query is open-ended: `[key, range_end)`. To
/// scan everything starting with `prefix`, set `range_end` to
/// `prefix` with the last byte incremented. e.g. `"foo/"` →
/// `"foo0"` (`/` is `0x2F`, `0` is `0x30`). On overflow (last
/// byte `0xFF`), shorten the prefix.
pub fn prefix_to_range_end(prefix: &str) -> Vec<u8> {
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(last) = bytes.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return bytes;
        }
        bytes.pop();
    }
    // Empty / all-0xFF prefix → unbounded range.
    Vec::new()
}

/// Parse an etcd v3 range response. Pure — usable from tests
/// without a live server.
pub fn parse_response(body: &str) -> Result<Vec<SocketAddr>, String> {
    let parsed: RangeResponse =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let mut out = Vec::new();
    for kv in parsed.kvs.unwrap_or_default() {
        // Values are base64-encoded `addr:port` strings.
        let value_bytes = base64::engine::general_purpose::STANDARD
            .decode(kv.value.as_bytes())
            .map_err(|e| format!("value base64 decode: {e}"))?;
        let value_str = std::str::from_utf8(&value_bytes)
            .map_err(|e| format!("value not UTF-8: {e}"))?;
        let socket: SocketAddr = value_str.trim().parse().map_err(|e| {
            format!("value {value_str:?} is not a valid addr:port: {e}")
        })?;
        out.push(socket);
    }
    Ok(out)
}

/// Build the HTTP client. Honors mTLS cert + key paths.
fn build_client(cfg: &EtcdConfig) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(15));

    if let Some(ca_path) = &cfg.ca_cert_path {
        let pem = std::fs::read(ca_path).map_err(|e| {
            format!("reading AEGIS_ETCD_CA_CERT_PATH={ca_path}: {e}")
        })?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| format!("parsing CA at {ca_path}: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }

    if let (Some(cert_path), Some(key_path)) =
        (&cfg.client_cert_path, &cfg.client_key_path)
    {
        let mut combined = std::fs::read(cert_path).map_err(|e| {
            format!("reading AEGIS_ETCD_CLIENT_CERT_PATH={cert_path}: {e}")
        })?;
        let mut key_pem = std::fs::read(key_path).map_err(|e| {
            format!("reading AEGIS_ETCD_CLIENT_KEY_PATH={key_path}: {e}")
        })?;
        // reqwest's Identity::from_pem expects cert+key concatenated.
        combined.extend_from_slice(b"\n");
        combined.append(&mut key_pem);
        let identity = reqwest::Identity::from_pem(&combined)
            .map_err(|e| format!("parsing client identity: {e}"))?;
        builder = builder.identity(identity);
    }

    builder
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

#[derive(Serialize)]
struct RangeRequest {
    key: String,
    range_end: String,
}

#[derive(Deserialize)]
struct RangeResponse {
    #[serde(default)]
    kvs: Option<Vec<KeyValue>>,
}

#[derive(Deserialize)]
struct KeyValue {
    #[allow(dead_code)]
    key: String,
    value: String,
}

#[derive(Serialize)]
struct AuthRequest {
    name: String,
    password: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process-wide mutex serialising tests that mutate the
    /// `AEGIS_ETCD_*` env vars. Same pattern as the consul tests.
    static ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    struct EnvGuard {
        prior: Vec<(String, Option<String>)>,
        _lock: parking_lot::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&str, Option<&str>)]) -> Self {
            let lock = ENV_LOCK.lock();
            let prior: Vec<(String, Option<String>)> = pairs
                .iter()
                .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
                .collect();
            for (k, v) in pairs {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            Self { prior, _lock: lock }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, prior) in &self.prior {
                match prior {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn config_defaults_when_no_env() {
        let _g = EnvGuard::set(&[
            ("AEGIS_ETCD_ENDPOINTS", None),
            ("AEGIS_ETCD_USER", None),
            ("AEGIS_ETCD_PASSWORD", None),
            ("AEGIS_ETCD_CA_CERT_PATH", None),
            ("AEGIS_ETCD_CLIENT_CERT_PATH", None),
            ("AEGIS_ETCD_CLIENT_KEY_PATH", None),
            ("AEGIS_ETCD_POLL_INTERVAL_MS", None),
        ]);
        let cfg = EtcdConfig::from_env();
        assert_eq!(cfg.endpoints, vec!["http://127.0.0.1:2379".to_string()]);
        assert!(cfg.user.is_none());
        assert!(cfg.password.is_none());
        assert!(cfg.ca_cert_path.is_none());
        assert_eq!(cfg.poll_interval, Duration::from_millis(DEFAULT_POLL_MS));
    }

    #[test]
    fn config_parses_comma_separated_endpoints() {
        let _g = EnvGuard::set(&[(
            "AEGIS_ETCD_ENDPOINTS",
            Some("http://e1:2379,http://e2:2379, http://e3:2379"),
        )]);
        let cfg = EtcdConfig::from_env();
        assert_eq!(
            cfg.endpoints,
            vec![
                "http://e1:2379".to_string(),
                "http://e2:2379".to_string(),
                "http://e3:2379".to_string(),
            ]
        );
    }

    #[test]
    fn config_filters_empty_endpoints_and_strings() {
        let _g = EnvGuard::set(&[
            ("AEGIS_ETCD_ENDPOINTS", Some("http://e1:2379,, ,http://e2:2379")),
            ("AEGIS_ETCD_USER", Some("")),
            ("AEGIS_ETCD_PASSWORD", Some("")),
        ]);
        let cfg = EtcdConfig::from_env();
        assert_eq!(
            cfg.endpoints,
            vec!["http://e1:2379".to_string(), "http://e2:2379".to_string()]
        );
        assert!(cfg.user.is_none());
        assert!(cfg.password.is_none());
    }

    #[test]
    fn config_parses_poll_interval() {
        let _g = EnvGuard::set(&[("AEGIS_ETCD_POLL_INTERVAL_MS", Some("750"))]);
        let cfg = EtcdConfig::from_env();
        assert_eq!(cfg.poll_interval, Duration::from_millis(750));
    }

    #[test]
    fn config_invalid_poll_interval_falls_back_to_default() {
        let _g = EnvGuard::set(&[("AEGIS_ETCD_POLL_INTERVAL_MS", Some("not-a-number"))]);
        let cfg = EtcdConfig::from_env();
        assert_eq!(cfg.poll_interval, Duration::from_millis(DEFAULT_POLL_MS));
    }

    #[test]
    fn prefix_to_range_end_simple() {
        // 'foo/' -> 'foo0' ('/' is 0x2F, 0x30 is '0')
        assert_eq!(prefix_to_range_end("foo/"), b"foo0");
    }

    #[test]
    fn prefix_to_range_end_unicode_terminator() {
        // U+007E '~' is the highest 1-byte ASCII that's still
        // < 0xFF — incrementing it stays in 1-byte range.
        assert_eq!(prefix_to_range_end("~"), b"\x7F");
    }

    #[test]
    fn prefix_to_range_end_empty_string_yields_empty_range() {
        // Edge case: empty prefix means "scan everything",
        // expressed as an empty range_end.
        assert!(prefix_to_range_end("").is_empty());
    }

    #[test]
    fn prefix_to_range_end_increments_last_ascii_byte() {
        assert_eq!(prefix_to_range_end("upstream/"), b"upstream0");
        assert_eq!(prefix_to_range_end("a"), b"b");
        assert_eq!(prefix_to_range_end("zzz"), b"zz{");
    }

    #[test]
    fn parse_empty_kv_set() {
        // Range response with no kvs (key omitted entirely is also
        // legal — etcd elides the field when empty).
        let body = r#"{}"#;
        let members = parse_response(body).unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn parse_single_member() {
        // value is base64 of "10.0.0.1:8080"
        let value = base64::engine::general_purpose::STANDARD
            .encode("10.0.0.1:8080".as_bytes());
        let key =
            base64::engine::general_purpose::STANDARD.encode("upstream/n1".as_bytes());
        let body = format!(
            r#"{{"kvs":[{{"key":"{key}","value":"{value}"}}]}}"#
        );
        let members = parse_response(&body).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0],
            "10.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_multiple_members() {
        let mk = |k: &str, v: &str| {
            format!(
                r#"{{"key":"{}","value":"{}"}}"#,
                base64::engine::general_purpose::STANDARD.encode(k.as_bytes()),
                base64::engine::general_purpose::STANDARD.encode(v.as_bytes())
            )
        };
        let body = format!(
            r#"{{"kvs":[{},{},{}]}}"#,
            mk("upstream/n1", "10.0.0.1:8080"),
            mk("upstream/n2", "10.0.0.2:8080"),
            mk("upstream/n3", "10.0.0.3:8080"),
        );
        let members = parse_response(&body).unwrap();
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn parse_value_not_addr_port_errors() {
        let value = base64::engine::general_purpose::STANDARD.encode("not-an-addr".as_bytes());
        let key =
            base64::engine::general_purpose::STANDARD.encode("upstream/n1".as_bytes());
        let body = format!(
            r#"{{"kvs":[{{"key":"{key}","value":"{value}"}}]}}"#
        );
        let err = parse_response(&body).unwrap_err();
        assert!(err.contains("addr:port"), "got: {err}");
    }

    #[test]
    fn parse_value_not_base64_errors() {
        // value field set to a non-base64 string
        let key =
            base64::engine::general_purpose::STANDARD.encode("upstream/n1".as_bytes());
        let body = format!(
            r#"{{"kvs":[{{"key":"{key}","value":"!!!not-base64!!!"}}]}}"#
        );
        let err = parse_response(&body).unwrap_err();
        assert!(err.contains("base64"), "got: {err}");
    }

    #[test]
    fn parse_value_not_utf8_errors() {
        // 0xFF is not valid UTF-8 start byte.
        let value = base64::engine::general_purpose::STANDARD.encode([0xFFu8, 0xFE, 0xFD]);
        let key =
            base64::engine::general_purpose::STANDARD.encode("upstream/n1".as_bytes());
        let body = format!(
            r#"{{"kvs":[{{"key":"{key}","value":"{value}"}}]}}"#
        );
        let err = parse_response(&body).unwrap_err();
        assert!(err.contains("UTF-8"), "got: {err}");
    }

    #[test]
    fn parse_invalid_json_errors() {
        let err = parse_response("not json").unwrap_err();
        assert!(err.contains("invalid JSON"), "got: {err}");
    }

    #[test]
    fn diff_first_observation_is_all_added() {
        let old = HashSet::new();
        let new: HashSet<SocketAddr> = [
            "10.0.0.1:8080".parse().unwrap(),
            "10.0.0.2:8080".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let events = diff_members(&old, &new);
        assert_eq!(events.len(), 2);
    }

    /// Live integration test gated by an explicit opt-in env
    /// var. Run with:
    ///
    /// ```sh
    /// AEGIS_ETCD_INTEGRATION_TEST=1 \
    /// AEGIS_ETCD_ENDPOINTS=http://127.0.0.1:2379 \
    ///   cargo test -p aegis-proxy --features etcd \
    ///     --lib sd::etcd::tests::live_etcd_watch
    /// ```
    ///
    /// The dev compose's etcd service is reachable on
    /// `127.0.0.1:2379` when up. This test writes one
    /// `/upstream/test-N` key, watches the prefix, and asserts
    /// the `Added` event arrives within the poll interval.
    #[tokio::test]
    async fn live_etcd_watch() {
        if std::env::var("AEGIS_ETCD_INTEGRATION_TEST").is_err() {
            eprintln!(
                "[sd::etcd] skipped — set AEGIS_ETCD_INTEGRATION_TEST=1 to run"
            );
            return;
        }
        let mut rx = watch("upstream/");
        // An operator running this test should pre-populate
        // /upstream/test-1 with `127.0.0.1:9999` (or whatever).
        // We poll up to 15s — accommodates the default 5s interval.
        let event = tokio::time::timeout(Duration::from_secs(15), rx.recv())
            .await
            .expect("watcher should emit within 15s")
            .expect("channel should be open");
        match event {
            DiscoveryEvent::Added(_) => {}
            other => panic!("expected Added on first observation, got {other:?}"),
        }
    }
}
