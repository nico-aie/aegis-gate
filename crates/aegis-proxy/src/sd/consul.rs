//! Consul service discovery watcher (B2-T5 — Phase B).
//!
//! Watches a service via Consul's blocking-query API and emits
//! [`DiscoveryEvent`]s on a channel as members come and go.
//!
//! ## Wire protocol
//!
//! Consul exposes a long-poll on `/v1/health/service/<name>`:
//! pass `index=<last-seen>` and `wait=<duration>` and the call
//! blocks until the index advances or the wait elapses. The
//! response is a JSON array of `{Service, Node, Checks}` objects
//! plus an `X-Consul-Index` response header that's the cursor
//! for the next call. We loop forever:
//!
//! 1. GET with current index + `passing=true` filter.
//! 2. Diff the returned member set against our last view via
//!    [`super::diff_members`].
//! 3. Emit [`DiscoveryEvent`]s on the mpsc.
//! 4. Update the index from `X-Consul-Index` and loop.
//!
//! Network errors → exponential backoff (capped) + retry. Auth
//! errors (401/403) end the watcher with a logged error so the
//! operator notices the misconfigured ACL rather than silently
//! retrying forever.
//!
//! ## Config
//!
//! Env-var driven, mirroring B2-T1..T4:
//!
//! | Env | Required | Purpose |
//! |---|---|---|
//! | `AEGIS_CONSUL_ADDR` | no (default `http://127.0.0.1:8500`) | Consul HTTP API address |
//! | `AEGIS_CONSUL_TOKEN` | no | ACL token, sent as `X-Consul-Token` |
//! | `AEGIS_CONSUL_DATACENTER` | no | DC for cross-DC queries |
//! | `AEGIS_CONSUL_CA_CERT_PATH` | no | PEM bundle for mTLS / private CA |

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::mpsc;

use super::{diff_members, DiscoveryEvent};

/// Default block time for Consul long-poll. Five minutes is the
/// upstream default; longer is fine — Consul caps at 10m.
const DEFAULT_BLOCK_WAIT: &str = "5m";

/// Backoff bounds for transient network errors.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Channel capacity for emitted events. Big enough to absorb
/// a startup burst of `Added` events for a 100-member service
/// without blocking the watcher loop.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Resolved watcher config.
#[derive(Debug, Clone)]
pub struct ConsulConfig {
    pub address: String,
    pub token: Option<String>,
    pub datacenter: Option<String>,
    pub ca_cert_path: Option<String>,
}

impl ConsulConfig {
    /// Build from environment. Only `AEGIS_CONSUL_ADDR` has a
    /// default — everything else is opt-in.
    pub fn from_env() -> Self {
        Self {
            address: std::env::var("AEGIS_CONSUL_ADDR")
                .unwrap_or_else(|_| "http://127.0.0.1:8500".to_string()),
            token: std::env::var("AEGIS_CONSUL_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            datacenter: std::env::var("AEGIS_CONSUL_DATACENTER")
                .ok()
                .filter(|s| !s.is_empty()),
            ca_cert_path: std::env::var("AEGIS_CONSUL_CA_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}

/// Spawn a watcher task for `service`. Returns the receiver
/// half of the event channel; the sender lives in the spawned
/// task. Drop the receiver to stop the watcher (the task exits
/// the next time it tries to send).
pub fn watch(service: impl Into<String>) -> mpsc::Receiver<DiscoveryEvent> {
    let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let cfg = ConsulConfig::from_env();
    let service = service.into();

    tokio::spawn(async move {
        if let Err(e) = run_watcher(cfg, service.clone(), tx).await {
            tracing::warn!(
                service = %service,
                error = %e,
                "consul watcher exited",
            );
        }
    });

    rx
}

/// The watcher main loop. Returns when the channel closes
/// (downstream consumer dropped) or on auth error.
async fn run_watcher(
    cfg: ConsulConfig,
    service: String,
    tx: mpsc::Sender<DiscoveryEvent>,
) -> Result<(), String> {
    let http = build_client(&cfg)?;
    let mut last_index: u64 = 0;
    let mut last_members: HashSet<SocketAddr> = HashSet::new();
    let mut backoff = BACKOFF_MIN;

    loop {
        if tx.is_closed() {
            return Ok(());
        }

        match poll_once(&http, &cfg, &service, last_index).await {
            Ok((members, new_index)) => {
                let next: HashSet<SocketAddr> = members.into_iter().collect();
                for evt in diff_members(&last_members, &next) {
                    if tx.send(evt).await.is_err() {
                        // Receiver dropped — graceful exit.
                        return Ok(());
                    }
                }
                last_members = next;
                last_index = new_index;
                backoff = BACKOFF_MIN; // reset on success
            }
            Err(WatcherError::Auth(msg)) => {
                // Don't retry — the operator needs to fix
                // ACLs. Surface the error and stop.
                return Err(format!("consul auth error (stopping): {msg}"));
            }
            Err(WatcherError::Transient(msg)) => {
                tracing::debug!(
                    service = %service,
                    backoff_ms = backoff.as_millis() as u64,
                    error = %msg,
                    "consul watch transient error; backing off",
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

#[derive(Debug)]
enum WatcherError {
    /// 401 / 403 — operator action required, do not retry.
    Auth(String),
    /// Network / 5xx / parse — try again after backoff.
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

/// One blocking-query round-trip. Returns the parsed members and
/// the new `X-Consul-Index` value.
async fn poll_once(
    http: &reqwest::Client,
    cfg: &ConsulConfig,
    service: &str,
    index: u64,
) -> Result<(Vec<SocketAddr>, u64), WatcherError> {
    let mut url = format!(
        "{}/v1/health/service/{}?passing=true&index={}&wait={}",
        cfg.address.trim_end_matches('/'),
        urlencode_segment(service),
        index,
        DEFAULT_BLOCK_WAIT,
    );
    if let Some(dc) = &cfg.datacenter {
        url.push_str("&dc=");
        url.push_str(&urlencode_segment(dc));
    }

    let mut req = http.get(&url);
    if let Some(token) = &cfg.token {
        req = req.header("X-Consul-Token", token);
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
            "Consul returned {status}: {body} (check AEGIS_CONSUL_TOKEN ACL grants `service:read`)"
        )));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(WatcherError::Transient(format!(
            "Consul returned {status}: {body}"
        )));
    }

    let new_index = resp
        .headers()
        .get("X-Consul-Index")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(index);

    let body = resp
        .text()
        .await
        .map_err(|e| WatcherError::Transient(format!("read body: {e}")))?;

    let members = parse_response(&body)
        .map_err(|e| WatcherError::Transient(format!("parse: {e}")))?;

    Ok((members, new_index))
}

/// Parse the array-of-services response into a flat list of
/// `addr:port`. Pure — usable from tests without a live server.
pub fn parse_response(body: &str) -> Result<Vec<SocketAddr>, String> {
    let entries: Vec<HealthServiceEntry> =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        // Prefer Service.Address; fall back to Node.Address.
        // Empty-string Service.Address is a Consul convention
        // meaning "use the node's address" so we treat it the
        // same as missing.
        let addr = entry
            .service
            .address
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(entry.node.address.as_deref())
            .ok_or("entry has no Service.Address or Node.Address")?;

        let socket = format!("{addr}:{}", entry.service.port)
            .parse::<SocketAddr>()
            .map_err(|e| format!("bad addr {addr}:{}: {e}", entry.service.port))?;
        out.push(socket);
    }
    Ok(out)
}

#[derive(Deserialize)]
struct HealthServiceEntry {
    #[serde(rename = "Service")]
    service: ServiceInfo,
    #[serde(rename = "Node")]
    node: NodeInfo,
}

#[derive(Deserialize)]
struct ServiceInfo {
    #[serde(rename = "Address")]
    address: Option<String>,
    #[serde(rename = "Port")]
    port: u16,
}

#[derive(Deserialize)]
struct NodeInfo {
    #[serde(rename = "Address")]
    address: Option<String>,
}

/// Build the HTTP client. mTLS / custom CA via
/// `AEGIS_CONSUL_CA_CERT_PATH` if set.
fn build_client(cfg: &ConsulConfig) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        // Long enough to cover the longest Consul wait + a
        // generous network slop.
        .timeout(Duration::from_secs(360));

    if let Some(path) = &cfg.ca_cert_path {
        let pem = std::fs::read(path).map_err(|e| {
            format!("reading AEGIS_CONSUL_CA_CERT_PATH={path}: {e}")
        })?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| format!("parsing CA at {path}: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }

    builder
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

/// Minimal URL-segment encoder. Service names + datacenter names
/// in Consul are typically already URL-safe (`[a-zA-Z0-9-_]`)
/// but we encode anything outside that set for safety.
fn urlencode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process-wide mutex serialising tests that mutate the
    /// `AEGIS_CONSUL_*` env vars. Same pattern as the other
    /// resolvers' tests.
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
            ("AEGIS_CONSUL_ADDR", None),
            ("AEGIS_CONSUL_TOKEN", None),
            ("AEGIS_CONSUL_DATACENTER", None),
            ("AEGIS_CONSUL_CA_CERT_PATH", None),
        ]);
        let cfg = ConsulConfig::from_env();
        assert_eq!(cfg.address, "http://127.0.0.1:8500");
        assert!(cfg.token.is_none());
        assert!(cfg.datacenter.is_none());
        assert!(cfg.ca_cert_path.is_none());
    }

    #[test]
    fn config_picks_up_all_env_vars() {
        let _g = EnvGuard::set(&[
            ("AEGIS_CONSUL_ADDR", Some("https://consul.internal:8501")),
            ("AEGIS_CONSUL_TOKEN", Some("acl-token-xyz")),
            ("AEGIS_CONSUL_DATACENTER", Some("dc2")),
            ("AEGIS_CONSUL_CA_CERT_PATH", Some("/etc/consul/ca.pem")),
        ]);
        let cfg = ConsulConfig::from_env();
        assert_eq!(cfg.address, "https://consul.internal:8501");
        assert_eq!(cfg.token.as_deref(), Some("acl-token-xyz"));
        assert_eq!(cfg.datacenter.as_deref(), Some("dc2"));
        assert_eq!(cfg.ca_cert_path.as_deref(), Some("/etc/consul/ca.pem"));
    }

    #[test]
    fn config_filters_empty_strings_as_unset() {
        let _g = EnvGuard::set(&[
            ("AEGIS_CONSUL_ADDR", Some("http://127.0.0.1:8500")),
            ("AEGIS_CONSUL_TOKEN", Some("")),
            ("AEGIS_CONSUL_DATACENTER", Some("")),
            ("AEGIS_CONSUL_CA_CERT_PATH", Some("")),
        ]);
        let cfg = ConsulConfig::from_env();
        assert!(cfg.token.is_none());
        assert!(cfg.datacenter.is_none());
        assert!(cfg.ca_cert_path.is_none());
    }

    #[test]
    fn parse_empty_array() {
        let members = parse_response("[]").unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn parse_single_member_with_service_address() {
        let body = r#"[{
            "Service": {"Address": "10.0.0.1", "Port": 8080},
            "Node":    {"Address": "10.0.0.99"}
        }]"#;
        let members = parse_response(body).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0],
            "10.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_falls_back_to_node_address_when_service_address_empty() {
        // Consul's convention: `Service.Address: ""` means
        // "use Node.Address". We honor that.
        let body = r#"[{
            "Service": {"Address": "", "Port": 9000},
            "Node":    {"Address": "10.0.0.42"}
        }]"#;
        let members = parse_response(body).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0],
            "10.0.0.42:9000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_falls_back_to_node_address_when_service_address_missing() {
        let body = r#"[{
            "Service": {"Port": 9000},
            "Node":    {"Address": "10.0.0.42"}
        }]"#;
        let members = parse_response(body).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0],
            "10.0.0.42:9000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_multiple_members() {
        let body = r#"[
            {"Service": {"Address": "10.0.0.1", "Port": 8080}, "Node": {"Address": "10.0.0.1"}},
            {"Service": {"Address": "10.0.0.2", "Port": 8080}, "Node": {"Address": "10.0.0.2"}},
            {"Service": {"Address": "10.0.0.3", "Port": 8080}, "Node": {"Address": "10.0.0.3"}}
        ]"#;
        let members = parse_response(body).unwrap();
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn parse_member_with_no_address_anywhere_errors() {
        let body = r#"[{
            "Service": {"Port": 8080},
            "Node":    {}
        }]"#;
        let err = parse_response(body).unwrap_err();
        assert!(err.contains("no Service.Address or Node.Address"), "got: {err}");
    }

    #[test]
    fn parse_invalid_json_errors() {
        let err = parse_response("not json").unwrap_err();
        assert!(err.contains("invalid JSON"), "got: {err}");
    }

    #[test]
    fn parse_bad_port_errors() {
        // Port too large — JSON parses but SocketAddr rejects.
        let body = r#"[{
            "Service": {"Address": "10.0.0.1", "Port": 65536},
            "Node":    {"Address": "10.0.0.1"}
        }]"#;
        let err = parse_response(body);
        // The actual failure point is JSON deserialization
        // (port is u16, 65536 overflows). Either path
        // surfaces an error — assert we don't silently
        // succeed.
        assert!(err.is_err(), "should reject port out of u16 range");
    }

    #[test]
    fn urlencode_passes_unreserved_through() {
        assert_eq!(urlencode_segment("web-api_v2"), "web-api_v2");
    }

    #[test]
    fn urlencode_percent_encodes_special() {
        assert_eq!(urlencode_segment("a/b"), "a%2Fb");
        assert_eq!(urlencode_segment("a b"), "a%20b");
    }

    /// Diff integration: prove the watcher's inner loop produces
    /// the right shape of `DiscoveryEvent`s when the member set
    /// changes. Pure — no live Consul needed.
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
        for e in events {
            assert!(matches!(e, DiscoveryEvent::Added(_)));
        }
    }

    #[test]
    fn diff_member_drop_emits_removed() {
        let old: HashSet<SocketAddr> = [
            "10.0.0.1:8080".parse().unwrap(),
            "10.0.0.2:8080".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let new: HashSet<SocketAddr> =
            ["10.0.0.1:8080".parse().unwrap()].into_iter().collect();
        let events = diff_members(&old, &new);
        assert_eq!(events.len(), 1);
        match &events[0] {
            DiscoveryEvent::Removed(a) => {
                assert_eq!(*a, "10.0.0.2:8080".parse().unwrap())
            }
            other => panic!("expected Removed, got {other:?}"),
        }
    }

    /// Live integration test gated by an explicit opt-in env
    /// var. Run with:
    ///
    /// ```sh
    /// AEGIS_CONSUL_INTEGRATION_TEST=1 \
    /// AEGIS_CONSUL_ADDR=http://127.0.0.1:8500 \
    /// AEGIS_CONSUL_TEST_SERVICE=consul \
    ///   cargo test -p aegis-proxy --features consul \
    ///     --lib sd::consul::tests::live_consul_watch
    /// ```
    ///
    /// Defaults the service name to `consul` (the built-in
    /// service every agent registers itself as) so a vanilla
    /// `consul agent -dev` works without prep.
    #[tokio::test]
    async fn live_consul_watch() {
        if std::env::var("AEGIS_CONSUL_INTEGRATION_TEST").is_err() {
            eprintln!(
                "[sd::consul] skipped — set AEGIS_CONSUL_INTEGRATION_TEST=1 to run"
            );
            return;
        }
        let service = std::env::var("AEGIS_CONSUL_TEST_SERVICE")
            .unwrap_or_else(|_| "consul".to_string());

        let mut rx = watch(&service);
        // First non-empty event arrives within seconds against
        // a healthy Consul.
        let event = tokio::time::timeout(Duration::from_secs(15), rx.recv())
            .await
            .expect("watcher should emit within 15s")
            .expect("channel should be open");
        // Built-in `consul` service is always Added at boot.
        assert!(matches!(event, DiscoveryEvent::Added(_)));
    }
}
