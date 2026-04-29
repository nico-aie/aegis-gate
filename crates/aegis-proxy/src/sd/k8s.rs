//! Kubernetes service discovery watcher (B2-T7 — Phase B).
//!
//! Watches `EndpointSlice` objects for a service in a namespace
//! via the Kubernetes streaming watch API and emits
//! [`DiscoveryEvent`]s as endpoints come and go. Closes the
//! discovery half of milestone B2 (after consul + etcd).
//!
//! ## Why hand-roll, not `kube-rs`
//!
//! `kube-rs` is excellent but pulls a controller-runtime + a
//! generated typed-API stack. For one watch endpoint with a
//! known shape it's overkill — same rationale as B2-T5
//! (Consul) and B2-T6 (etcd). We POST nothing, GET one
//! `?watch=true` URL, and parse JSON-line events as they
//! arrive. No runtime, no informers, no caches.
//!
//! ## Wire shape
//!
//! Watch URL:
//!
//! ```text
//! GET <api-server>/apis/discovery.k8s.io/v1/namespaces/<ns>/endpointslices
//!     ?labelSelector=kubernetes.io/service-name=<svc>
//!     &watch=true
//! ```
//!
//! The response is a stream of newline-delimited JSON
//! `WatchEvent` envelopes:
//!
//! ```json
//! {"type": "ADDED",    "object": <EndpointSlice>}
//! {"type": "MODIFIED", "object": <EndpointSlice>}
//! {"type": "DELETED",  "object": <EndpointSlice>}
//! ```
//!
//! Each `EndpointSlice` may carry many endpoints and many
//! ports. We keep a per-slice address set, union them across
//! all live slices, diff the union against our last view via
//! [`super::diff_members`], and emit events.
//!
//! ## Auth
//!
//! In-cluster (default): bearer token at
//! `/var/run/secrets/kubernetes.io/serviceaccount/token`, CA at
//! `.../ca.crt`. Out-of-cluster: override via
//! `AEGIS_K8S_TOKEN_PATH` / `AEGIS_K8S_CA_CERT_PATH`. We do
//! **not** parse `~/.kube/config` — for dev work, set the env
//! vars to point at the right files instead.
//!
//! ## Config (env)
//!
//! | Env | Required | Purpose |
//! |---|---|---|
//! | `AEGIS_K8S_API_SERVER` | no (default `https://kubernetes.default.svc`) | Kubernetes API endpoint |
//! | `AEGIS_K8S_NAMESPACE` | no (default `default`) | Namespace of the watched service |
//! | `AEGIS_K8S_TOKEN_PATH` | no (default in-cluster path) | Service-account token file |
//! | `AEGIS_K8S_CA_CERT_PATH` | no (default in-cluster path) | API-server CA file |

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::mpsc;

use super::{diff_members, DiscoveryEvent};

const DEFAULT_API_SERVER: &str = "https://kubernetes.default.svc";
const DEFAULT_NAMESPACE: &str = "default";
const DEFAULT_SA_TOKEN_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_SA_CA_CERT_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Backoff bounds for transient errors.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Channel capacity for emitted events.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Resolved watcher config.
#[derive(Debug, Clone)]
pub struct K8sConfig {
    pub api_server: String,
    pub namespace: String,
    pub token_path: String,
    pub ca_cert_path: String,
}

impl K8sConfig {
    pub fn from_env() -> Self {
        Self {
            api_server: std::env::var("AEGIS_K8S_API_SERVER")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_API_SERVER.to_string()),
            namespace: std::env::var("AEGIS_K8S_NAMESPACE")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
            token_path: std::env::var("AEGIS_K8S_TOKEN_PATH")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_SA_TOKEN_PATH.to_string()),
            ca_cert_path: std::env::var("AEGIS_K8S_CA_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_SA_CA_CERT_PATH.to_string()),
        }
    }
}

/// Spawn a watcher for `service` in the configured namespace.
/// Returns the receiver half of the event channel.
pub fn watch(service: impl Into<String>) -> mpsc::Receiver<DiscoveryEvent> {
    let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let cfg = K8sConfig::from_env();
    let service = service.into();

    tokio::spawn(async move {
        if let Err(e) = run_watcher(cfg, service.clone(), tx).await {
            tracing::warn!(
                service = %service,
                error = %e,
                "k8s watcher exited",
            );
        }
    });

    rx
}

async fn run_watcher(
    cfg: K8sConfig,
    service: String,
    tx: mpsc::Sender<DiscoveryEvent>,
) -> Result<(), String> {
    let mut state = WatcherState::default();
    let mut backoff = BACKOFF_MIN;

    loop {
        if tx.is_closed() {
            return Ok(());
        }

        let token = std::fs::read_to_string(&cfg.token_path).map_err(|e| {
            format!(
                "reading service-account token at {}: {e}",
                cfg.token_path
            )
        })?;
        let token = token.trim().to_string();

        let http = build_client(&cfg)?;

        match read_watch_stream(&http, &cfg, &service, &token, &tx, &mut state).await
        {
            Ok(()) => {
                // Stream closed cleanly (k8s watch timeout — server
                // disconnects after a few minutes by design). Reconnect
                // immediately, no backoff.
                tracing::debug!(
                    service = %service,
                    "k8s watch stream closed cleanly; reconnecting",
                );
                backoff = BACKOFF_MIN;
            }
            Err(WatcherError::Auth(msg)) => {
                return Err(format!("k8s auth error (stopping): {msg}"));
            }
            Err(WatcherError::Transient(msg)) => {
                tracing::debug!(
                    service = %service,
                    backoff_ms = backoff.as_millis() as u64,
                    error = %msg,
                    "k8s watch transient error; backing off",
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

/// One full watch session — opens the stream, parses events as
/// they arrive, applies them to `state`, and sends events on
/// `tx`. Returns when the server closes the stream (clean) or
/// errors (caller decides retry).
async fn read_watch_stream(
    http: &reqwest::Client,
    cfg: &K8sConfig,
    service: &str,
    token: &str,
    tx: &mpsc::Sender<DiscoveryEvent>,
    state: &mut WatcherState,
) -> Result<(), WatcherError> {
    let url = format!(
        "{}/apis/discovery.k8s.io/v1/namespaces/{}/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3D{}&watch=true",
        cfg.api_server.trim_end_matches('/'),
        urlencode_segment(&cfg.namespace),
        urlencode_segment(service),
    );

    let resp = http
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| WatcherError::Transient(format!("transport: {e}")))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
    {
        let body = resp.text().await.unwrap_or_default();
        return Err(WatcherError::Auth(format!(
            "k8s API returned {status}: {body} (check service-account RBAC for endpointslices/get,watch on {})",
            cfg.namespace
        )));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(WatcherError::Transient(format!(
            "k8s API returned {status}: {body}"
        )));
    }

    // The stream is newline-delimited JSON. We read chunks via
    // `chunk()` (smaller surface than `bytes_stream`) and split
    // on `\n`. A partial line at the end of a chunk waits for
    // the next chunk.
    let mut resp = resp;
    let mut buf = Vec::with_capacity(8192);
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                buf.extend_from_slice(&chunk);
                // Drain complete lines.
                while let Some(nl_pos) = buf.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=nl_pos).collect();
                    let line_str = std::str::from_utf8(&line[..line.len() - 1])
                        .map_err(|e| {
                            WatcherError::Transient(format!("non-UTF-8 line: {e}"))
                        })?
                        .trim();
                    if line_str.is_empty() {
                        continue;
                    }
                    let parsed = parse_event_line(line_str).map_err(|e| {
                        WatcherError::Transient(format!("event parse: {e}"))
                    })?;
                    let events = state.apply(parsed);
                    for evt in events {
                        if tx.send(evt).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
            Ok(None) => return Ok(()), // server closed cleanly
            Err(e) => {
                return Err(WatcherError::Transient(format!("stream: {e}")));
            }
        }
    }
}

/// Build the HTTP client. CA cert is loaded from disk; if
/// missing, fall back to system roots (common when running
/// out-of-cluster against a public LB).
fn build_client(cfg: &K8sConfig) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        // K8s watch streams typically last 5–10 minutes before
        // the server force-closes; we want a long-poll-friendly
        // read timeout.
        .timeout(Duration::from_secs(900));

    if let Ok(pem) = std::fs::read(&cfg.ca_cert_path) {
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| format!("parsing CA at {}: {e}", cfg.ca_cert_path))?;
        builder = builder.add_root_certificate(cert);
    }
    // If the CA file is missing, fall through to system roots.
    // That's fine for `kubectl proxy` style local dev.

    builder
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

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

// ---------------------------------------------------------------------------
// Event parsing + state machine
// ---------------------------------------------------------------------------

/// Per-service state — the union of all live `EndpointSlice`s.
#[derive(Debug, Default)]
struct WatcherState {
    /// `<slice-name>` → its current address set.
    slices: HashMap<String, HashSet<SocketAddr>>,
    /// Cached union — diffed on each `apply` call to produce
    /// the right `DiscoveryEvent`s.
    current: HashSet<SocketAddr>,
}

impl WatcherState {
    fn apply(&mut self, event: ParsedEvent) -> Vec<DiscoveryEvent> {
        match event.kind {
            EventType::Added | EventType::Modified => {
                self.slices.insert(event.slice_name, event.addrs);
            }
            EventType::Deleted => {
                self.slices.remove(&event.slice_name);
            }
            EventType::Bookmark | EventType::Error | EventType::Unknown => {
                // Bookmarks are server-side resume cursors; we
                // don't use them for this simple watcher.
                // ERROR / unknown events are logged elsewhere.
                return Vec::new();
            }
        }

        let new_union: HashSet<SocketAddr> = self
            .slices
            .values()
            .flat_map(|s| s.iter())
            .copied()
            .collect();
        let events = diff_members(&self.current, &new_union);
        self.current = new_union;
        events
    }
}

/// Parsed shape of one watch-event line.
#[derive(Debug, PartialEq, Eq)]
struct ParsedEvent {
    kind: EventType,
    slice_name: String,
    addrs: HashSet<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventType {
    Added,
    Modified,
    Deleted,
    Bookmark,
    Error,
    Unknown,
}

/// Parse one JSON-line event from the watch stream. Pure —
/// usable from tests without a live cluster.
fn parse_event_line(line: &str) -> Result<ParsedEvent, String> {
    let envelope: WatchEnvelope =
        serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;

    let kind = match envelope.event_type.as_str() {
        "ADDED" => EventType::Added,
        "MODIFIED" => EventType::Modified,
        "DELETED" => EventType::Deleted,
        "BOOKMARK" => EventType::Bookmark,
        "ERROR" => EventType::Error,
        _ => EventType::Unknown,
    };

    // For bookmark / error / unknown we don't need addrs but
    // we still need a slice name to satisfy the struct shape;
    // synthesize a dummy.
    if !matches!(kind, EventType::Added | EventType::Modified | EventType::Deleted) {
        return Ok(ParsedEvent {
            kind,
            slice_name: String::new(),
            addrs: HashSet::new(),
        });
    }

    let slice = envelope.object.ok_or_else(|| {
        "event is missing `object` field for ADDED/MODIFIED/DELETED".to_string()
    })?;

    let slice_name = slice
        .metadata
        .name
        .clone()
        .ok_or_else(|| "EndpointSlice missing metadata.name".to_string())?;

    let addrs = slice_to_addrs(&slice);
    Ok(ParsedEvent {
        kind,
        slice_name,
        addrs,
    })
}

/// Cross-product the slice's ready endpoints × ports into a
/// flat set of `addr:port` socket addresses.
fn slice_to_addrs(slice: &EndpointSlice) -> HashSet<SocketAddr> {
    let mut out = HashSet::new();

    let endpoints = slice.endpoints.as_deref().unwrap_or(&[]);
    let ports = slice.ports.as_deref().unwrap_or(&[]);

    for ep in endpoints {
        // `conditions.ready == true` is the canonical filter.
        // Spec note: `ready` is `Option<bool>`; absence means
        // "unknown" which we treat as not-ready (conservative —
        // a brand-new endpoint without a verdict shouldn't
        // start receiving traffic mid-rollout).
        if ep.conditions.as_ref().and_then(|c| c.ready) != Some(true) {
            continue;
        }
        for port in ports {
            // Skip ports without a numeric value (k8s allows
            // string port names; we resolve those server-side
            // typically — for SD purposes we need a u16).
            let Some(p) = port.port else { continue };
            for addr_str in ep.addresses.iter() {
                if let Ok(parsed_addr) = addr_str.parse::<std::net::IpAddr>() {
                    out.insert(SocketAddr::new(parsed_addr, p));
                }
                // Non-IP addresses (e.g. FQDNs) skipped — k8s
                // resolves them at routing time; for SD we
                // need a final `addr:port`.
            }
        }
    }

    out
}

#[derive(Deserialize)]
struct WatchEnvelope {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    object: Option<EndpointSlice>,
}

#[derive(Deserialize)]
struct EndpointSlice {
    #[serde(default)]
    metadata: ObjectMeta,
    #[serde(default)]
    endpoints: Option<Vec<Endpoint>>,
    #[serde(default)]
    ports: Option<Vec<EndpointPort>>,
}

#[derive(Deserialize, Default)]
struct ObjectMeta {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct Endpoint {
    addresses: Vec<String>,
    #[serde(default)]
    conditions: Option<EndpointConditions>,
}

#[derive(Deserialize)]
struct EndpointConditions {
    #[serde(default)]
    ready: Option<bool>,
}

#[derive(Deserialize)]
struct EndpointPort {
    #[serde(default)]
    port: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ("AEGIS_K8S_API_SERVER", None),
            ("AEGIS_K8S_NAMESPACE", None),
            ("AEGIS_K8S_TOKEN_PATH", None),
            ("AEGIS_K8S_CA_CERT_PATH", None),
        ]);
        let cfg = K8sConfig::from_env();
        assert_eq!(cfg.api_server, DEFAULT_API_SERVER);
        assert_eq!(cfg.namespace, DEFAULT_NAMESPACE);
        assert_eq!(cfg.token_path, DEFAULT_SA_TOKEN_PATH);
        assert_eq!(cfg.ca_cert_path, DEFAULT_SA_CA_CERT_PATH);
    }

    #[test]
    fn config_picks_up_overrides() {
        let _g = EnvGuard::set(&[
            ("AEGIS_K8S_API_SERVER", Some("https://k8s.internal:6443")),
            ("AEGIS_K8S_NAMESPACE", Some("aegis-system")),
            ("AEGIS_K8S_TOKEN_PATH", Some("/etc/k8s/token")),
            ("AEGIS_K8S_CA_CERT_PATH", Some("/etc/k8s/ca.pem")),
        ]);
        let cfg = K8sConfig::from_env();
        assert_eq!(cfg.api_server, "https://k8s.internal:6443");
        assert_eq!(cfg.namespace, "aegis-system");
        assert_eq!(cfg.token_path, "/etc/k8s/token");
        assert_eq!(cfg.ca_cert_path, "/etc/k8s/ca.pem");
    }

    #[test]
    fn config_filters_empty_strings_as_unset() {
        let _g = EnvGuard::set(&[
            ("AEGIS_K8S_API_SERVER", Some("")),
            ("AEGIS_K8S_NAMESPACE", Some("")),
        ]);
        let cfg = K8sConfig::from_env();
        assert_eq!(cfg.api_server, DEFAULT_API_SERVER);
        assert_eq!(cfg.namespace, DEFAULT_NAMESPACE);
    }

    fn slice_json(name: &str, addrs: &[&str], port: u16, ready: bool) -> String {
        let addrs_json: Vec<String> =
            addrs.iter().map(|a| format!("\"{a}\"")).collect();
        let addrs_inner = addrs_json.join(",");
        format!(
            r#"{{
                "type": "ADDED",
                "object": {{
                    "metadata": {{"name": "{name}"}},
                    "endpoints": [{{
                        "addresses": [{addrs_inner}],
                        "conditions": {{"ready": {ready}}}
                    }}],
                    "ports": [{{"port": {port}}}]
                }}
            }}"#
        )
    }

    #[test]
    fn parse_added_with_ready_endpoints() {
        let line = slice_json("svc-abc1", &["10.0.0.1", "10.0.0.2"], 8080, true);
        let event = parse_event_line(&line).unwrap();
        assert_eq!(event.kind, EventType::Added);
        assert_eq!(event.slice_name, "svc-abc1");
        assert_eq!(event.addrs.len(), 2);
        assert!(event.addrs.contains(&"10.0.0.1:8080".parse().unwrap()));
        assert!(event.addrs.contains(&"10.0.0.2:8080".parse().unwrap()));
    }

    #[test]
    fn parse_filters_unready_endpoints() {
        let line = slice_json("svc-abc1", &["10.0.0.1"], 8080, false);
        let event = parse_event_line(&line).unwrap();
        // ready=false → no addresses surface.
        assert!(event.addrs.is_empty());
    }

    #[test]
    fn parse_treats_missing_ready_as_not_ready() {
        // No `conditions` block at all — conservative path,
        // we don't ship traffic to endpoints whose readiness
        // is unknown.
        let line = r#"{
            "type": "ADDED",
            "object": {
                "metadata": {"name": "svc-x"},
                "endpoints": [{"addresses": ["10.0.0.1"]}],
                "ports": [{"port": 8080}]
            }
        }"#;
        let event = parse_event_line(line).unwrap();
        assert!(event.addrs.is_empty());
    }

    #[test]
    fn parse_skips_string_named_ports() {
        // Named ports without a numeric value are skipped.
        let line = r#"{
            "type": "ADDED",
            "object": {
                "metadata": {"name": "svc-x"},
                "endpoints": [{
                    "addresses": ["10.0.0.1"],
                    "conditions": {"ready": true}
                }],
                "ports": [{"name": "http"}]
            }
        }"#;
        let event = parse_event_line(line).unwrap();
        assert!(event.addrs.is_empty());
    }

    #[test]
    fn parse_skips_non_ip_addresses() {
        // FQDN entries are skipped; k8s typically resolves
        // these server-side but for SD we need final addr:port.
        let line = r#"{
            "type": "ADDED",
            "object": {
                "metadata": {"name": "svc-x"},
                "endpoints": [{
                    "addresses": ["pod-1.svc.cluster.local"],
                    "conditions": {"ready": true}
                }],
                "ports": [{"port": 8080}]
            }
        }"#;
        let event = parse_event_line(line).unwrap();
        assert!(event.addrs.is_empty());
    }

    #[test]
    fn parse_modified_event() {
        let line = slice_json("svc-x", &["10.0.0.1"], 8080, true);
        let line = line.replace("ADDED", "MODIFIED");
        let event = parse_event_line(&line).unwrap();
        assert_eq!(event.kind, EventType::Modified);
    }

    #[test]
    fn parse_deleted_event() {
        let line = slice_json("svc-x", &["10.0.0.1"], 8080, true);
        let line = line.replace("ADDED", "DELETED");
        let event = parse_event_line(&line).unwrap();
        assert_eq!(event.kind, EventType::Deleted);
    }

    #[test]
    fn parse_bookmark_yields_no_addrs() {
        let line = r#"{"type": "BOOKMARK", "object": {}}"#;
        let event = parse_event_line(line).unwrap();
        assert_eq!(event.kind, EventType::Bookmark);
        assert!(event.addrs.is_empty());
    }

    #[test]
    fn parse_error_event_yields_no_addrs() {
        let line =
            r#"{"type": "ERROR", "object": {"message": "watch closed"}}"#;
        let event = parse_event_line(line).unwrap();
        assert_eq!(event.kind, EventType::Error);
    }

    #[test]
    fn parse_unknown_event_type_is_safe() {
        let line = r#"{"type": "STRANGE_NEW_KIND", "object": {}}"#;
        let event = parse_event_line(line).unwrap();
        assert_eq!(event.kind, EventType::Unknown);
    }

    #[test]
    fn parse_invalid_json_errors() {
        let err = parse_event_line("not json").unwrap_err();
        assert!(err.contains("invalid JSON"), "got: {err}");
    }

    #[test]
    fn parse_added_missing_object_errors() {
        let line = r#"{"type": "ADDED"}"#;
        let err = parse_event_line(line).unwrap_err();
        assert!(err.contains("missing `object`"), "got: {err}");
    }

    #[test]
    fn parse_added_missing_metadata_name_errors() {
        let line = r#"{
            "type": "ADDED",
            "object": {
                "endpoints": [],
                "ports": []
            }
        }"#;
        let err = parse_event_line(line).unwrap_err();
        assert!(err.contains("metadata.name"), "got: {err}");
    }

    #[test]
    fn state_added_emits_added_for_each_addr() {
        let mut state = WatcherState::default();
        let event = parse_event_line(&slice_json(
            "slice-1",
            &["10.0.0.1", "10.0.0.2"],
            8080,
            true,
        ))
        .unwrap();
        let events = state.apply(event);
        assert_eq!(events.len(), 2);
        for e in events {
            assert!(matches!(e, DiscoveryEvent::Added(_)));
        }
    }

    #[test]
    fn state_modified_replaces_slice() {
        let mut state = WatcherState::default();

        // Add slice with two addrs.
        let evt =
            parse_event_line(&slice_json("slice-1", &["10.0.0.1", "10.0.0.2"], 8080, true))
                .unwrap();
        state.apply(evt);

        // Modify to one addr — the other should be Removed.
        let mut evt =
            parse_event_line(&slice_json("slice-1", &["10.0.0.1"], 8080, true)).unwrap();
        evt.kind = EventType::Modified;
        let events = state.apply(evt);
        assert_eq!(events.len(), 1);
        match &events[0] {
            DiscoveryEvent::Removed(a) => {
                assert_eq!(*a, "10.0.0.2:8080".parse().unwrap())
            }
            other => panic!("expected Removed, got {other:?}"),
        }
    }

    #[test]
    fn state_deleted_drops_slice() {
        let mut state = WatcherState::default();

        // Two slices, each with one addr.
        let evt = parse_event_line(&slice_json("slice-1", &["10.0.0.1"], 8080, true))
            .unwrap();
        state.apply(evt);
        let evt = parse_event_line(&slice_json("slice-2", &["10.0.0.2"], 8080, true))
            .unwrap();
        state.apply(evt);

        // Delete slice-1.
        let mut evt = parse_event_line(&slice_json("slice-1", &["10.0.0.1"], 8080, true))
            .unwrap();
        evt.kind = EventType::Deleted;
        let events = state.apply(evt);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], DiscoveryEvent::Removed(_)));
    }

    #[test]
    fn state_unions_across_slices() {
        // Two slices contributing distinct addrs — the union
        // is what surfaces to the consumer.
        let mut state = WatcherState::default();

        let evt = parse_event_line(&slice_json("slice-1", &["10.0.0.1"], 8080, true))
            .unwrap();
        let events = state.apply(evt);
        assert_eq!(events.len(), 1);

        let evt = parse_event_line(&slice_json("slice-2", &["10.0.0.2"], 8080, true))
            .unwrap();
        let events = state.apply(evt);
        assert_eq!(events.len(), 1);
        assert!(state.current.contains(&"10.0.0.1:8080".parse().unwrap()));
        assert!(state.current.contains(&"10.0.0.2:8080".parse().unwrap()));
    }

    #[test]
    fn state_bookmark_is_noop() {
        let mut state = WatcherState::default();
        let evt = parse_event_line(r#"{"type": "BOOKMARK", "object": {}}"#).unwrap();
        let events = state.apply(evt);
        assert!(events.is_empty());
        assert!(state.current.is_empty());
    }

    #[test]
    fn urlencode_segment_passes_unreserved() {
        assert_eq!(urlencode_segment("aegis-system"), "aegis-system");
    }

    #[test]
    fn urlencode_segment_percent_encodes_special() {
        assert_eq!(urlencode_segment("name with space"), "name%20with%20space");
        assert_eq!(urlencode_segment("ns/foo"), "ns%2Ffoo");
    }

    /// Live integration test gated by an explicit opt-in env
    /// var. Run with:
    ///
    /// ```sh
    /// AEGIS_K8S_INTEGRATION_TEST=1 \
    /// AEGIS_K8S_API_SERVER=https://localhost:6443 \
    /// AEGIS_K8S_TOKEN_PATH=/path/to/sa/token \
    /// AEGIS_K8S_CA_CERT_PATH=/path/to/ca.crt \
    /// AEGIS_K8S_NAMESPACE=default \
    /// AEGIS_K8S_TEST_SERVICE=kubernetes \
    ///   cargo test -p aegis-proxy --features k8s \
    ///     --lib sd::k8s::tests::live_k8s_watch
    /// ```
    ///
    /// Defaults to the `kubernetes` service in the `default`
    /// namespace, which exists on every cluster.
    #[tokio::test]
    async fn live_k8s_watch() {
        if std::env::var("AEGIS_K8S_INTEGRATION_TEST").is_err() {
            eprintln!(
                "[sd::k8s] skipped — set AEGIS_K8S_INTEGRATION_TEST=1 to run"
            );
            return;
        }
        let service = std::env::var("AEGIS_K8S_TEST_SERVICE")
            .unwrap_or_else(|_| "kubernetes".to_string());
        let mut rx = watch(&service);
        let event = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("watcher should emit within 20s")
            .expect("channel should be open");
        assert!(matches!(event, DiscoveryEvent::Added(_)));
    }
}
