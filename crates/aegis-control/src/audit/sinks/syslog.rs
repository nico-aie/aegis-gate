//! HACK-T5 — RFC 5424 / CEF audit forwarder (Tier-C bonus).
//!
//! Streams every `AuditEvent` from the broadcast bus to a
//! remote syslog or CEF receiver. Data plane never blocks on
//! the forwarder — a dedicated tokio task subscribes to the
//! bus, formats each event, and sends fire-and-forget over UDP
//! or TCP.
//!
//! ## Transports
//!
//! - **UDP** (RFC 5426) — default. One datagram per event.
//!   Lossy under congestion (UDP doesn't acknowledge); the
//!   receiver SHOULD be on the same private segment for low
//!   loss in practice.
//! - **TCP** — newline-terminated framing (RFC 6587 §3.4
//!   "non-transparent framing"). Reconnects on failure with
//!   exponential backoff capped at 30 s. Send errors are
//!   logged and the event is dropped from the syslog sink
//!   only — JSONL persistence is unaffected.
//!
//! ## Formats
//!
//! - **RFC 5424** — `<PRI>1 TS HOST APP PROCID MSGID STRUCTURED MSG`
//!   with the AuditEvent JSON in the MSG slot. SIEMs that
//!   parse standard syslog ingest this directly.
//! - **CEF** — ArcSight Common Event Format
//!   `CEF:0|Vendor|Product|Version|EventClassID|Name|Severity|<extension>`.
//!   The extension carries `act=` / `src=` / `request_id=` /
//!   etc. so SIEMs that index CEF fields show the audit event
//!   as native columns.
//!
//! ## What this slice does NOT include
//!
//! - **TLS transport** — the variant exists in the config
//!   schema but the sink falls back to TCP when `tls`
//!   transport is requested. TLS-wrapping reuses
//!   `tokio_rustls::TlsConnector` and the existing
//!   `ClientTrustStore` — separable follow-up.
//! - **Reliable delivery** — UDP is best-effort by design;
//!   TCP recovers across reconnects but doesn't replay events
//!   buffered during the disconnect. JSONL remains the
//!   durable persistence path; syslog is the live tail.

use std::sync::Arc;
use std::time::Duration;

use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};
use aegis_core::config::{SyslogFormat, SyslogTransport};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// HACK-T5 — Per-sink runtime config. Built from
/// [`aegis_core::config::AuditSinkConfig::Syslog`] at boot.
#[derive(Clone, Debug)]
pub struct SyslogConfig {
    /// `host:port`. Required.
    pub address: String,
    pub transport: SyslogTransport,
    pub format: SyslogFormat,
    /// RFC 5424 facility (0..=23). Default 10 (security/auth).
    pub facility: u8,
    /// APP-NAME header field — typically `aegis-waf`.
    pub app_name: String,
    /// HACK-T5 TLS — optional explicit CA bundle PEM. `None`
    /// → use webpki system roots. Ignored unless
    /// `transport = Tls`.
    pub ca_bundle: Option<std::path::PathBuf>,
    /// HACK-T5 TLS — SNI / cert-validation hostname. `None`
    /// → derive from the host part of `address`.
    pub server_name: Option<String>,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:514".into(),
            transport: SyslogTransport::Udp,
            format: SyslogFormat::Rfc5424,
            facility: 10,
            app_name: "aegis-waf".into(),
            ca_bundle: None,
            server_name: None,
        }
    }
}

/// Live syslog forwarder. Holds the open UDP socket / TCP
/// stream and a small reconnect budget. Cheap to clone — the
/// inner connection lives behind a `Mutex` so concurrent
/// writes serialise on the wire (one event per send).
pub struct SyslogSink {
    cfg: SyslogConfig,
    state: Mutex<TransportState>,
}

enum TransportState {
    /// UDP — connectionless; we keep one bound socket open and
    /// `send_to` per event.
    Udp(UdpSocket),
    /// TCP — newline-framed. `None` means we're disconnected
    /// and will retry on the next event (with backoff applied
    /// elsewhere).
    Tcp(Option<TcpStream>),
    /// HACK-T5 — TLS-wrapped TCP. Reconnects re-handshake;
    /// the rustls config is held alongside so reconnect can
    /// reuse the same trust + SNI without re-parsing.
    Tls {
        stream: Option<tokio_rustls::client::TlsStream<TcpStream>>,
        connector: tokio_rustls::TlsConnector,
        server_name: rustls_pki_types::ServerName<'static>,
    },
}

impl SyslogSink {
    /// The operator-configured receiver address — the identity half
    /// of this sink's [`super::delivery::syslog_key`] registry key.
    pub fn destination(&self) -> &str {
        &self.cfg.address
    }

    /// Construct + connect. UDP binds an ephemeral local
    /// socket; TCP connects synchronously and backs off on
    /// failure (initial connect failure is logged and the
    /// sink is left in a disconnected state — subsequent
    /// `write` calls reconnect lazily). TLS handshakes after
    /// the TCP connect using `tokio_rustls`; on initial
    /// failure the sink is left disconnected and the next
    /// send retries (same lazy-reconnect contract as TCP).
    pub async fn connect(cfg: SyslogConfig) -> aegis_core::Result<Self> {
        let state = match cfg.transport {
            SyslogTransport::Udp => {
                let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
                    aegis_core::WafError::Other(format!(
                        "syslog udp bind failed: {e}"
                    ))
                })?;
                sock.connect(&cfg.address).await.map_err(|e| {
                    aegis_core::WafError::Other(format!(
                        "syslog udp connect to {} failed: {e}",
                        cfg.address,
                    ))
                })?;
                TransportState::Udp(sock)
            }
            SyslogTransport::Tcp => {
                match TcpStream::connect(&cfg.address).await {
                    Ok(stream) => TransportState::Tcp(Some(stream)),
                    Err(e) => {
                        tracing::warn!(
                            address = %cfg.address,
                            error = %e,
                            "syslog tcp initial connect failed; will retry on first event",
                        );
                        TransportState::Tcp(None)
                    }
                }
            }
            SyslogTransport::Tls => {
                // Build the TLS connector once and reuse for
                // reconnects. SNI defaults to the host part
                // of `address` if `server_name` is unset.
                let connector = build_tls_connector(&cfg)?;
                let server_name = derive_server_name(&cfg)?;
                let stream = tls_connect(&cfg.address, &connector, &server_name).await
                    .map(Some)
                    .unwrap_or_else(|e| {
                        tracing::warn!(
                            address = %cfg.address,
                            error = %e,
                            "syslog tls initial handshake failed; will retry on first event",
                        );
                        None
                    });
                TransportState::Tls {
                    stream,
                    connector,
                    server_name,
                }
            }
        };
        Ok(Self {
            cfg,
            state: Mutex::new(state),
        })
    }

    /// Format + emit one event. UDP datagram or TCP framed
    /// write. Lock contention is bounded by the audit-bus
    /// drain task being the single writer — concurrent writers
    /// would serialise but in practice only the persist task
    /// calls this.
    pub async fn send(&self, ev: &AuditEvent) -> aegis_core::Result<()> {
        let line = match self.cfg.format {
            SyslogFormat::Rfc5424 => format_rfc5424(ev, &self.cfg),
            SyslogFormat::Cef => format_cef(ev, &self.cfg),
        };
        let mut guard = self.state.lock().await;
        match &mut *guard {
            TransportState::Udp(sock) => {
                sock.send(line.as_bytes()).await.map_err(|e| {
                    aegis_core::WafError::Other(format!(
                        "syslog udp send to {} failed: {e}",
                        self.cfg.address,
                    ))
                })?;
            }
            TransportState::Tcp(slot) => {
                // Reconnect lazily if disconnected.
                if slot.is_none() {
                    match TcpStream::connect(&self.cfg.address).await {
                        Ok(stream) => *slot = Some(stream),
                        Err(e) => {
                            return Err(aegis_core::WafError::Other(format!(
                                "syslog tcp reconnect to {} failed: {e}",
                                self.cfg.address,
                            )));
                        }
                    }
                }
                let stream = slot.as_mut().expect("just reconnected");
                let mut framed = line;
                if !framed.ends_with('\n') {
                    framed.push('\n');
                }
                if let Err(e) = stream.write_all(framed.as_bytes()).await {
                    // Drop the connection; next call will
                    // reconnect.
                    *slot = None;
                    return Err(aegis_core::WafError::Other(format!(
                        "syslog tcp send to {} failed: {e}",
                        self.cfg.address,
                    )));
                }
            }
            TransportState::Tls { stream, connector, server_name } => {
                if stream.is_none() {
                    match tls_connect(&self.cfg.address, connector, server_name).await {
                        Ok(s) => *stream = Some(s),
                        Err(e) => {
                            return Err(aegis_core::WafError::Other(format!(
                                "syslog tls reconnect to {} failed: {e}",
                                self.cfg.address,
                            )));
                        }
                    }
                }
                let s = stream.as_mut().expect("just reconnected");
                let mut framed = line;
                if !framed.ends_with('\n') {
                    framed.push('\n');
                }
                if let Err(e) = s.write_all(framed.as_bytes()).await {
                    *stream = None;
                    return Err(aegis_core::WafError::Other(format!(
                        "syslog tls send to {} failed: {e}",
                        self.cfg.address,
                    )));
                }
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::AuditSink for SyslogSink {
    fn id(&self) -> &str {
        "syslog"
    }

    async fn write(&self, ev: &AuditEvent) -> aegis_core::Result<()> {
        self.send(ev).await
    }
}

/// Format an event as RFC 5424. Fields packed into the
/// MSG slot as a JSON object so SIEMs can re-parse with their
/// JSON-aware filters.
pub fn format_rfc5424(ev: &AuditEvent, cfg: &SyslogConfig) -> String {
    let severity = severity_for(ev.class);
    let priority = (cfg.facility as u32) * 8 + severity as u32;
    let ts = ev.ts.to_rfc3339();
    let msg = serde_json::to_string(ev).unwrap_or_default();
    format!(
        "<{priority}>1 {ts} - {app} - - - {msg}",
        app = cfg.app_name,
    )
}

/// Format an event as ArcSight CEF. Severity ∈ 0..=10.
pub fn format_cef(ev: &AuditEvent, cfg: &SyslogConfig) -> String {
    let severity_cef = match ev.class {
        AuditClass::Detection => 7, // high
        AuditClass::Admin => 4,
        AuditClass::Access => 3,
        AuditClass::System => 5,
    };
    let class_id = format!("{:?}", ev.class).to_lowercase();
    let name = ev.action.as_str().to_string();
    // Common extensions.
    let mut extension = format!(
        "act={action} src={ip} request_id={rid} mode={mode}",
        action = cef_escape(ev.action.as_str()),
        ip = cef_escape(&ev.client_ip),
        rid = cef_escape(&ev.request_id),
        mode = cef_extract_mode(&ev.fields),
    );
    if let Some(rule) = &ev.rule_id {
        use std::fmt::Write;
        let _ = write!(&mut extension, " cs1Label=rule_id cs1={}", cef_escape(rule));
    }
    if let Some(score) = ev.risk_score {
        use std::fmt::Write;
        let _ = write!(&mut extension, " cn1Label=risk_score cn1={score}");
    }
    format!(
        "CEF:0|Aegis|{app}|0.1.0|{class_id}|{name}|{severity_cef}|{extension}",
        app = cef_escape(&cfg.app_name),
        name = cef_escape(&name),
    )
}

/// CEF escape: `\`, `=`, `|`, newline → backslash-escaped.
fn cef_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

fn cef_extract_mode(fields: &serde_json::Value) -> &'static str {
    match fields.get("mode").and_then(|v| v.as_str()) {
        Some("log_only") => "log_only",
        Some("enforce") => "enforce",
        _ => "unknown",
    }
}

fn severity_for(class: AuditClass) -> u8 {
    match class {
        AuditClass::Detection => 4, // warning
        AuditClass::Admin => 6,     // informational
        AuditClass::Access => 6,
        AuditClass::System => 5, // notice
    }
}

/// HACK-T5 TLS — build a `tokio_rustls::TlsConnector` from
/// the syslog config. Loads the configured `ca_bundle` if
/// present; otherwise uses webpki system roots. The returned
/// connector is reused across reconnects so we never re-parse
/// the trust store on a per-event basis.
fn build_tls_connector(
    cfg: &SyslogConfig,
) -> aegis_core::Result<tokio_rustls::TlsConnector> {
    use rustls_pki_types::CertificateDer;
    use std::sync::Arc;

    // Install the ring crypto provider once per process. The
    // upstream-mTLS path does the same dance.
    static PROVIDER_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let mut roots = rustls::RootCertStore::empty();
    if let Some(bundle_path) = cfg.ca_bundle.as_ref() {
        let pem = std::fs::read(bundle_path).map_err(|e| {
            aegis_core::WafError::Config(format!(
                "syslog tls ca_bundle {} read failed: {e}",
                bundle_path.display(),
            ))
        })?;
        let mut reader = std::io::BufReader::new(pem.as_slice());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                aegis_core::WafError::Config(format!(
                    "syslog tls ca_bundle parse failed: {e}",
                ))
            })?;
        if certs.is_empty() {
            return Err(aegis_core::WafError::Config(
                "syslog tls ca_bundle has no CERTIFICATE blocks".into(),
            ));
        }
        for cert in certs {
            roots.add(cert).map_err(|e| {
                aegis_core::WafError::Config(format!(
                    "syslog tls rustls rejected CA: {e}",
                ))
            })?;
        }
    } else {
        // Webpki system roots — appropriate when the receiver
        // is behind a public CA. Operators with private PKI
        // configure `ca_bundle` instead.
        roots.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    }

    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_cfg)))
}

/// Pull the SNI / cert-validation hostname out of `cfg`.
/// Explicit `server_name` wins; otherwise we strip the `:port`
/// suffix from `address`. IPv6 literals (with brackets) are
/// passed through verbatim — rustls accepts them.
fn derive_server_name(
    cfg: &SyslogConfig,
) -> aegis_core::Result<rustls_pki_types::ServerName<'static>> {
    let raw = cfg
        .server_name
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| host_from_address(&cfg.address));
    rustls_pki_types::ServerName::try_from(raw.clone()).map_err(|e| {
        aegis_core::WafError::Config(format!(
            "syslog tls server_name {raw} invalid: {e}",
        ))
    })
}

fn host_from_address(addr: &str) -> String {
    // IPv6 literal: `[::1]:514` → `[::1]`. Strip the trailing
    // `:port` while preserving brackets.
    if let Some(close) = addr.find(']') {
        return addr[..=close].to_string();
    }
    match addr.rsplit_once(':') {
        Some((host, _)) => host.to_string(),
        None => addr.to_string(),
    }
}

/// HACK-T5 TLS — TCP connect + rustls handshake. Returns a
/// negotiated stream ready for `write_all`.
async fn tls_connect(
    address: &str,
    connector: &tokio_rustls::TlsConnector,
    server_name: &rustls_pki_types::ServerName<'static>,
) -> aegis_core::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address).await.map_err(|e| {
        aegis_core::WafError::Other(format!(
            "syslog tls tcp connect to {address} failed: {e}",
        ))
    })?;
    connector
        .connect(server_name.clone(), tcp)
        .await
        .map_err(|e| {
            aegis_core::WafError::Other(format!(
                "syslog tls handshake to {address} failed: {e}",
            ))
        })
}

/// Spawnable forwarder task — subscribes to the bus and
/// delivers every event to the supplied sink. Backpressure:
/// `Lagged(_)` increments a warn-level log counter and
/// continues; the data plane never blocks. Send failures are
/// logged and dropped from this sink only.
pub async fn run_forward_task(bus: AuditBus, sink: Arc<SyslogSink>) {
    // PE-2 — delivery accounting for `/api/cold-tier`.
    let delivery = super::delivery::DeliveryRegistry::global()
        .handle(super::delivery::syslog_key(sink.destination()));
    let mut rx = bus.subscribe();
    loop {
        match rx.recv().await {
            Ok(ev) => match sink.send(&ev).await {
                Ok(()) => delivery.record_success(1),
                Err(e) => {
                    delivery.record_error();
                    tracing::warn!(
                        sink = "syslog",
                        error = %e,
                        "syslog forward failed; event dropped from this sink only",
                    );
                    // Brief backoff so we don't spin on a
                    // sustained failure (e.g. wrong port).
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                crate::metrics::audit_events::record_dropped(
                    crate::metrics::audit_events::consumer_label::SYSLOG,
                    n,
                );
                tracing::warn!(
                    dropped = n,
                    "syslog forward task lagged; events dropped from broadcast",
                );
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-sys".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "xss".into(),
            client_ip: "5.6.7.8".into(),
            route_id: None,
            rule_id: Some("xss".into()),
            risk_score: Some(72),
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({ "mode": "enforce" }),
        }
    }

    #[test]
    fn rfc5424_priority_calculated_from_facility_and_severity() {
        // facility=10 * 8 + severity=4 = 84 (Detection class).
        let cfg = SyslogConfig::default();
        let msg = format_rfc5424(&detection_event(), &cfg);
        assert!(msg.starts_with("<84>1 "), "got {msg}");
    }

    #[test]
    fn rfc5424_carries_app_name_and_event_json() {
        let cfg = SyslogConfig::default();
        let msg = format_rfc5424(&detection_event(), &cfg);
        assert!(msg.contains("aegis-waf"));
        assert!(msg.contains("\"request_id\":\"req-sys\""));
        assert!(msg.contains("\"action\":\"block\""));
    }

    #[test]
    fn rfc5424_admin_class_severity_is_6() {
        // facility=10*8 + severity=6 = 86.
        let mut ev = detection_event();
        ev.class = AuditClass::Admin;
        let cfg = SyslogConfig::default();
        let msg = format_rfc5424(&ev, &cfg);
        assert!(msg.starts_with("<86>1 "));
    }

    #[test]
    fn cef_starts_with_canonical_header() {
        let cfg = SyslogConfig::default();
        let msg = format_cef(&detection_event(), &cfg);
        assert!(msg.starts_with("CEF:0|Aegis|aegis-waf|0.1.0|"), "got {msg}");
    }

    #[test]
    fn cef_includes_action_src_request_id_mode() {
        let cfg = SyslogConfig::default();
        let msg = format_cef(&detection_event(), &cfg);
        assert!(msg.contains("act=block"));
        assert!(msg.contains("src=5.6.7.8"));
        assert!(msg.contains("request_id=req-sys"));
        assert!(msg.contains("mode=enforce"));
    }

    #[test]
    fn cef_includes_rule_id_and_risk_score_when_present() {
        let cfg = SyslogConfig::default();
        let msg = format_cef(&detection_event(), &cfg);
        assert!(msg.contains("cs1Label=rule_id"));
        assert!(msg.contains("cs1=xss"));
        assert!(msg.contains("cn1Label=risk_score"));
        assert!(msg.contains("cn1=72"));
    }

    #[test]
    fn cef_escape_handles_pipe_equals_backslash() {
        // Pipe / equals / backslash must escape; the audit
        // event's `action` field is operator-influenced (rule
        // ids, etc.) so this is the security-relevant escape
        // path.
        let mut ev = detection_event();
        ev.action = "block|=test".into();
        let cfg = SyslogConfig::default();
        let msg = format_cef(&ev, &cfg);
        assert!(msg.contains("act=block\\|\\=test"));
    }

    #[test]
    fn cef_severity_per_audit_class() {
        let cfg = SyslogConfig::default();
        let mut ev = detection_event();
        ev.class = AuditClass::Detection;
        assert!(format_cef(&ev, &cfg).contains("|7|"));
        ev.class = AuditClass::Admin;
        assert!(format_cef(&ev, &cfg).contains("|4|"));
        ev.class = AuditClass::Access;
        assert!(format_cef(&ev, &cfg).contains("|3|"));
        ev.class = AuditClass::System;
        assert!(format_cef(&ev, &cfg).contains("|5|"));
    }

    #[tokio::test]
    async fn udp_send_round_trips_to_loopback_receiver() {
        // Stand up a UDP receiver on an ephemeral port, send
        // one event through the sink, and assert the receiver
        // got the formatted line.
        let recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv.local_addr().unwrap();

        let cfg = SyslogConfig {
            address: recv_addr.to_string(),
            transport: SyslogTransport::Udp,
            format: SyslogFormat::Rfc5424,
            ..Default::default()
        };
        let sink = SyslogSink::connect(cfg).await.unwrap();
        sink.send(&detection_event()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _from) = tokio::time::timeout(
            Duration::from_secs(1),
            recv.recv_from(&mut buf),
        )
        .await
        .expect("receiver timed out")
        .unwrap();
        let msg = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(msg.starts_with("<84>1 "));
        assert!(msg.contains("\"request_id\":\"req-sys\""));
    }

    #[tokio::test]
    async fn tcp_send_round_trips_to_loopback_listener() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let recv_handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            // Read until the first newline (RFC 6587 §3.4
            // non-transparent framing).
            let mut tmp = [0u8; 1024];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.contains(&b'\n') {
                    break;
                }
            }
            String::from_utf8(buf).unwrap()
        });

        let cfg = SyslogConfig {
            address: addr.to_string(),
            transport: SyslogTransport::Tcp,
            format: SyslogFormat::Cef,
            ..Default::default()
        };
        let sink = SyslogSink::connect(cfg).await.unwrap();
        sink.send(&detection_event()).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), recv_handle)
            .await
            .expect("tcp recv timed out")
            .unwrap();
        assert!(received.starts_with("CEF:0|Aegis|"));
        assert!(received.ends_with('\n'));
    }

    #[tokio::test]
    async fn tcp_reconnect_after_initial_failure_does_not_panic() {
        // Connect to a port nothing is listening on. The sink
        // should construct cleanly with `slot: None`, and the
        // first `send` call should return Err (not panic) so
        // the forward task can log + continue.
        let cfg = SyslogConfig {
            address: "127.0.0.1:1".into(), // privileged + unused
            transport: SyslogTransport::Tcp,
            format: SyslogFormat::Rfc5424,
            ..Default::default()
        };
        let sink = SyslogSink::connect(cfg).await.unwrap();
        let result = sink.send(&detection_event()).await;
        assert!(result.is_err(), "expected send to fail with no listener");
    }

    // ---------------- HACK-T5 TLS ----------------

    #[test]
    fn host_from_address_strips_port() {
        assert_eq!(host_from_address("syslog.example.com:6514"), "syslog.example.com");
        assert_eq!(host_from_address("10.0.0.5:514"), "10.0.0.5");
        // No port → unchanged.
        assert_eq!(host_from_address("syslog"), "syslog");
    }

    #[test]
    fn host_from_address_preserves_ipv6_brackets() {
        assert_eq!(host_from_address("[::1]:6514"), "[::1]");
        assert_eq!(host_from_address("[2001:db8::1]:6514"), "[2001:db8::1]");
    }

    #[test]
    fn derive_server_name_explicit_field_wins() {
        let cfg = SyslogConfig {
            address: "10.0.0.5:6514".into(),
            transport: SyslogTransport::Tls,
            server_name: Some("syslog.internal.example.com".into()),
            ..Default::default()
        };
        let sn = derive_server_name(&cfg).unwrap();
        // ServerName::Dns variant → display matches.
        let dns_str = format!("{sn:?}");
        assert!(
            dns_str.contains("syslog.internal.example.com"),
            "expected DNS name in {dns_str}",
        );
    }

    #[test]
    fn derive_server_name_falls_back_to_address_host() {
        let cfg = SyslogConfig {
            address: "syslog.example.com:6514".into(),
            transport: SyslogTransport::Tls,
            server_name: None,
            ..Default::default()
        };
        let sn = derive_server_name(&cfg).unwrap();
        let dns_str = format!("{sn:?}");
        assert!(dns_str.contains("syslog.example.com"));
    }

    #[test]
    fn build_tls_connector_uses_webpki_roots_when_no_ca_bundle() {
        // Connector must build cleanly without a configured
        // ca_bundle — webpki roots are bundled into the
        // `webpki-roots` crate.
        let cfg = SyslogConfig {
            transport: SyslogTransport::Tls,
            ca_bundle: None,
            ..Default::default()
        };
        // `TlsConnector` doesn't impl Debug, so we can't use
        // `.expect(...)` directly; check the variant instead.
        assert!(
            build_tls_connector(&cfg).is_ok(),
            "webpki roots connector must build",
        );
    }

    #[test]
    fn build_tls_connector_rejects_missing_ca_bundle() {
        let cfg = SyslogConfig {
            transport: SyslogTransport::Tls,
            ca_bundle: Some(std::path::PathBuf::from("/no/such/ca.pem")),
            ..Default::default()
        };
        let err = match build_tls_connector(&cfg) {
            Err(e) => e,
            Ok(_) => panic!("expected ca_bundle path error"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/no/such/ca.pem"),
            "error must surface bundle path: {msg}",
        );
    }

    #[tokio::test]
    async fn tls_send_round_trips_to_self_signed_loopback_listener() {
        // Issue a self-signed cert for `localhost`, run a
        // tokio_rustls server on it, write the CA into a
        // tempfile, configure the sink to trust it via
        // `ca_bundle`, and verify the receiver got a
        // CEF-formatted line.
        use std::io::Write;
        use rustls_pki_types::CertificateDer;
        use tokio::io::AsyncReadExt;

        // 1. Generate self-signed CA + leaf.
        let mut ca_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        // Write the CA pem to a tempfile so the sink can
        // load it via the `ca_bundle` config knob.
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        let mut f = std::fs::File::create(&ca_path).unwrap();
        f.write_all(ca_cert.pem().as_bytes()).unwrap();
        f.sync_all().unwrap();

        // 2. Build the rustls server config with the leaf
        // and stand up a TLS listener.
        // Install crypto provider for the server side.
        static SERVER_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        SERVER_INIT.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let leaf_chain: Vec<CertificateDer<'static>> =
            vec![leaf_cert.der().clone()];
        let leaf_priv = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        );
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(leaf_chain, leaf_priv)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let recv_handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match tls.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.contains(&b'\n') {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            String::from_utf8(buf).unwrap()
        });

        // 3. Build the syslog sink as a TLS client trusting
        // our CA, send one event, and verify the receiver
        // got the framed line.
        let cfg = SyslogConfig {
            address: addr.to_string(),
            transport: SyslogTransport::Tls,
            format: SyslogFormat::Cef,
            ca_bundle: Some(ca_path),
            // Override SNI to `localhost` because the leaf's
            // SAN is `localhost` but the address is
            // `127.0.0.1:NNN`.
            server_name: Some("localhost".into()),
            ..Default::default()
        };
        let sink = SyslogSink::connect(cfg).await.expect("tls handshake");
        sink.send(&detection_event()).await.expect("send");

        let received = tokio::time::timeout(Duration::from_secs(3), recv_handle)
            .await
            .expect("tls recv timed out")
            .unwrap();
        assert!(
            received.starts_with("CEF:0|Aegis|"),
            "expected CEF header in {received}",
        );
        assert!(received.ends_with('\n'));

        // Keep tempdir alive until end of test.
        drop(dir);
    }

    #[tokio::test]
    async fn tls_handshake_failure_against_nothing_does_not_panic() {
        // No listener at the address. Initial handshake fails;
        // sink is left disconnected with `stream: None`. First
        // `send` returns Err (the forward task can log + continue).
        let cfg = SyslogConfig {
            address: "127.0.0.1:1".into(),
            transport: SyslogTransport::Tls,
            format: SyslogFormat::Rfc5424,
            ca_bundle: None,
            ..Default::default()
        };
        let sink = SyslogSink::connect(cfg).await.unwrap();
        let result = sink.send(&detection_event()).await;
        assert!(
            result.is_err(),
            "expected tls send to fail with no listener",
        );
    }
}
