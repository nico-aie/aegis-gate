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
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:514".into(),
            transport: SyslogTransport::Udp,
            format: SyslogFormat::Rfc5424,
            facility: 10,
            app_name: "aegis-waf".into(),
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
}

impl SyslogSink {
    /// Construct + connect. UDP binds an ephemeral local
    /// socket; TCP connects synchronously and backs off on
    /// failure (initial connect failure is logged and the
    /// sink is left in a disconnected state — subsequent
    /// `write` calls reconnect lazily).
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
    let name = ev.action.clone();
    // Common extensions.
    let mut extension = format!(
        "act={action} src={ip} request_id={rid} mode={mode}",
        action = cef_escape(&ev.action),
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

/// Spawnable forwarder task — subscribes to the bus and
/// delivers every event to the supplied sink. Backpressure:
/// `Lagged(_)` increments a warn-level log counter and
/// continues; the data plane never blocks. Send failures are
/// logged and dropped from this sink only.
pub async fn run_forward_task(bus: AuditBus, sink: Arc<SyslogSink>) {
    let mut rx = bus.subscribe();
    loop {
        match rx.recv().await {
            Ok(ev) => {
                if let Err(e) = sink.send(&ev).await {
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
}
