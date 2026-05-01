//! `/api/logging` — read + apply operator verbosity (P8 of the
//! security-toggle plan), and `/api/cold-tier` — list the audit
//! sinks the proxy is configured to flush events into.
//!
//! GET on either endpoint is read-only. PUT on `/api/logging`
//! routes through `AuditedMutate` so every level change lands an
//! admin chain entry.

#![allow(dead_code)]

use aegis_core::config::AuditSinkConfig;
use aegis_core::{SharedVerbosity, VerbosityLevel};
use serde::{Deserialize, Serialize};

/// Render the GET payload for `/api/logging`.
pub fn render_logging_get(verbosity: &SharedVerbosity) -> String {
    serde_json::to_string(&verbosity.snapshot()).unwrap_or_else(|_| String::from("{}"))
}

/// Body shape for `PUT /api/logging`. `level` field is required.
#[derive(Clone, Debug, Deserialize)]
pub struct LoggingPutBody {
    pub level: String,
}

pub fn apply_logging_put(
    verbosity: &SharedVerbosity,
    body: LoggingPutBody,
) -> Result<(), String> {
    match VerbosityLevel::parse_str(&body.level) {
        Some(lv) => {
            verbosity.set(lv);
            Ok(())
        }
        None => Err(format!("unknown verbosity level: {:?}", body.level)),
    }
}

/// One row of the cold-tier sink list. `delivery` is a placeholder
/// today — the production version is wired by the sink runtime
/// once it tracks per-sink last-success / lag.
#[derive(Clone, Debug, Serialize)]
pub struct SinkEntry {
    pub id: &'static str,
    pub kind: &'static str,
    pub destination: String,
    pub delivery: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ColdTierResponse {
    pub sinks: Vec<SinkEntry>,
    pub fallback_buffer_bytes: u64,
}

/// Render `/api/cold-tier` from a `WafConfig.audit.sinks` slice.
/// `delivery` is reported as `"unknown"` until the sink runtime
/// publishes per-sink state — surfacing the operator's configured
/// destinations with a known-stale flag is more useful than a
/// permanent `not_supported` 404.
pub fn render_cold_tier(sinks: &[AuditSinkConfig]) -> String {
    let entries: Vec<SinkEntry> = sinks
        .iter()
        .map(|cfg| match cfg {
            AuditSinkConfig::Jsonl { path, .. } => SinkEntry {
                id: "jsonl",
                kind: "file",
                destination: path.display().to_string(),
                delivery: "unknown",
            },
            AuditSinkConfig::Syslog { address, transport, .. } => SinkEntry {
                id: "syslog",
                kind: match transport {
                    aegis_core::config::SyslogTransport::Udp => "udp",
                    aegis_core::config::SyslogTransport::Tcp => "tcp",
                },
                destination: address.clone(),
                delivery: "unknown",
            },
            AuditSinkConfig::Splunk { endpoint, .. } => SinkEntry {
                id: "splunk",
                kind: "https",
                destination: endpoint.clone(),
                delivery: "unknown",
            },
            AuditSinkConfig::Kafka { brokers, topic } => SinkEntry {
                id: "kafka",
                kind: "stream",
                destination: format!("{} / {topic}", brokers.join(",")),
                delivery: "unknown",
            },
        })
        .collect();
    let body = ColdTierResponse {
        sinks: entries,
        fallback_buffer_bytes: 0,
    };
    serde_json::to_string(&body).unwrap_or_else(|_| String::from("{}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn render_logging_get_returns_documented_shape() {
        let v = SharedVerbosity::default();
        let body = render_logging_get(&v);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["level"].as_str(), Some("info"));
        let levels = json["levels"].as_array().unwrap();
        assert_eq!(levels.len(), 6);
        assert_eq!(levels[0], "silent");
        assert_eq!(levels[5], "trace");
    }

    #[test]
    fn apply_logging_put_accepts_each_level() {
        for s in ["silent", "error", "warn", "info", "debug", "trace"] {
            let v = SharedVerbosity::default();
            apply_logging_put(&v, LoggingPutBody { level: s.into() }).unwrap();
            assert_eq!(v.current().as_str(), s);
        }
    }

    #[test]
    fn apply_logging_put_rejects_unknown_level() {
        let v = SharedVerbosity::default();
        let err = apply_logging_put(&v, LoggingPutBody { level: "nope".into() }).unwrap_err();
        assert!(err.contains("unknown verbosity level"));
        assert_eq!(v.current(), VerbosityLevel::Info);
    }

    #[test]
    fn render_cold_tier_handles_each_sink_variant() {
        let sinks = vec![
            AuditSinkConfig::Jsonl {
                path: PathBuf::from("/var/log/aegis/audit.jsonl"),
                retention_days: 30,
                max_batch: 100,
                flush_interval: std::time::Duration::from_secs(1),
            },
            AuditSinkConfig::Syslog {
                address: "10.0.0.5:514".into(),
                transport: aegis_core::config::SyslogTransport::Udp,
                format: aegis_core::config::SyslogFormat::Rfc5424,
                facility: 10,
                app_name: "aegis-waf".into(),
            },
            AuditSinkConfig::Splunk {
                endpoint: "https://splunk.example.com:8088".into(),
                token_ref: "${secret:etcd:/aegis/secrets/splunk}".into(),
            },
            AuditSinkConfig::Kafka {
                brokers: vec!["k1:9092".into(), "k2:9092".into()],
                topic: "audit".into(),
            },
        ];
        let body = render_cold_tier(&sinks);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr = v["sinks"].as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0]["id"], "jsonl");
        assert_eq!(arr[0]["kind"], "file");
        assert_eq!(arr[1]["id"], "syslog");
        assert_eq!(arr[2]["id"], "splunk");
        assert!(arr[2]["destination"].as_str().unwrap().starts_with("https://"));
        assert_eq!(arr[3]["id"], "kafka");
        assert!(arr[3]["destination"].as_str().unwrap().contains("k1:9092"));
        // Token never echoes back — defence in depth even though
        // we only kept `endpoint` from the Splunk variant.
        let body_str = body;
        assert!(!body_str.contains("secret:"));
    }

    #[test]
    fn render_cold_tier_with_no_sinks_returns_empty_list() {
        let body = render_cold_tier(&[]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["sinks"].as_array().unwrap().is_empty());
        assert_eq!(v["fallback_buffer_bytes"].as_u64(), Some(0));
    }
}
