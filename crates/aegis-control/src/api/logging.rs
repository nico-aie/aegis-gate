//! `/api/logging` — read + apply operator verbosity (P8 of the
//! security-toggle plan), and `/api/cold-tier` — list the audit
//! sinks the proxy is configured to flush events into.
//!
//! GET on either endpoint is read-only. PUT on `/api/logging`
//! routes through `AuditedMutate` so every level change lands an
//! admin chain entry.


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

/// One row of the cold-tier sink list. PE-2 (committee round-2 🔴3):
/// `delivery` + counters come from the live
/// [`crate::audit::sinks::delivery::DeliveryRegistry`] the sink
/// tasks record into — the old hardcoded `"unknown"` is gone.
///
/// `delivery` taxonomy:
/// - `ok`      — last write succeeded
/// - `error`   — last write failed (counters show scope)
/// - `pending` — task running, nothing flushed yet
/// - `unwired` — configured but no forwarder task exists in this
///   build (Splunk/Kafka today) or the task failed to start
#[derive(Clone, Debug, Serialize)]
pub struct SinkEntry {
    pub id: &'static str,
    pub kind: &'static str,
    pub destination: String,
    pub delivery: &'static str,
    pub delivered: u64,
    pub errors: u64,
    pub last_success: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ColdTierResponse {
    pub sinks: Vec<SinkEntry>,
    pub fallback_buffer_bytes: u64,
}

/// Render `/api/cold-tier` from a `WafConfig.audit.sinks` slice,
/// joined against the delivery registry the sink tasks record into.
pub fn render_cold_tier(
    sinks: &[AuditSinkConfig],
    registry: &crate::audit::sinks::delivery::DeliveryRegistry,
) -> String {
    use crate::audit::sinks::delivery::sink_key;
    let stats = registry.snapshot();
    let entries: Vec<SinkEntry> = sinks
        .iter()
        .map(|cfg| {
            let (id, kind, destination): (&'static str, &'static str, String) = match cfg {
                AuditSinkConfig::Jsonl { path, .. } => {
                    ("jsonl", "file", path.display().to_string())
                }
                AuditSinkConfig::Syslog { address, transport, .. } => (
                    "syslog",
                    match transport {
                        aegis_core::config::SyslogTransport::Udp => "udp",
                        aegis_core::config::SyslogTransport::Tcp => "tcp",
                        aegis_core::config::SyslogTransport::Tls => "tls",
                    },
                    address.clone(),
                ),
                AuditSinkConfig::Splunk { endpoint, .. } => {
                    ("splunk", "https", endpoint.clone())
                }
                AuditSinkConfig::Kafka { brokers, topic } => {
                    ("kafka", "stream", format!("{} / {topic}", brokers.join(",")))
                }
            };
            match stats.get(&sink_key(cfg)) {
                None => SinkEntry {
                    id,
                    kind,
                    destination,
                    delivery: "unwired",
                    delivered: 0,
                    errors: 0,
                    last_success: None,
                    last_error: None,
                },
                Some(s) => {
                    let delivery = if s.delivered == 0 && s.errors == 0 {
                        "pending"
                    } else if s.errors > 0 && s.last_error_ms() >= s.last_success_ms() {
                        "error"
                    } else {
                        "ok"
                    };
                    SinkEntry {
                        id,
                        kind,
                        destination,
                        delivery,
                        delivered: s.delivered,
                        errors: s.errors,
                        last_success: s.last_success,
                        last_error: s.last_error,
                    }
                }
            }
        })
        .collect();
    let body = ColdTierResponse {
        sinks: entries,
        fallback_buffer_bytes: 0,
    };
    serde_json::to_string(&body).unwrap_or_else(|_| String::from("{}"))
}

#[cfg(test)]
mod pe2_delivery_tests {
    // PE-2 (committee round-2 🔴3) — `/api/cold-tier` reports real
    // per-sink delivery state instead of the hardcoded
    // `delivery: "unknown"`. Sink tasks record outcomes into a
    // `DeliveryRegistry`; the renderer joins by `sink_key`.
    use super::*;
    use crate::audit::sinks::delivery::{sink_key, DeliveryRegistry};
    use std::path::PathBuf;

    fn jsonl_cfg() -> AuditSinkConfig {
        AuditSinkConfig::Jsonl {
            path: PathBuf::from("/var/log/aegis/audit.jsonl"),
            retention_days: 30,
            max_batch: 100,
            flush_interval: std::time::Duration::from_secs(1),
        }
    }

    fn kafka_cfg() -> AuditSinkConfig {
        AuditSinkConfig::Kafka {
            brokers: vec!["k1:9092".into()],
            topic: "audit".into(),
        }
    }

    #[test]
    fn registry_records_success_and_error() {
        let reg = DeliveryRegistry::new();
        let h = reg.handle(sink_key(&jsonl_cfg()));
        h.record_success(3);
        h.record_success(2);
        h.record_error();
        let snap = reg.snapshot();
        let s = snap.get(&sink_key(&jsonl_cfg())).expect("entry present");
        assert_eq!(s.delivered, 5);
        assert_eq!(s.errors, 1);
        assert!(s.last_success.is_some());
        assert!(s.last_error.is_some());
    }

    #[test]
    fn sink_key_is_stable_per_destination() {
        assert_eq!(sink_key(&jsonl_cfg()), sink_key(&jsonl_cfg()));
        assert_ne!(sink_key(&jsonl_cfg()), sink_key(&kafka_cfg()));
    }

    #[test]
    fn cold_tier_delivery_ok_when_success_recorded() {
        let reg = DeliveryRegistry::new();
        reg.handle(sink_key(&jsonl_cfg())).record_success(10);
        let body = render_cold_tier(&[jsonl_cfg()], &reg);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let s = &v["sinks"][0];
        assert_eq!(s["delivery"], "ok");
        assert_eq!(s["delivered"].as_u64(), Some(10));
        assert_eq!(s["errors"].as_u64(), Some(0));
        assert!(s["last_success"].is_string(), "last_success timestamp missing");
    }

    #[test]
    fn cold_tier_delivery_error_when_last_outcome_failed() {
        let reg = DeliveryRegistry::new();
        let h = reg.handle(sink_key(&jsonl_cfg()));
        h.record_success(4);
        std::thread::sleep(std::time::Duration::from_millis(5));
        h.record_error();
        let body = render_cold_tier(&[jsonl_cfg()], &reg);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["sinks"][0]["delivery"], "error");
        assert_eq!(v["sinks"][0]["delivered"].as_u64(), Some(4));
        assert_eq!(v["sinks"][0]["errors"].as_u64(), Some(1));
    }

    #[test]
    fn cold_tier_delivery_pending_before_first_event() {
        // Task spawned (handle registered) but nothing flushed yet.
        let reg = DeliveryRegistry::new();
        let _h = reg.handle(sink_key(&jsonl_cfg()));
        let body = render_cold_tier(&[jsonl_cfg()], &reg);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["sinks"][0]["delivery"], "pending");
        assert!(v["sinks"][0]["last_success"].is_null());
    }

    #[test]
    fn cold_tier_delivery_unwired_when_no_task_registered() {
        // Kafka/Splunk parse as config but have no forwarder task in
        // this build — the honest label is "unwired", never "unknown".
        let reg = DeliveryRegistry::new();
        let body = render_cold_tier(&[kafka_cfg()], &reg);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["sinks"][0]["delivery"], "unwired");
    }

    #[test]
    fn cold_tier_never_reports_unknown() {
        let reg = DeliveryRegistry::new();
        let body = render_cold_tier(&[jsonl_cfg(), kafka_cfg()], &reg);
        assert!(!body.contains("\"unknown\""), "placeholder string resurfaced: {body}");
    }
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
                ca_bundle: None,
                server_name: None,
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
        let registry = crate::audit::sinks::delivery::DeliveryRegistry::new();
        let body = render_cold_tier(&sinks, &registry);
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
        let registry = crate::audit::sinks::delivery::DeliveryRegistry::new();
        let body = render_cold_tier(&[], &registry);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["sinks"].as_array().unwrap().is_empty());
        assert_eq!(v["fallback_buffer_bytes"].as_u64(), Some(0));
    }
}
