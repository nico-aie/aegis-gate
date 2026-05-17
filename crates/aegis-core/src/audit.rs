use crate::tier::Tier;

/// 2026-05-17 F-CRITICAL-001/002/005 (core audit): wire-shape fixes
/// applied via serde attributes so the canonical JSON written to
/// the §6 audit log AND hashed by `chain::chain_hash` matches the
/// v2.3 §6 mandate. Rust field names kept stable to avoid a
/// 125-site construction sweep — the wire shape is what the
/// benchmarker validates.
///
/// Per-field mapping (Rust field → JSON key):
/// - `ts: DateTime<Utc>`     → `ts_ms` (i64 epoch millis)        F-CRITICAL-001
/// - `client_ip: String`     → `ip`                              F-CRITICAL-002
/// - `risk_score: Option<u32>` → `risk_score` (u32, clamped 0..=100, 0 if None)  F-CRITICAL-005
///
/// Still outstanding (filed for follow-up commit):
/// - F-CRITICAL-003: add `method`, `path`, `mode` fields
/// - F-CRITICAL-004: convert `action: String` → enum
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub schema_version: u32,
    #[serde(
        rename = "ts_ms",
        serialize_with = "serialize_ts_as_ms",
        deserialize_with = "deserialize_ts_from_ms"
    )]
    pub ts: chrono::DateTime<chrono::Utc>,
    pub request_id: String,
    pub class: AuditClass,
    pub tenant_id: Option<String>,
    pub tier: Option<Tier>,
    pub action: String,
    pub reason: String,
    #[serde(rename = "ip")]
    pub client_ip: String,
    pub route_id: Option<String>,
    pub rule_id: Option<String>,
    #[serde(
        serialize_with = "serialize_risk_score_clamped",
        deserialize_with = "deserialize_risk_score"
    )]
    pub risk_score: Option<u32>,
    pub fields: serde_json::Value,
}

/// §6 wire shape: `ts_ms` integer Unix epoch milliseconds.
fn serialize_ts_as_ms<S: serde::Serializer>(
    ts: &chrono::DateTime<chrono::Utc>,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_i64(ts.timestamp_millis())
}

/// Deserialize `ts_ms` integer back into a `DateTime<Utc>`. Invalid
/// values (negative beyond chrono's range) fall back to epoch 0
/// rather than erroring — read-side leniency keeps the chain
/// recoverable against any future drift.
fn deserialize_ts_from_ms<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<chrono::DateTime<chrono::Utc>, D::Error> {
    use serde::Deserialize;
    let ms = i64::deserialize(d)?;
    Ok(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(0).unwrap()))
}

/// §6 wire shape: `risk_score` integer in 0..=100, always present.
/// `None` populator → 0 on the wire. Out-of-range → clamped to 100.
fn serialize_risk_score_clamped<S: serde::Serializer>(
    score: &Option<u32>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let clamped = score.unwrap_or(0).min(100);
    s.serialize_u32(clamped)
}

/// Accept both legacy `null` and the new always-present integer.
fn deserialize_risk_score<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<u32>, D::Error> {
    use serde::Deserialize;
    Option::<u32>::deserialize(d)
}

impl AuditEvent {
    /// 2026-05-17 F-CRITICAL-001: in-memory accessor for callers
    /// that need a `DateTime<Utc>`. The wire shape is `ts_ms`.
    pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        self.ts
    }
}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditClass {
    Detection,
    Admin,
    Access,
    System,
}

#[derive(Clone)]
pub struct AuditBus(tokio::sync::broadcast::Sender<AuditEvent>);

impl AuditBus {
    pub fn new(cap: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(cap);
        Self(tx)
    }

    pub fn emit(&self, ev: AuditEvent) {
        let _ = self.0.send(ev);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<AuditEvent> {
        self.0.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serializes_to_json() {
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-001".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: Some(Tier::High),
            action: "block".into(),
            reason: "sqli detected".into(),
            client_ip: "1.2.3.4".into(),
            route_id: Some("api-users".into()),
            rule_id: Some("sqli-1".into()),
            risk_score: Some(85),
            fields: serde_json::json!({"detector": "sqli"}),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"class\":\"detection\""));
    }

    /// 2026-05-17 F-CRITICAL-001: §6 wire-shape regression. `ts`
    /// emits as integer `ts_ms`, never as a string `ts`.
    #[test]
    fn audit_event_ts_emits_as_ts_ms_integer() {
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(1_715_904_000_123)
                .unwrap(),
            request_id: "req-ts".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "allow".into(),
            reason: "ok".into(),
            client_ip: "127.0.0.1".into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(0),
            fields: serde_json::Value::Null,
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert!(v["ts_ms"].is_i64(), "ts_ms must be integer, got {:?}", v["ts_ms"]);
        assert_eq!(v["ts_ms"].as_i64().unwrap(), 1_715_904_000_123);
        assert!(v.get("ts").is_none(), "legacy `ts` key must not appear");
    }

    /// 2026-05-17 F-CRITICAL-002: §6 wire-shape regression. The
    /// Rust field is `client_ip` for backward compat, but the
    /// JSON key must be `ip` per §6.
    #[test]
    fn audit_event_client_ip_emits_as_ip() {
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-ip".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "10.0.0.1".into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(50),
            fields: serde_json::Value::Null,
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["ip"].as_str().unwrap(), "10.0.0.1");
        assert!(v.get("client_ip").is_none(), "legacy `client_ip` key must not appear");
    }

    /// 2026-05-17 F-CRITICAL-005: §6 says `risk_score` is required
    /// (always present, 0..=100). `None` populator → 0; out-of-range
    /// clamps to 100.
    #[test]
    fn audit_event_risk_score_serializes_clamped_and_required() {
        let mut ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-rs".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "allow".into(),
            reason: "ok".into(),
            client_ip: "1.1.1.1".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        };
        // None → 0 on the wire, never `null`, never missing.
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["risk_score"].as_u64().unwrap(), 0);

        // Above-range clamps to 100.
        ev.risk_score = Some(250);
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["risk_score"].as_u64().unwrap(), 100);

        // In-range pass through.
        ev.risk_score = Some(73);
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["risk_score"].as_u64().unwrap(), 73);
    }

    /// 2026-05-17 F-CRITICAL-001: round-trip ts_ms through serde.
    /// Both serialize and deserialize handle the integer wire shape.
    #[test]
    fn audit_event_ts_ms_round_trips() {
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(1_700_000_000_000)
                .unwrap(),
            request_id: "req-rt".into(),
            class: AuditClass::System,
            tenant_id: None,
            tier: None,
            action: "allow".into(),
            reason: "".into(),
            client_ip: "0.0.0.0".into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(0),
            fields: serde_json::Value::Null,
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: AuditEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.ts.timestamp_millis(), 1_700_000_000_000);
        assert_eq!(back.client_ip, "0.0.0.0");
    }

    #[test]
    fn audit_class_variants_serialize_snake_case() {
        let det = serde_json::to_string(&AuditClass::Detection).unwrap();
        let admin = serde_json::to_string(&AuditClass::Admin).unwrap();
        let access = serde_json::to_string(&AuditClass::Access).unwrap();
        let system = serde_json::to_string(&AuditClass::System).unwrap();

        assert_eq!(det, "\"detection\"");
        assert_eq!(admin, "\"admin\"");
        assert_eq!(access, "\"access\"");
        assert_eq!(system, "\"system\"");
    }

    #[test]
    fn audit_event_schema_version_starts_at_one() {
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-002".into(),
            class: AuditClass::System,
            tenant_id: None,
            tier: None,
            action: "startup".into(),
            reason: "waf started".into(),
            client_ip: "".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        };
        assert_eq!(ev.schema_version, 1);
    }

    #[tokio::test]
    async fn audit_bus_emit_and_subscribe() {
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();

        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-bus".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        };
        bus.emit(ev);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.request_id, "req-bus");
    }

    #[test]
    fn audit_bus_emit_without_subscribers_does_not_panic() {
        let bus = AuditBus::new(4);
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-no-sub".into(),
            class: AuditClass::System,
            tenant_id: None,
            tier: None,
            action: "test".into(),
            reason: "no subscriber".into(),
            client_ip: "".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        };
        bus.emit(ev); // should not panic
    }
}
