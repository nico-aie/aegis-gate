use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::tier::{FailureMode, Tier};

pub struct RequestCtx {
    pub request_id: String,
    pub received_at: std::time::Instant,
    pub client: ClientInfo,
    pub tenant_id: Option<String>,
    pub trace_id: Option<String>,
    pub fields: BTreeMap<String, FieldValue>,
}

#[derive(Clone, Debug)]
pub enum FieldValue {
    Str(String),
    Int(i64),
    U32(u32),
    Bool(bool),
    List(Vec<FieldValue>),
}

pub struct ClientInfo {
    pub ip: IpAddr,
    pub tls_fingerprint: Option<TlsFingerprint>,
    pub h2_fingerprint: Option<String>,
    pub user_agent: Option<String>,
}

pub struct TlsFingerprint {
    pub ja3: String,
    pub ja4: String,
}

pub struct RouteCtx {
    pub route_id: String,
    pub tier: Tier,
    pub failure_mode: FailureMode,
    pub upstream: String,
    pub tenant_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn request_ctx_starts_with_empty_fields() {
        let ctx = RequestCtx {
            request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            received_at: std::time::Instant::now(),
            client: ClientInfo {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                tls_fingerprint: None,
                h2_fingerprint: None,
                user_agent: Some("curl/8.0".into()),
            },
            tenant_id: None,
            trace_id: None,
            fields: BTreeMap::new(),
        };
        assert!(ctx.fields.is_empty());
        assert!(ctx.tenant_id.is_none());
    }

    #[test]
    fn field_value_variants() {
        let s = FieldValue::Str("admin".into());
        let i = FieldValue::Int(42);
        let u = FieldValue::U32(100);
        let b = FieldValue::Bool(true);
        let l = FieldValue::List(vec![FieldValue::Str("a".into())]);

        assert!(matches!(s, FieldValue::Str(_)));
        assert!(matches!(i, FieldValue::Int(42)));
        assert!(matches!(u, FieldValue::U32(100)));
        assert!(matches!(b, FieldValue::Bool(true)));
        assert!(matches!(l, FieldValue::List(_)));
    }

    #[test]
    fn route_ctx_critical_tier() {
        let rctx = RouteCtx {
            route_id: "login".into(),
            tier: Tier::Critical,
            failure_mode: FailureMode::FailClose,
            upstream: "auth-pool".into(),
            tenant_id: None,
        };
        assert_eq!(rctx.tier, Tier::Critical);
        assert_eq!(rctx.failure_mode, FailureMode::FailClose);
    }

    #[test]
    fn client_info_with_tls_fingerprint() {
        let ci = ClientInfo {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            tls_fingerprint: Some(TlsFingerprint {
                ja3: "abc123".into(),
                ja4: "t13d1516h2_8daaf6152771_b0da82dd1658".into(),
            }),
            h2_fingerprint: Some("h2fp_example".into()),
            user_agent: None,
        };
        assert!(ci.tls_fingerprint.is_some());
        assert_eq!(
            ci.tls_fingerprint.as_ref().unwrap().ja4,
            "t13d1516h2_8daaf6152771_b0da82dd1658"
        );
    }
}
