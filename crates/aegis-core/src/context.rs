use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::tier::{FailureMode, Tier};

pub struct RequestCtx {
    pub request_id: String,
    pub received_at: std::time::Instant,
    pub client: ClientInfo,
    // 2026-05-19 — `tenant_id` removed (was always `None`; multi-tenant
    // feature deprecated upstream). `AuditEvent.tenant_id` keeps its
    // own wire-contract field for SIEM-sink compatibility.
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
    // 2026-05-19 — `tenant_id` removed (was always `None`; multi-tenant
    // feature deprecated upstream).
    /// MTLS-T4 — required client-identity kinds for this
    /// route. Empty = any identity admitted (default open).
    /// Non-empty acts as an allow-list against
    /// [`crate::ClientIdentity::kind`]. The data-plane handler
    /// checks this after route resolution and 403s on mismatch
    /// (`rule_id = mtls_required`).
    pub auth_required: Vec<String>,
    /// TCP-T3c — resolved upstream scheme, lifted out of
    /// `cfg.upstreams[upstream].connection.scheme` at compile
    /// time so the CONNECT-method dispatch in the data-plane
    /// handler doesn't need a second pool lookup.
    pub pool_scheme: crate::config::UpstreamScheme,
    /// TCP-T3c — pre-parsed CONNECT destination allowlist for
    /// `pool_scheme == Tcp` routes. Empty for non-tcp routes
    /// (the dispatch is gated by scheme so the field is
    /// effectively unused there). Parsed once at config load
    /// so the hot path is a `policy_admits` lookup, not a
    /// re-parse.
    pub tcp_destination_allowlist: Vec<crate::tcp_destination::TcpDestinationRule>,
    /// TCP-T3c — per-source-IP cap on concurrent open tunnels
    /// for this route. `0` means "use the boot default of 16"
    /// (resolved by `aegis_proxy::tcp_tunnel::effective_cap`).
    pub max_concurrent_tunnels_per_ip: u32,
    /// 2026-05-12 — precomputed prefix to strip from the request
    /// path before forwarding to the upstream. `None` = forward
    /// the path unchanged (path-preserving mode, or
    /// match-type doesn't support stripping). `Some("/news")` =
    /// remove that exact literal prefix from the request URI's
    /// path component; the query string is preserved verbatim.
    ///
    /// Set by `CompiledRoute::to_ctx` based on
    /// `RouteConfig.strip_prefix` (default `true`) + match-type
    /// gating, so the data-plane handler doesn't have to re-derive
    /// the rule on every request.
    pub path_strip_prefix: Option<String>,
    /// WS-MSG — per-route WebSocket message-inspection settings, carried
    /// from `RouteConfig.ws_inspect`. `None` (default) ⇒ the zero-copy
    /// WS bridge; `Some(.. enabled: true)` ⇒ the inspecting bridge for
    /// client→upstream text frames.
    pub ws_inspect: Option<crate::config::WsInspectConfig>,
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
            trace_id: None,
            fields: BTreeMap::new(),
        };
        assert!(ctx.fields.is_empty());
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
            auth_required: Vec::new(),
            pool_scheme: crate::config::UpstreamScheme::Auto,
            tcp_destination_allowlist: Vec::new(),
            max_concurrent_tunnels_per_ip: 0,
            path_strip_prefix: None,
            ws_inspect: None,
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
