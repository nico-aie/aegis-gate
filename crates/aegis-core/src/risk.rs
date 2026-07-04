//! Risk **types** only — the composite [`RiskKey`] the whole risk
//! system keys on, plus its constructors/encoding. If you came here
//! looking for risk *behavior*, it lives elsewhere:
//!
//! - **Accumulation, decay, trust recovery, thresholds, strikes:**
//!   `aegis-security/src/risk/tracker.rs` (`RiskTracker`) — the
//!   in-process engine the data plane consults per request.
//! - **Cross-node persistence + reconciliation:** the proxy's
//!   `StateBackend` impls — `aegis-proxy/src/state/in_memory.rs` and
//!   `state/reconcile.rs` (durable `control:waf:risk` hash, LWW
//!   merge on rehydrate).
//! - **Per-request detector scores vs cumulative IP risk:** two
//!   different numbers — see `detectors/scores.rs` for the per-hit
//!   values; the tracker folds max-per-request into the cumulative
//!   score that `challenge_at`/`block_at` gate on.
//!
//! (LT-P8: this module doc exists because this thin type file is
//! where people land first when hunting risk logic.)

use std::net::IpAddr;

/// 2026-06-24 — `Serialize`/`Deserialize` added for the interim Redis
/// durability bridge (`redis-interim-durability` P2): the key is the field
/// of the durable `control:waf:risk` hash, encoded as canonical JSON
/// (`serde_json::to_string`). Struct fields serialize in declaration order,
/// so the encoding is deterministic — the same key always maps to the same
/// field, making the flush an idempotent overwrite rather than a duplicate.
#[derive(Clone, Hash, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct RiskKey {
    pub ip: IpAddr,
    pub device_fp: Option<String>,
    pub session: Option<String>,
}

impl RiskKey {
    /// 2026-05-18 F-CRITICAL-001 (security audit, Phase E) — the
    /// "legacy" / IP-only constructor. Used when the data plane
    /// doesn't have device-fingerprint or session info available
    /// (e.g. anonymous public endpoints, pre-session-warmup). All
    /// `Option` axes stay `None`.
    ///
    /// Composite-key construction (with `device_fp` from JA4 + UA
    /// hash, `session` from cookie / JWT-sub) is a separate
    /// site-specific constructor — callers build a `RiskKey { … }`
    /// literal there. This helper is the bridge for the migration
    /// from IP-only to composite.
    ///
    /// 2026-05-19 — `tenant_id` axis removed. The multi-tenant
    /// feature was deprecated upstream; every populator site was
    /// hard-coded to `None`. Dropping the axis simplifies the
    /// composite-key surface and saves an `Option<String>` per
    /// bucket. `AuditEvent.tenant_id` is a separate wire-contract
    /// field and stays for SIEM-sink compatibility.
    pub fn from_ip(ip: IpAddr) -> Self {
        Self {
            ip,
            device_fp: None,
            session: None,
        }
    }
}

impl From<IpAddr> for RiskKey {
    fn from(ip: IpAddr) -> Self {
        Self::from_ip(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    #[test]
    fn risk_key_equality() {
        let k1 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            device_fp: Some("fp123".into()),
            session: Some("sess-abc".into()),
        };
        let k2 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            device_fp: Some("fp123".into()),
            session: Some("sess-abc".into()),
        };
        assert_eq!(k1, k2);
    }

    #[test]
    fn risk_key_hash_stability() {
        let k1 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            device_fp: None,
            session: None,
        };
        let k2 = k1.clone();
        let mut set = HashSet::new();
        set.insert(k1);
        assert!(set.contains(&k2));
    }

    #[test]
    fn risk_key_different_ips_not_equal() {
        let k1 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            device_fp: None,
            session: None,
        };
        let k2 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            device_fp: None,
            session: None,
        };
        assert_ne!(k1, k2);
    }
}
