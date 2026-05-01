//! MTLS-T1 — client identity types.
//!
//! `ClientIdentity` is the **discrete identity-extractor stage**
//! between TLS Termination and the WAF Policy Engine. It rides
//! through the request handler the same way `peer_addr` does
//! today. Pattern-matched at policy decision points (admin
//! login, per-route authz) and surfaced in audit chain entries
//! so dashboard rows show "blocked SQLi by
//! `spiffe://prod/payments-api`" instead of just an IP.
//!
//! ## Shape choice — enum, not struct
//!
//! An enum lets us add SPIFFE / JWT / OIDC / API-key identities
//! later without churning the policy engine signature. Pattern
//! matching makes audit logs / metrics labels mechanical:
//! `actor.kind = "mtls" | "spiffe" | "anonymous"`.
//!
//! ## Variants ship in slices
//!
//! - `Anonymous` — always available (no client cert, no auth).
//! - `Mtls` — populated by MTLS-T3's
//!   `extract_identity_from_handshake`.
//! - `Spiffe` — populated by the same extractor when the leaf's
//!   first URI-SAN starts with `spiffe://`. Free rider on
//!   MTLS-T3; no SPIRE workload-API integration required.
//!
//! Future variants (`Jwt`, `ApiKey`, …) land as new arms when
//! the auth method ships. Existing match-sites get a compiler
//! error pointing exactly where to extend — that's the design
//! goal of the enum-not-struct choice.

/// Identity of the client behind the current request, as
/// extracted by the listener stage. Pure data — no I/O, no
/// Arc, cheap to clone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ClientIdentity {
    /// No client cert presented (or `client_auth.mode: optional`
    /// admitted a no-cert connection). The default for every
    /// request when MTLS-T1's `client_auth` is `None`.
    #[default]
    Anonymous,
    /// Client presented a cert that chained to the configured
    /// trust anchor. `san` is the leaf's first DNS / email SAN
    /// (the SAN admin policy + `allowed_sans` checks operate on
    /// this string). `fingerprint` is a hex-encoded SHA-256 of
    /// the leaf cert DER — stable across handshakes from the
    /// same cert, useful for pinning and audit. `chain_ok` is
    /// `true` when WebPkiClientVerifier accepted the chain.
    Mtls {
        san: String,
        fingerprint: String,
        chain_ok: bool,
    },
    /// Client presented a cert whose first URI-SAN was a
    /// SPIFFE ID. `uri` is the full `spiffe://td/path` form;
    /// `td` is the trust-domain prefix (parsed once at
    /// extraction time). Operators running SPIRE point SPIRE at
    /// the WAF and configure the issuing CA in
    /// `cfg.tls.client_auth.ca_bundle` — no SPIRE client
    /// integration required on the WAF side.
    Spiffe { uri: String, td: String },
}

impl ClientIdentity {
    /// Stable label for audit chain entries + Prometheus
    /// `actor_kind` metric label. Stays stable across schema
    /// versions so log analytics doesn't churn when new
    /// variants land.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Mtls { .. } => "mtls",
            Self::Spiffe { .. } => "spiffe",
        }
    }

    /// Best-effort identifier for audit display. Returns
    /// `None` for `Anonymous`. For `Mtls` returns the leaf
    /// SAN; for `Spiffe` returns the full SPIFFE URI.
    pub fn principal(&self) -> Option<&str> {
        match self {
            Self::Anonymous => None,
            Self::Mtls { san, .. } => Some(san),
            Self::Spiffe { uri, .. } => Some(uri),
        }
    }

    /// Whether the identity passed strict trust-chain
    /// verification. `Anonymous` returns `false`; `Mtls`
    /// returns the verifier outcome; `Spiffe` returns `true`
    /// (SPIFFE ID extraction implies the chain was accepted —
    /// the WebPkiClientVerifier filtered upstream).
    pub fn is_authenticated(&self) -> bool {
        match self {
            Self::Anonymous => false,
            Self::Mtls { chain_ok, .. } => *chain_ok,
            Self::Spiffe { .. } => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_is_default() {
        assert_eq!(ClientIdentity::default(), ClientIdentity::Anonymous);
    }

    #[test]
    fn kind_labels_are_stable() {
        assert_eq!(ClientIdentity::Anonymous.kind(), "anonymous");
        assert_eq!(
            ClientIdentity::Mtls {
                san: "admin@example.com".into(),
                fingerprint: "deadbeef".into(),
                chain_ok: true,
            }
            .kind(),
            "mtls",
        );
        assert_eq!(
            ClientIdentity::Spiffe {
                uri: "spiffe://prod/api".into(),
                td: "prod".into(),
            }
            .kind(),
            "spiffe",
        );
    }

    #[test]
    fn principal_returns_san_for_mtls_uri_for_spiffe_none_for_anonymous() {
        assert!(ClientIdentity::Anonymous.principal().is_none());
        assert_eq!(
            ClientIdentity::Mtls {
                san: "ops@aegis.local".into(),
                fingerprint: "f1".into(),
                chain_ok: true,
            }
            .principal(),
            Some("ops@aegis.local"),
        );
        assert_eq!(
            ClientIdentity::Spiffe {
                uri: "spiffe://prod/svc".into(),
                td: "prod".into(),
            }
            .principal(),
            Some("spiffe://prod/svc"),
        );
    }

    #[test]
    fn anonymous_not_authenticated() {
        assert!(!ClientIdentity::Anonymous.is_authenticated());
    }

    #[test]
    fn mtls_authentication_follows_chain_ok() {
        let ok = ClientIdentity::Mtls {
            san: "x".into(),
            fingerprint: "y".into(),
            chain_ok: true,
        };
        assert!(ok.is_authenticated());
        let bad = ClientIdentity::Mtls {
            san: "x".into(),
            fingerprint: "y".into(),
            chain_ok: false,
        };
        assert!(!bad.is_authenticated());
    }

    #[test]
    fn spiffe_always_authenticated() {
        let id = ClientIdentity::Spiffe {
            uri: "spiffe://td/svc".into(),
            td: "td".into(),
        };
        assert!(id.is_authenticated());
    }

    #[test]
    fn clone_is_cheap_value_semantics() {
        let original = ClientIdentity::Mtls {
            san: "a".into(),
            fingerprint: "b".into(),
            chain_ok: true,
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
