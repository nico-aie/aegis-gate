//! MTLS-T8 — runtime client-auth mode store + `/api/mtls/mode`.
//!
//! Holds an in-process override of `cfg.tls.client_auth.mode` so an
//! operator can flip between Disabled / Optional / Required without
//! editing YAML. The store is consulted whenever the TLS acceptor is
//! (re-)built; today that's at boot + on every hot-reload of
//! `cfg.tls.certificates`. Pure mode flips don't yet trigger an
//! acceptor rebuild on their own, so the response carries an
//! explicit `requires_restart` flag the dashboard surfaces.
//!
//! The store starts at the configured mode (None means "no
//! override"). PUT /api/mtls/mode swaps in an `Override(mode)`;
//! DELETE clears it back to "use config".

use std::sync::Arc;

use arc_swap::ArcSwap;

pub use aegis_core::config::ClientAuthMode;

/// Runtime override over `cfg.tls.client_auth.mode`. The
/// configured value (from YAML) is captured at boot; the
/// override is `None` initially and swapped in by
/// `PUT /api/mtls/mode`.
#[derive(Clone)]
pub struct ClientAuthModeStore {
    /// Boot-time value from `cfg.tls.client_auth.mode` (or
    /// `Disabled` when no client_auth block is configured).
    /// Read-only after construction — operators flip the
    /// override below.
    configured: ClientAuthMode,
    inner: Arc<ArcSwap<Option<ClientAuthMode>>>,
}

impl ClientAuthModeStore {
    /// Default ctor — starts with `Disabled` configured + no
    /// override. Bundles built before the proxy populates the
    /// real configured value land here.
    pub fn new() -> Self {
        Self::with_configured(ClientAuthMode::Disabled)
    }

    /// Build with the boot-time configured mode.
    pub fn with_configured(configured: ClientAuthMode) -> Self {
        Self {
            configured,
            inner: Arc::new(ArcSwap::from_pointee(None)),
        }
    }

    /// Build with an initial override already in place (used by
    /// tests).
    pub fn with_override(configured: ClientAuthMode, mode: Option<ClientAuthMode>) -> Self {
        Self {
            configured,
            inner: Arc::new(ArcSwap::from_pointee(mode)),
        }
    }

    /// The configured (YAML) mode. Constant for the process
    /// lifetime.
    pub fn configured(&self) -> ClientAuthMode {
        self.configured
    }

    /// Snapshot the current override. Cheap (one ArcSwap load).
    pub fn current(&self) -> Option<ClientAuthMode> {
        **self.inner.load()
    }

    /// Snapshot the *effective* mode (override if set, else
    /// configured). One ArcSwap load.
    pub fn effective(&self) -> ClientAuthMode {
        effective_mode(self.configured, self.current())
    }

    /// Set the override. Returns the previous value so the audit
    /// emitter can record the diff.
    pub fn set(&self, mode: ClientAuthMode) -> Option<ClientAuthMode> {
        let prev = **self.inner.load();
        self.inner.store(Arc::new(Some(mode)));
        prev
    }

    /// Clear the override — subsequent reads return `None` and
    /// callers fall back to the configured value.
    pub fn clear(&self) -> Option<ClientAuthMode> {
        let prev = **self.inner.load();
        self.inner.store(Arc::new(None));
        prev
    }
}

impl Default for ClientAuthModeStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve the effective mode given the configured value + any
/// runtime override. The override wins. Used by the boot path
/// and by future acceptor-rebuild paths.
pub fn effective_mode(
    configured: ClientAuthMode,
    override_value: Option<ClientAuthMode>,
) -> ClientAuthMode {
    override_value.unwrap_or(configured)
}

/// Render the wire shape for `GET /api/mtls/mode`.
pub fn render_mode_response(
    configured: ClientAuthMode,
    override_value: Option<ClientAuthMode>,
) -> serde_json::Value {
    let effective = effective_mode(configured, override_value);
    serde_json::json!({
        "configured": mode_label(configured),
        "override": override_value.map(mode_label),
        "effective": mode_label(effective),
        // Today's acceptor rebuild only fires on cfg.tls swaps;
        // pure mode flips need a process restart to take effect
        // at the TLS handshake layer. The dashboard surfaces this
        // so operators don't expect an instant transport change.
        "requires_restart": override_value.is_some() && override_value != Some(configured),
    })
}

pub fn mode_label(m: ClientAuthMode) -> &'static str {
    match m {
        ClientAuthMode::Disabled => "disabled",
        ClientAuthMode::Optional => "optional",
        ClientAuthMode::Required => "required",
    }
}

pub fn parse_mode(s: &str) -> Option<ClientAuthMode> {
    match s {
        "disabled" => Some(ClientAuthMode::Disabled),
        "optional" => Some(ClientAuthMode::Optional),
        "required" => Some(ClientAuthMode::Required),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_store_has_no_override() {
        let s = ClientAuthModeStore::new();
        assert!(s.current().is_none());
    }

    #[test]
    fn effective_falls_back_to_configured() {
        let s = ClientAuthModeStore::with_configured(ClientAuthMode::Optional);
        assert_eq!(s.effective(), ClientAuthMode::Optional);
    }

    #[test]
    fn set_replaces_override_and_returns_previous() {
        let s = ClientAuthModeStore::new();
        let prev = s.set(ClientAuthMode::Optional);
        assert!(prev.is_none());
        assert_eq!(s.current(), Some(ClientAuthMode::Optional));
        let prev2 = s.set(ClientAuthMode::Required);
        assert_eq!(prev2, Some(ClientAuthMode::Optional));
        assert_eq!(s.current(), Some(ClientAuthMode::Required));
    }

    #[test]
    fn clear_returns_to_no_override() {
        let s = ClientAuthModeStore::with_override(
            ClientAuthMode::Disabled,
            Some(ClientAuthMode::Required),
        );
        assert_eq!(s.clear(), Some(ClientAuthMode::Required));
        assert!(s.current().is_none());
        assert_eq!(s.effective(), ClientAuthMode::Disabled);
    }

    #[test]
    fn effective_falls_back_to_configured_when_no_override() {
        assert_eq!(
            effective_mode(ClientAuthMode::Optional, None),
            ClientAuthMode::Optional,
        );
    }

    #[test]
    fn override_wins_over_configured() {
        assert_eq!(
            effective_mode(ClientAuthMode::Required, Some(ClientAuthMode::Disabled)),
            ClientAuthMode::Disabled,
        );
    }

    #[test]
    fn render_response_includes_all_fields_and_restart_flag() {
        let body = render_mode_response(
            ClientAuthMode::Required,
            Some(ClientAuthMode::Optional),
        );
        assert_eq!(body["configured"], "required");
        assert_eq!(body["override"], "optional");
        assert_eq!(body["effective"], "optional");
        assert_eq!(body["requires_restart"], true);
    }

    #[test]
    fn render_response_no_restart_when_override_matches_configured() {
        let body = render_mode_response(
            ClientAuthMode::Optional,
            Some(ClientAuthMode::Optional),
        );
        assert_eq!(body["requires_restart"], false);
    }

    #[test]
    fn render_response_no_restart_when_no_override() {
        let body = render_mode_response(ClientAuthMode::Disabled, None);
        assert_eq!(body["override"], serde_json::Value::Null);
        assert_eq!(body["effective"], "disabled");
        assert_eq!(body["requires_restart"], false);
    }

    #[test]
    fn parse_mode_recognises_all_three_values() {
        assert_eq!(parse_mode("disabled"), Some(ClientAuthMode::Disabled));
        assert_eq!(parse_mode("optional"), Some(ClientAuthMode::Optional));
        assert_eq!(parse_mode("required"), Some(ClientAuthMode::Required));
    }

    #[test]
    fn parse_mode_rejects_unknown_strings() {
        assert!(parse_mode("strict").is_none());
        assert!(parse_mode("DISABLED").is_none());
        assert!(parse_mode("").is_none());
    }
}
