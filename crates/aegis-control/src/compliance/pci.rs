//! PCI-DSS profile.
//!
//! - TLS ≥ 1.2.
//! - PAN masking in DLP (credit-card pattern recommended).
//! - Audit retention ≥ 90 days.

use aegis_core::{
    config::{DlpAction, DlpDir, DlpPattern, WafConfig},
    Result,
};

use super::{version_at_least, MIN_TLS_VERSION, PCI_MIN_RETENTION};

/// PAN (Primary Account Number) regex — matches 13–19 digits with separators.
const PAN_REGEX: &str = r"\b(?:\d[ -]?){12,18}\d\b";
/// PAN DLP rule identifier.
pub const PAN_RULE_ID: &str = "pci-pan";

/// Apply PCI-DSS settings to `cfg`.
pub fn apply(cfg: &mut WafConfig) -> Result<()> {
    {
        let profile = cfg
            .compliance
            .as_mut()
            .expect("compliance profile must exist before pci::apply");

        let needs_bump = match profile.min_tls_version.as_deref() {
            Some(v) => !version_at_least(v, MIN_TLS_VERSION),
            None => true,
        };
        if needs_bump {
            profile.min_tls_version = Some(MIN_TLS_VERSION.to_string());
        }
    }

    if cfg.audit.retention < PCI_MIN_RETENTION {
        cfg.audit.retention = PCI_MIN_RETENTION;
    }

    if !cfg.dlp.patterns.iter().any(|p| p.id == PAN_RULE_ID) {
        cfg.dlp.patterns.push(DlpPattern {
            id: PAN_RULE_ID.to_string(),
            regex: PAN_REGEX.to_string(),
            direction: DlpDir::Outbound,
            action: DlpAction::Redact,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::{ComplianceMode, ComplianceProfile, WafConfig};
    use std::time::Duration;

    fn minimal_cfg() -> WafConfig {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let mut cfg = aegis_core::config::load_config_str(yaml).unwrap();
        cfg.compliance = Some(ComplianceProfile {
            modes: vec![ComplianceMode::Pci],
            min_tls_version: None,
            disallow_algorithms: Vec::new(),
            pii_pseudonymize: false,
        });
        cfg
    }

    #[test]
    fn pci_sets_min_tls_when_unset() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        assert_eq!(
            cfg.compliance.as_ref().unwrap().min_tls_version.as_deref(),
            Some(MIN_TLS_VERSION)
        );
    }

    #[test]
    fn pci_extends_short_retention() {
        let mut cfg = minimal_cfg();
        cfg.audit.retention = Duration::from_secs(60 * 24 * 3600);
        apply(&mut cfg).unwrap();
        assert!(cfg.audit.retention >= PCI_MIN_RETENTION);
    }

    #[test]
    fn pci_keeps_longer_retention() {
        let mut cfg = minimal_cfg();
        let long = Duration::from_secs(365 * 24 * 3600);
        cfg.audit.retention = long;
        apply(&mut cfg).unwrap();
        assert_eq!(cfg.audit.retention, long);
    }

    #[test]
    fn pci_adds_pan_rule() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        let pan = cfg.dlp.patterns.iter().find(|p| p.id == PAN_RULE_ID).unwrap();
        assert_eq!(pan.action, DlpAction::Redact);
        assert_eq!(pan.direction, DlpDir::Outbound);
    }

    #[test]
    fn pci_idempotent_pan_rule() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        apply(&mut cfg).unwrap();
        let pan_count = cfg.dlp.patterns.iter().filter(|p| p.id == PAN_RULE_ID).count();
        assert_eq!(pan_count, 1);
    }
}
