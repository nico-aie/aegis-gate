//! HIPAA profile.
//!
//! PHI-safe log mode: PHI fields are masked before any sink write.

use aegis_core::{config::WafConfig, Result};

/// Default PHI tag patterns: SSN, MRN-like ids, US phone numbers.
pub const DEFAULT_PHI_TAGS: &[&str] = &["ssn", "mrn", "patient_id", "dob"];

/// Apply HIPAA settings to `cfg`.
pub fn apply(cfg: &mut WafConfig) -> Result<()> {
    cfg.audit.pseudonymize_ip = true;
    if let Some(profile) = cfg.compliance.as_mut() {
        profile.pii_pseudonymize = true;
    }
    Ok(())
}

/// True when audit pipeline is configured for PHI-safe writes.
pub fn phi_safe(cfg: &WafConfig) -> bool {
    cfg.audit.pseudonymize_ip
        && cfg
            .compliance
            .as_ref()
            .map(|p| p.pii_pseudonymize)
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::{ComplianceMode, ComplianceProfile};

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
            modes: vec![ComplianceMode::Hipaa],
            min_tls_version: None,
            disallow_algorithms: Vec::new(),
            pii_pseudonymize: false,
        });
        cfg
    }

    #[test]
    fn hipaa_phi_safe_after_apply() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        assert!(phi_safe(&cfg));
    }

    #[test]
    fn hipaa_idempotent() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        apply(&mut cfg).unwrap();
        assert!(phi_safe(&cfg));
    }

    #[test]
    fn default_phi_tags_nonempty() {
        assert!(!DEFAULT_PHI_TAGS.is_empty());
    }
}
