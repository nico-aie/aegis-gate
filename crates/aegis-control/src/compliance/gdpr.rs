//! GDPR profile.
//!
//! - PII pseudonymization in audit logs.
//! - Data residency pin required (validated by the residency module).

use aegis_core::{config::WafConfig, Result};

/// Apply GDPR settings to `cfg`.
pub fn apply(cfg: &mut WafConfig) -> Result<()> {
    cfg.audit.pseudonymize_ip = true;
    if let Some(profile) = cfg.compliance.as_mut() {
        profile.pii_pseudonymize = true;
    }
    Ok(())
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
            modes: vec![ComplianceMode::Gdpr],
            min_tls_version: None,
            disallow_algorithms: Vec::new(),
            pii_pseudonymize: false,
        });
        cfg
    }

    #[test]
    fn gdpr_enables_pseudonymize() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        assert!(cfg.audit.pseudonymize_ip);
        assert!(cfg.compliance.as_ref().unwrap().pii_pseudonymize);
    }

    #[test]
    fn gdpr_idempotent() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        apply(&mut cfg).unwrap();
        assert!(cfg.audit.pseudonymize_ip);
    }
}
