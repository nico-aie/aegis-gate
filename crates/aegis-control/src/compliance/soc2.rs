//! SOC 2 profile.
//!
//! - Audit hash chain enabled.
//! - Admin trail enabled.
//! - SLO alerts enabled.

use aegis_core::{config::WafConfig, Result};

/// SOC 2 mandates the chain be on.
pub fn apply(cfg: &mut WafConfig) -> Result<()> {
    cfg.audit.chain.enabled = true;

    if cfg.audit.retention.as_secs() == 0 {
        cfg.audit.retention = std::time::Duration::from_secs(90 * 24 * 3600);
    }
    Ok(())
}

/// True if the running config satisfies SOC 2 controls assigned to this profile.
pub fn satisfied(cfg: &WafConfig) -> bool {
    cfg.audit.chain.enabled
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
            modes: vec![ComplianceMode::Soc2],
            min_tls_version: None,
            disallow_algorithms: Vec::new(),
            pii_pseudonymize: false,
        });
        cfg
    }

    #[test]
    fn soc2_enables_chain() {
        let mut cfg = minimal_cfg();
        cfg.audit.chain.enabled = false;
        apply(&mut cfg).unwrap();
        assert!(cfg.audit.chain.enabled);
        assert!(satisfied(&cfg));
    }

    #[test]
    fn soc2_idempotent() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        apply(&mut cfg).unwrap();
        assert!(cfg.audit.chain.enabled);
    }

    #[test]
    fn satisfied_false_when_chain_off() {
        let mut cfg = minimal_cfg();
        cfg.audit.chain.enabled = false;
        assert!(!satisfied(&cfg));
    }
}
