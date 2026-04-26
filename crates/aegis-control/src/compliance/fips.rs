//! FIPS 140-3 profile.
//!
//! Forces the `aws-lc-rs` TLS provider and rejects non-FIPS algorithms.

use aegis_core::{config::WafConfig, Result};

use super::{add_disallowed, version_at_least, FIPS_DISALLOWED, FIPS_TLS_PROVIDER, MIN_TLS_VERSION};

/// Apply FIPS settings to `cfg`.
pub fn apply(cfg: &mut WafConfig) -> Result<()> {
    let profile = cfg
        .compliance
        .as_mut()
        .expect("compliance profile must exist before fips::apply");

    add_disallowed(&mut profile.disallow_algorithms, FIPS_DISALLOWED);

    let needs_bump = match profile.min_tls_version.as_deref() {
        Some(v) => !version_at_least(v, MIN_TLS_VERSION),
        None => true,
    };
    if needs_bump {
        profile.min_tls_version = Some(MIN_TLS_VERSION.to_string());
    }
    Ok(())
}

/// Returns the FIPS-required TLS provider name when FIPS has been applied.
///
/// Detection: every algorithm in [`FIPS_DISALLOWED`] is present in the
/// compliance profile's disallow list.
pub fn provider_for(cfg: &WafConfig) -> Option<&'static str> {
    let profile = cfg.compliance.as_ref()?;
    let all_present = FIPS_DISALLOWED.iter().all(|algo| {
        profile
            .disallow_algorithms
            .iter()
            .any(|a| a.eq_ignore_ascii_case(algo))
    });
    if all_present {
        Some(FIPS_TLS_PROVIDER)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::{ComplianceMode, ComplianceProfile, WafConfig};

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
            modes: vec![ComplianceMode::Fips],
            min_tls_version: None,
            disallow_algorithms: Vec::new(),
            pii_pseudonymize: false,
        });
        cfg
    }

    #[test]
    fn fips_provider_detected_after_apply() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        assert_eq!(provider_for(&cfg), Some(FIPS_TLS_PROVIDER));
    }

    #[test]
    fn fips_provider_none_without_apply() {
        let cfg = minimal_cfg();
        assert!(provider_for(&cfg).is_none());
    }

    #[test]
    fn fips_disallows_legacy_algos() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        let p = cfg.compliance.as_ref().unwrap();
        for algo in FIPS_DISALLOWED {
            assert!(p.disallow_algorithms.iter().any(|a| a == algo));
        }
    }

    #[test]
    fn fips_sets_min_tls_when_unset() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        assert_eq!(
            cfg.compliance.as_ref().unwrap().min_tls_version.as_deref(),
            Some(MIN_TLS_VERSION)
        );
    }

    #[test]
    fn fips_does_not_lower_higher_min_tls() {
        let mut cfg = minimal_cfg();
        cfg.compliance.as_mut().unwrap().min_tls_version = Some("1.3".into());
        apply(&mut cfg).unwrap();
        assert_eq!(
            cfg.compliance.as_ref().unwrap().min_tls_version.as_deref(),
            Some("1.3")
        );
    }

    #[test]
    fn fips_idempotent() {
        let mut cfg = minimal_cfg();
        apply(&mut cfg).unwrap();
        let len = cfg.compliance.as_ref().unwrap().disallow_algorithms.len();
        apply(&mut cfg).unwrap();
        assert_eq!(
            cfg.compliance.as_ref().unwrap().disallow_algorithms.len(),
            len
        );
    }
}
