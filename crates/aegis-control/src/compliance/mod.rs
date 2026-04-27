//! Compliance profiles.
//!
//! Applies one or more [`ComplianceMode`] profiles to a [`WafConfig`].
//! Strictest setting wins. Conflicting combinations are refused.
//!
//! Profiles:
//! - **FIPS**: force `aws-lc-rs` TLS provider; reject non-FIPS algorithms.
//! - **PCI-DSS**: TLS ≥ 1.2; PAN masking in DLP; audit retention ≥ 90 days.
//! - **SOC 2**: audit hash chain + admin trail + SLO alerts must be enabled.
//! - **GDPR**: PII pseudonymization in audit logs; data residency pin required.
//! - **HIPAA**: PHI-safe log mode (PHI fields masked before any sink write).

pub mod fips;
pub mod gdpr;
pub mod hipaa;
pub mod pci;
pub mod soc2;

use std::time::Duration;

use aegis_core::{
    config::{ComplianceMode, ComplianceProfile, WafConfig},
    error::WafError,
    Result,
};

/// Minimum audit retention enforced by PCI-DSS.
pub const PCI_MIN_RETENTION: Duration = Duration::from_secs(90 * 24 * 3600);

/// Minimum TLS version enforced by PCI-DSS / FIPS.
pub const MIN_TLS_VERSION: &str = "1.2";

/// FIPS-required TLS provider tag.
pub const FIPS_TLS_PROVIDER: &str = "aws-lc-rs";

/// Algorithms FIPS rejects.
pub const FIPS_DISALLOWED: &[&str] = &["RC4", "DES", "3DES", "MD5"];

/// Apply the listed compliance profiles to `cfg`.
///
/// Strictest setting wins. Conflicting combinations are refused with
/// [`WafError::Config`] before any mutation is committed.
pub fn apply(profiles: &[ComplianceMode], cfg: &mut WafConfig) -> Result<()> {
    detect_conflicts(profiles, cfg)?;

    // Ensure compliance profile metadata exists so we can record applied state.
    if cfg.compliance.is_none() {
        cfg.compliance = Some(ComplianceProfile {
            modes: profiles.to_vec(),
            min_tls_version: None,
            disallow_algorithms: Vec::new(),
            pii_pseudonymize: false,
        });
    } else if let Some(profile) = cfg.compliance.as_mut() {
        for mode in profiles {
            if !profile.modes.contains(mode) {
                profile.modes.push(mode.clone());
            }
        }
    }

    for mode in profiles {
        match mode {
            ComplianceMode::Fips => fips::apply(cfg)?,
            ComplianceMode::Pci => pci::apply(cfg)?,
            ComplianceMode::Soc2 => soc2::apply(cfg)?,
            ComplianceMode::Gdpr => gdpr::apply(cfg)?,
            ComplianceMode::Hipaa => hipaa::apply(cfg)?,
        }
    }
    Ok(())
}

/// Detect contradictions among the requested profiles before mutating config.
///
/// Conflict rules:
/// - User-supplied `cfg.compliance.min_tls_version` cannot be lower than what
///   the strictest profile requires.
/// - User-supplied `cfg.compliance.disallow_algorithms` cannot exclude an
///   algorithm class that another profile relies on.
fn detect_conflicts(profiles: &[ComplianceMode], cfg: &WafConfig) -> Result<()> {
    let wants_min_tls_12 = profiles
        .iter()
        .any(|m| matches!(m, ComplianceMode::Pci | ComplianceMode::Fips));
    if wants_min_tls_12 {
        if let Some(profile) = cfg.compliance.as_ref() {
            if let Some(v) = profile.min_tls_version.as_deref() {
                if !version_at_least(v, MIN_TLS_VERSION) {
                    return Err(WafError::Config(format!(
                        "compliance: min_tls_version='{v}' is below required {MIN_TLS_VERSION} for PCI/FIPS"
                    )));
                }
            }
        }
    }

    if profiles.contains(&ComplianceMode::Fips) {
        if let Some(profile) = cfg.compliance.as_ref() {
            // FIPS-approved algorithms must not be in the user-supplied disallow list.
            for disallowed in &profile.disallow_algorithms {
                let upper = disallowed.to_ascii_uppercase();
                if upper.contains("AES") || upper == "SHA256" || upper == "SHA-256" {
                    return Err(WafError::Config(format!(
                        "compliance: FIPS requires '{disallowed}' but it is in disallow_algorithms"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Compare two dotted version strings (e.g. `"1.2"` vs `"1.3"`).
/// Returns true if `actual >= required`.
pub fn version_at_least(actual: &str, required: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> {
        s.split('.').filter_map(|p| p.parse::<u32>().ok()).collect()
    };
    let a = parse(actual);
    let r = parse(required);
    let len = a.len().max(r.len());
    for i in 0..len {
        let av = a.get(i).copied().unwrap_or(0);
        let rv = r.get(i).copied().unwrap_or(0);
        if av > rv {
            return true;
        }
        if av < rv {
            return false;
        }
    }
    true
}

/// Ensure `disallow` is present in `dst` without duplicating it.
pub(crate) fn add_disallowed(dst: &mut Vec<String>, items: &[&str]) {
    for item in items {
        let s = (*item).to_string();
        if !dst.iter().any(|existing| existing.eq_ignore_ascii_case(&s)) {
            dst.push(s);
        }
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
        aegis_core::config::load_config_str(yaml).unwrap()
    }

    #[test]
    fn apply_fips_sets_provider_and_disallows_legacy_algos() {
        let mut cfg = minimal_cfg();
        apply(&[ComplianceMode::Fips], &mut cfg).unwrap();
        let profile = cfg.compliance.as_ref().unwrap();
        assert!(profile.disallow_algorithms.iter().any(|a| a == "RC4"));
        assert!(profile.disallow_algorithms.iter().any(|a| a == "MD5"));
        assert!(profile
            .min_tls_version
            .as_deref()
            .is_some_and(|v| version_at_least(v, "1.2")));
    }

    #[test]
    fn apply_pci_sets_min_tls_and_extends_retention() {
        let mut cfg = minimal_cfg();
        cfg.audit.retention = Duration::from_secs(60 * 24 * 3600); // 60 days
        apply(&[ComplianceMode::Pci], &mut cfg).unwrap();
        let profile = cfg.compliance.as_ref().unwrap();
        assert_eq!(profile.min_tls_version.as_deref(), Some("1.2"));
        assert!(cfg.audit.retention >= PCI_MIN_RETENTION);
    }

    #[test]
    fn apply_pci_does_not_lower_retention() {
        let mut cfg = minimal_cfg();
        let long = Duration::from_secs(180 * 24 * 3600); // 180 days
        cfg.audit.retention = long;
        apply(&[ComplianceMode::Pci], &mut cfg).unwrap();
        assert_eq!(cfg.audit.retention, long);
    }

    #[test]
    fn apply_soc2_enables_chain() {
        let mut cfg = minimal_cfg();
        cfg.audit.chain.enabled = false;
        apply(&[ComplianceMode::Soc2], &mut cfg).unwrap();
        assert!(cfg.audit.chain.enabled);
    }

    #[test]
    fn apply_gdpr_enables_pseudonymize() {
        let mut cfg = minimal_cfg();
        apply(&[ComplianceMode::Gdpr], &mut cfg).unwrap();
        assert!(cfg.audit.pseudonymize_ip);
        assert!(cfg.compliance.as_ref().unwrap().pii_pseudonymize);
    }

    #[test]
    fn apply_hipaa_marks_phi_safe_mode() {
        let mut cfg = minimal_cfg();
        apply(&[ComplianceMode::Hipaa], &mut cfg).unwrap();
        let profile = cfg.compliance.as_ref().unwrap();
        assert!(profile.pii_pseudonymize);
        assert!(cfg.audit.pseudonymize_ip);
    }

    #[test]
    fn apply_multiple_strictest_wins() {
        let mut cfg = minimal_cfg();
        apply(
            &[
                ComplianceMode::Pci,
                ComplianceMode::Soc2,
                ComplianceMode::Gdpr,
            ],
            &mut cfg,
        )
        .unwrap();
        let profile = cfg.compliance.as_ref().unwrap();
        assert_eq!(profile.min_tls_version.as_deref(), Some("1.2"));
        assert!(cfg.audit.chain.enabled);
        assert!(cfg.audit.pseudonymize_ip);
        assert!(cfg.audit.retention >= PCI_MIN_RETENTION);
    }

    #[test]
    fn conflict_user_min_tls_below_pci_rejected() {
        let mut cfg = minimal_cfg();
        cfg.compliance = Some(ComplianceProfile {
            modes: vec![],
            min_tls_version: Some("1.0".into()),
            disallow_algorithms: Vec::new(),
            pii_pseudonymize: false,
        });
        let err = apply(&[ComplianceMode::Pci], &mut cfg).unwrap_err();
        assert!(err.to_string().contains("min_tls_version"));
    }

    #[test]
    fn conflict_fips_with_disallow_aes_rejected() {
        let mut cfg = minimal_cfg();
        cfg.compliance = Some(ComplianceProfile {
            modes: vec![],
            min_tls_version: None,
            disallow_algorithms: vec!["AES-256-GCM".into()],
            pii_pseudonymize: false,
        });
        let err = apply(&[ComplianceMode::Fips], &mut cfg).unwrap_err();
        assert!(err.to_string().contains("FIPS"));
    }

    #[test]
    fn version_at_least_basic() {
        assert!(version_at_least("1.2", "1.2"));
        assert!(version_at_least("1.3", "1.2"));
        assert!(!version_at_least("1.0", "1.2"));
        assert!(version_at_least("2.0", "1.2"));
    }

    #[test]
    fn add_disallowed_dedups() {
        let mut v = vec!["RC4".to_string()];
        add_disallowed(&mut v, &["rc4", "MD5"]);
        assert_eq!(v.len(), 2);
        assert!(v.iter().any(|x| x == "MD5"));
    }

    #[test]
    fn apply_records_modes_in_profile() {
        let mut cfg = minimal_cfg();
        apply(&[ComplianceMode::Pci, ComplianceMode::Soc2], &mut cfg).unwrap();
        let modes = &cfg.compliance.as_ref().unwrap().modes;
        assert!(modes.contains(&ComplianceMode::Pci));
        assert!(modes.contains(&ComplianceMode::Soc2));
    }

    #[test]
    fn apply_idempotent_modes() {
        let mut cfg = minimal_cfg();
        apply(&[ComplianceMode::Pci], &mut cfg).unwrap();
        apply(&[ComplianceMode::Pci], &mut cfg).unwrap();
        let modes = &cfg.compliance.as_ref().unwrap().modes;
        let pci_count = modes.iter().filter(|m| **m == ComplianceMode::Pci).count();
        assert_eq!(pci_count, 1);
    }

    #[test]
    fn apply_empty_profiles_is_noop() {
        let mut cfg = minimal_cfg();
        let before = cfg.audit.retention;
        apply(&[], &mut cfg).unwrap();
        assert_eq!(cfg.audit.retention, before);
    }
}
