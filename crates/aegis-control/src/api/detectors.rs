//! `/api/detectors` — read + flip the live detector class mask
//! (P2 of the security-toggle plan).
//!
//! GET returns the current mask snapshot. PUT swaps the
//! [`SharedDetectorMask`] atomically; the data-plane filter picks
//! up the change on its next request without a restart.
//!
//! The PUT handler is invoked by the proxy admin_router after
//! [`crate::api::mutation::AuditedMutate::apply`] passes — this
//! module returns the rendered `Result` so the caller can map
//! `Ok` → `200` and `Err` to the standard error envelope.
//!
//! # Compliance clamp
//!
//! When the active config carries a non-empty `compliance.modes`,
//! certain classes can't be turned off: SQLi, XSS, path traversal,
//! and SSRF are required by every supported regime (PCI / HIPAA /
//! SOC 2 / GDPR / FIPS). The control plane refuses such PUTs with
//! `validation` and lists the offending classes in the message —
//! the dashboard renders those toggles disabled with a tooltip.

#![allow(dead_code)]

use aegis_core::config::ComplianceMode;
use aegis_core::tier::Tier;
use aegis_security::detectors::{
    tier_str, DetectorClass, DetectorMask, DetectorMaskBody, MaskState, SharedDetectorMask,
    ALL_TIERS,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// JSON shape returned by `GET /api/detectors`.
#[derive(Clone, Debug, Serialize)]
pub struct DetectorsResponse {
    pub mask: DetectorMaskBody,
    /// Per-tier overrides (P3). Missing keys fall back to `mask`.
    /// Order is stable: `critical`, `high`, `medium`, `catch_all`.
    pub overrides: BTreeMap<&'static str, DetectorMaskBody>,
    /// Classes that the active compliance profile forbids
    /// disabling. Renders as a `disabled` toggle on the dashboard.
    pub locked_classes: Vec<&'static str>,
    /// Active compliance modes — informational, mirrors
    /// `cfg.compliance.modes`.
    pub compliance_modes: Vec<&'static str>,
}

/// JSON shape accepted by `PUT /api/detectors`. Both fields are
/// optional: omit `mask` to keep the base mask, omit a tier under
/// `overrides` (or pass `null`) to clear that tier's override.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DetectorsPutBody {
    #[serde(default)]
    pub mask: Option<DetectorMaskBody>,
    /// Tier-keyed overrides. `null` value clears the override for
    /// that tier; missing key leaves it untouched.
    #[serde(default)]
    pub overrides: BTreeMap<String, Option<DetectorMaskBody>>,
}

/// Classes any compliance profile pins to "always on". Drawn from
/// the cross-section of PCI 6.5, HIPAA §164.312, SOC 2 CC 6.1, and
/// GDPR Art. 32(1)(b) detection mandates.
const COMPLIANCE_PINNED: &[DetectorClass] = &[
    DetectorClass::Sqli,
    DetectorClass::Xss,
    DetectorClass::PathTraversal,
    DetectorClass::Ssrf,
];

/// `true` if the active modes pin a class to "always on".
pub fn is_locked(class: DetectorClass, modes: &[ComplianceMode]) -> bool {
    !modes.is_empty() && COMPLIANCE_PINNED.contains(&class)
}

/// Validate a proposed mask against compliance constraints.
/// Returns the list of locked classes the proposal tried to
/// disable, or `Ok(())` if the proposal respects every clamp.
pub fn enforce_compliance_clamp(
    proposed: DetectorMask,
    modes: &[ComplianceMode],
) -> Result<(), Vec<&'static str>> {
    if modes.is_empty() {
        return Ok(());
    }
    let mut violations = Vec::new();
    for &class in COMPLIANCE_PINNED {
        if !proposed.is_enabled(class) {
            violations.push(class.as_str());
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Render the GET payload from a live mask snapshot.
pub fn render_get(mask: &SharedDetectorMask, modes: &[ComplianceMode]) -> String {
    let state = mask.load_state();
    let mut overrides: BTreeMap<&'static str, DetectorMaskBody> = BTreeMap::new();
    for tier in ALL_TIERS {
        if let Some(m) = state.override_for(tier) {
            overrides.insert(tier_str(tier), m.into());
        }
    }
    let body = DetectorsResponse {
        mask: state.base.into(),
        overrides,
        locked_classes: COMPLIANCE_PINNED
            .iter()
            .filter(|c| is_locked(**c, modes))
            .map(|c| c.as_str())
            .collect(),
        compliance_modes: modes.iter().map(compliance_mode_str).collect(),
    };
    serde_json::to_string(&body).unwrap_or_else(|_| String::from("{}"))
}

/// Resolve `Tier` from the wire-compatible string used in YAML and
/// the dashboard. Returns `None` for unrecognised values so the
/// PUT handler can reject the body cleanly.
pub fn parse_tier_str(raw: &str) -> Option<Tier> {
    match raw {
        "critical" => Some(Tier::Critical),
        "high" => Some(Tier::High),
        "medium" => Some(Tier::Medium),
        // `catch_all` / `catchall` kept as legacy aliases.
        "low" | "catch_all" | "catchall" => Some(Tier::Low),
        _ => None,
    }
}

/// Apply a parsed PUT body on top of the current state. Returns
/// the new state on success, or a list of human-readable error
/// strings (unknown tier, compliance violation) on failure.
pub fn apply_put_body(
    current: MaskState,
    body: DetectorsPutBody,
    modes: &[ComplianceMode],
) -> Result<MaskState, Vec<String>> {
    let mut errors = Vec::new();
    let mut next = current;

    if let Some(base_body) = body.mask {
        next.base = base_body.into();
    }
    for (tier_raw, override_body) in body.overrides {
        let Some(tier) = parse_tier_str(&tier_raw) else {
            errors.push(format!("unknown tier: {tier_raw}"));
            continue;
        };
        next = next.with_override(tier, override_body.map(DetectorMask::from));
    }

    // Compliance clamp applies to the base AND every override —
    // operators can't loosen pinned classes via per-tier policy
    // either.
    if let Err(violations) = enforce_compliance_clamp(next.base, modes) {
        errors.push(format!(
            "base mask violates compliance: {}",
            violations.join(", ")
        ));
    }
    for tier in ALL_TIERS {
        if let Some(mask) = next.override_for(tier) {
            if let Err(violations) = enforce_compliance_clamp(mask, modes) {
                errors.push(format!(
                    "override[{}] violates compliance: {}",
                    tier_str(tier),
                    violations.join(", ")
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(next)
    } else {
        Err(errors)
    }
}

/// Stable string codes for `ComplianceMode`. Kept here (and not on
/// the enum itself) because the wire codes are dashboard-facing
/// and must outlive any internal renames.
fn compliance_mode_str(m: &ComplianceMode) -> &'static str {
    match m {
        ComplianceMode::Fips => "fips",
        ComplianceMode::Pci => "pci",
        ComplianceMode::Soc2 => "soc2",
        ComplianceMode::Gdpr => "gdpr",
        ComplianceMode::Hipaa => "hipaa",
    }
}

/// Parse a flat PUT body — the P2 wire format — into a candidate
/// base mask. Kept for callers that don't yet understand the
/// per-tier shape.
pub fn parse_put_body(body: &str) -> Result<DetectorMask, String> {
    let parsed: DetectorMaskBody = serde_json::from_str(body).map_err(|e| e.to_string())?;
    Ok(parsed.into())
}

/// Parse the full P3 PUT body shape (`{mask, overrides}`) with a
/// graceful fall-back to the flat P2 shape (`{sqli, xss, …}`) so
/// older scripted callers keep working.
pub fn parse_full_put_body(body: &str) -> Result<DetectorsPutBody, String> {
    let parsed: DetectorsPutBody =
        serde_json::from_str(body).map_err(|e| e.to_string())?;
    if parsed.mask.is_some() || !parsed.overrides.is_empty() {
        return Ok(parsed);
    }
    // Fall back to the flat shape: caller posted a bare mask body.
    if let Ok(flat) = serde_json::from_str::<DetectorMaskBody>(body) {
        return Ok(DetectorsPutBody {
            mask: Some(flat),
            overrides: BTreeMap::new(),
        });
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_get_returns_documented_shape_when_no_compliance() {
        let mask = SharedDetectorMask::default();
        let body = render_get(&mask, &[]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["mask"]["sqli"].as_bool().unwrap());
        assert_eq!(v["locked_classes"].as_array().unwrap().len(), 0);
        assert_eq!(v["compliance_modes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn render_get_pins_locked_classes_under_pci() {
        let mask = SharedDetectorMask::default();
        let body = render_get(&mask, &[ComplianceMode::Pci]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let locked: Vec<&str> = v["locked_classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        // Order matches COMPLIANCE_PINNED — stable for the dashboard.
        assert_eq!(locked, vec!["sqli", "xss", "path_traversal", "ssrf"]);
        assert_eq!(v["compliance_modes"].as_array().unwrap()[0], "pci");
    }

    #[test]
    fn render_get_reports_disabled_classes_in_mask() {
        let mask = SharedDetectorMask::default();
        mask.store(
            DetectorMask::all_enabled().with(DetectorClass::Recon, false),
        );
        let body = render_get(&mask, &[]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(!v["mask"]["recon"].as_bool().unwrap());
        assert!(v["mask"]["sqli"].as_bool().unwrap());
    }

    #[test]
    fn enforce_clamp_passes_when_no_compliance_set() {
        let proposal = DetectorMask::none();
        // Disabling everything is fine if no modes are active.
        assert!(enforce_compliance_clamp(proposal, &[]).is_ok());
    }

    #[test]
    fn enforce_clamp_blocks_disabling_pinned_class() {
        let proposal = DetectorMask::all_enabled().with(DetectorClass::Sqli, false);
        let err = enforce_compliance_clamp(proposal, &[ComplianceMode::Pci]).unwrap_err();
        assert_eq!(err, vec!["sqli"]);
    }

    #[test]
    fn enforce_clamp_reports_all_violations() {
        let proposal = DetectorMask::none();
        let err = enforce_compliance_clamp(proposal, &[ComplianceMode::Hipaa]).unwrap_err();
        assert_eq!(err, vec!["sqli", "xss", "path_traversal", "ssrf"]);
    }

    #[test]
    fn enforce_clamp_allows_disabling_non_pinned_class() {
        let proposal = DetectorMask::all_enabled().with(DetectorClass::Recon, false);
        assert!(enforce_compliance_clamp(proposal, &[ComplianceMode::Pci]).is_ok());
    }

    #[test]
    fn parse_put_body_accepts_partial_shape() {
        // Missing fields default to false — caller is expected to
        // POST the full mask, but tolerate partials gracefully.
        let mask = parse_put_body(r#"{"sqli":true}"#).unwrap();
        assert!(mask.is_enabled(DetectorClass::Sqli));
        assert!(!mask.is_enabled(DetectorClass::Xss));
    }

    #[test]
    fn parse_put_body_rejects_non_json() {
        let err = parse_put_body("not json").unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn is_locked_off_when_no_modes() {
        assert!(!is_locked(DetectorClass::Sqli, &[]));
    }

    #[test]
    fn is_locked_only_for_pinned_classes() {
        let modes = [ComplianceMode::Pci];
        assert!(is_locked(DetectorClass::Sqli, &modes));
        assert!(!is_locked(DetectorClass::Recon, &modes));
        assert!(!is_locked(DetectorClass::BruteForce, &modes));
    }

    // ---------- P3 per-tier overrides ----------------------------------

    #[test]
    fn render_get_includes_empty_overrides_when_none_set() {
        let mask = SharedDetectorMask::default();
        let body = render_get(&mask, &[]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["overrides"].as_object().unwrap().is_empty());
    }

    #[test]
    fn render_get_serializes_per_tier_overrides() {
        let mask = SharedDetectorMask::default();
        mask.set_override(
            Tier::Medium,
            Some(DetectorMask::all_enabled().with(DetectorClass::Recon, false)),
        );
        let body = render_get(&mask, &[]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let medium = &v["overrides"]["medium"];
        assert!(medium.is_object(), "medium override missing in payload");
        assert!(!medium["recon"].as_bool().unwrap());
        assert!(medium["sqli"].as_bool().unwrap());
        // Other tiers absent — they fall back to base.
        assert!(v["overrides"].get("high").is_none());
    }

    #[test]
    fn parse_tier_str_round_trip() {
        for tier in ALL_TIERS {
            assert_eq!(parse_tier_str(tier_str(tier)), Some(tier));
        }
        assert_eq!(parse_tier_str("nope"), None);
    }

    #[test]
    fn apply_put_body_sets_override_for_named_tier() {
        let initial = MaskState::default();
        let mut body = DetectorsPutBody::default();
        body.overrides.insert(
            "medium".into(),
            Some(DetectorMaskBody {
                sqli: true,
                xss: true,
                path_traversal: true,
                ssrf: true,
                header_injection: true,
                body_abuse: true,
                recon: false,
                brute_force: true,
                command_injection: true,
                template_injection: true,
                nosql_injection: true,
            }),
        );
        let next = apply_put_body(initial, body, &[]).unwrap();
        let medium = next.override_for(Tier::Medium).unwrap();
        assert!(medium.is_enabled(DetectorClass::Sqli));
        assert!(!medium.is_enabled(DetectorClass::Recon));
        // Other tiers untouched.
        assert!(next.override_for(Tier::High).is_none());
    }

    #[test]
    fn apply_put_body_clears_override_when_value_is_null() {
        let initial = MaskState::default()
            .with_override(Tier::High, Some(DetectorMask::none()));
        let mut body = DetectorsPutBody::default();
        body.overrides.insert("high".into(), None);
        let next = apply_put_body(initial, body, &[]).unwrap();
        assert!(next.override_for(Tier::High).is_none());
    }

    #[test]
    fn apply_put_body_rejects_unknown_tier_name() {
        let mut body = DetectorsPutBody::default();
        body.overrides.insert("paranoid".into(), None);
        let err = apply_put_body(MaskState::default(), body, &[]).unwrap_err();
        assert!(err.iter().any(|e| e.contains("unknown tier")));
    }

    #[test]
    fn apply_put_body_clamps_overrides_against_compliance() {
        // Even at a single tier, dropping a pinned class is forbidden
        // when compliance mode is active.
        let mut body = DetectorsPutBody::default();
        body.overrides.insert(
            "high".into(),
            Some(DetectorMaskBody {
                sqli: false,
                xss: true,
                path_traversal: true,
                ssrf: true,
                header_injection: true,
                body_abuse: true,
                recon: true,
                brute_force: true,
                command_injection: true,
                template_injection: true,
                nosql_injection: true,
            }),
        );
        let err = apply_put_body(
            MaskState::default(),
            body,
            &[ComplianceMode::Pci],
        )
        .unwrap_err();
        assert!(err.iter().any(|e| e.contains("override[high]") && e.contains("sqli")));
    }

    #[test]
    fn apply_put_body_clamps_base_against_compliance() {
        let mut body = DetectorsPutBody::default();
        body.mask = Some(DetectorMaskBody {
            sqli: false,
            xss: true,
            path_traversal: true,
            ssrf: true,
            header_injection: true,
            body_abuse: true,
            recon: true,
            brute_force: true,
            command_injection: true,
            template_injection: true,
            nosql_injection: true,
        });
        let err = apply_put_body(
            MaskState::default(),
            body,
            &[ComplianceMode::Hipaa],
        )
        .unwrap_err();
        assert!(err.iter().any(|e| e.contains("base mask") && e.contains("sqli")));
    }

    #[test]
    fn apply_put_body_full_round_trip_no_compliance() {
        let initial = MaskState::default();
        let json = r#"{
            "mask": {"sqli":true,"xss":true,"path_traversal":true,"ssrf":true,
                      "header_injection":true,"body_abuse":true,"recon":false,
                      "brute_force":true},
            "overrides": {
                "critical": {"sqli":true,"xss":true,"path_traversal":true,
                              "ssrf":true,"header_injection":true,"body_abuse":true,
                              "recon":true,"brute_force":true}
            }
        }"#;
        let parsed: DetectorsPutBody = serde_json::from_str(json).unwrap();
        let next = apply_put_body(initial, parsed, &[]).unwrap();
        assert!(!next.base.is_enabled(DetectorClass::Recon));
        let critical = next.override_for(Tier::Critical).unwrap();
        assert!(critical.is_enabled(DetectorClass::Recon));
    }
}
