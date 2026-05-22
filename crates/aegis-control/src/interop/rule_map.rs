//! v2.3 §2.7 + §5.3 — map a data-plane `rule_id` string back to
//! the `(feature, policy)` pair the WAF exposes via
//! `GET /__waf_control/capabilities`. Used in two places:
//!
//! 1. **`X-WAF-Mode` stamping** — the response header MUST reflect
//!    the mode of the policy that produced `X-WAF-Action`, not a
//!    hardcoded global feature. The stamper calls
//!    [`mode_for_rule`] with the firing `rule_id` to look up the
//!    correct mode.
//!
//! 2. **`log_only` enforcement skip** — when the firing rule's
//!    feature/policy is in `log_only` mode, the data plane MUST
//!    record + audit the intended `block`/`challenge`/etc. but
//!    forward the request to upstream. Each block exit point in
//!    `aegis-proxy::data_plane` calls [`mode_for_rule`] before
//!    deciding whether to enforce.
//!
//! Returning `None` from [`rule_to_feature`] means "this rule_id
//! is a system-level signal (e.g. `body-too-large`,
//! `no-healthy-upstream`) that doesn't map to any toggleable
//! feature." Callers SHOULD treat that as `Mode::Enforce` — these
//! are non-policy decisions and the contract's `log_only` knob
//! does not apply.

use super::headers::Mode;
use super::mode::ModeStore;

/// Map a data-plane `rule_id` to the `(feature, policy)` pair
/// surfaced by the v2.3 capabilities response. Returns `None` for
/// rule_ids that don't correspond to a toggleable feature.
///
/// Multi-detector rule_ids (e.g. `"sqli,xss"`) are mapped via the
/// first comma-separated segment — that's the primary detector
/// that fired the strongest signal.
pub fn rule_to_feature(rule_id: &str) -> Option<(&'static str, &'static str)> {
    let primary = rule_id.split(',').next().unwrap_or(rule_id).trim();
    Some(match primary {
        // ---- access_control ----
        "blacklist" => ("access_control", "blacklist"),
        "whitelist" => ("access_control", "whitelist"),

        // ---- rules_engine ----
        "sqli" => ("rules_engine", "sqli"),
        "xss" => ("rules_engine", "xss"),
        "path_traversal" => ("rules_engine", "path_traversal"),
        "ssrf" => ("rules_engine", "ssrf"),
        "header_injection" | "header_inj" => ("rules_engine", "header_injection"),
        "body_abuse" | "xxe" | "mass_assignment" => ("rules_engine", "body_abuse"),
        "recon" => ("rules_engine", "recon"),
        "brute_force" | "brute-force" => ("rules_engine", "brute_force"),
        "ai" => ("rules_engine", "ai"),
        "command_injection" | "cmdi" => ("rules_engine", "command_injection"),
        "template_injection" | "ssti" => ("rules_engine", "template_injection"),
        "nosql_injection" | "nosqli" => ("rules_engine", "nosql_injection"),
        "open_redirect" | "openredir" => ("rules_engine", "open_redirect"),

        // 2026-05-20 — Phase-F detectors (committee interop fix).
        // canary / velocity / behavior_signals can fire AND block,
        // so the BTC must be able to see them in `capabilities` and
        // flip them enforce↔log_only via `set_profile`. Previously
        // these returned `None` → hard-pinned to Enforce, so a phase
        // that log_only'd "everything but SQLi" would still block on
        // them. velocity + behavior_signals emit dynamic per-rule
        // tags (`velocity_login_to_withdrawal`, `behavior_no_ua`, …)
        // so they match by prefix; proto_pollution is emitted by the
        // body_abuse detector and shares that policy.
        "canary" => ("rules_engine", "canary"),
        "proto_pollution" => ("rules_engine", "body_abuse"),
        p if p.starts_with("velocity_") => ("rules_engine", "velocity"),
        p if p.starts_with("behavior_") => ("rules_engine", "behavior_signals"),

        // ---- rate_limit ----
        "ip-rate-limit" | "rate_limit" => ("rate_limit", "per_ip"),

        // ---- risk_engine ----
        "risk-strikes" => ("risk_engine", "strikes"),
        "risk-score" | "risk-challenge" => ("risk_engine", "score"),

        // ---- ddos ----
        "ddos" => ("ddos", "per_ip"),

        // System-level signals (body-too-large, mtls_required,
        // websocket_*, unmatched_route, …) — not toggleable by
        // policy, always enforce.
        _ => return None,
    })
}

/// Resolve the effective mode for the firing rule. System-level
/// rule_ids that don't map to a toggleable feature default to
/// `Mode::Enforce` — operators can't disable engine-level safety
/// gates via the contract's `set_profile`.
pub fn mode_for_rule(modes: &ModeStore, rule_id: Option<&str>) -> Mode {
    // No policy fired (e.g. a clean `allow`) → reflect the ambient
    // default mode, so a global `set_profile {scope:all, mode:log_only}`
    // is visible as `X-WAF-Mode: log_only` on EVERY response, not just
    // the policy-blocked ones. Pre-fix this hardcoded `Enforce`, so a
    // benign response contradicted the operator's global log_only toggle.
    let Some(id) = rule_id else { return modes.current().default };
    // A rule_id that maps to no toggleable feature is an engine-level
    // safety gate — operators can't log_only it via set_profile, so it
    // stays `Enforce` regardless of the default.
    let Some((feat, pol)) = rule_to_feature(id) else {
        return Mode::Enforce;
    };
    modes.resolve(feat, Some(pol))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_class_maps_to_rules_engine() {
        assert_eq!(rule_to_feature("sqli"), Some(("rules_engine", "sqli")));
        assert_eq!(rule_to_feature("xss"), Some(("rules_engine", "xss")));
        assert_eq!(
            rule_to_feature("path_traversal"),
            Some(("rules_engine", "path_traversal")),
        );
    }

    #[test]
    fn ai_detector_maps_to_rules_engine_ai() {
        // v2.3 §2.5 — AI must be a toggleable policy so the OC harness
        // can put it into log_only without a YAML edit + restart.
        assert_eq!(rule_to_feature("ai"), Some(("rules_engine", "ai")));
    }

    #[test]
    fn command_injection_maps_to_rules_engine() {
        // SEC-M002 (2026-05-08) — dedicated cmdi class. Must be
        // toggleable via set_profile so operators can move it
        // into log_only without a config edit.
        assert_eq!(
            rule_to_feature("command_injection"),
            Some(("rules_engine", "command_injection")),
        );
        // Short alias for compatibility with detector code that
        // uses the abbreviated form.
        assert_eq!(
            rule_to_feature("cmdi"),
            Some(("rules_engine", "command_injection")),
        );
    }

    #[test]
    fn template_injection_maps_to_rules_engine() {
        // GAP-006 (2026-05-08) — dedicated SSTI class.
        assert_eq!(
            rule_to_feature("template_injection"),
            Some(("rules_engine", "template_injection")),
        );
        assert_eq!(
            rule_to_feature("ssti"),
            Some(("rules_engine", "template_injection")),
        );
    }

    #[test]
    fn nosql_injection_maps_to_rules_engine() {
        // GAP-007 (2026-05-08) — dedicated NoSQL class.
        assert_eq!(
            rule_to_feature("nosql_injection"),
            Some(("rules_engine", "nosql_injection")),
        );
        assert_eq!(
            rule_to_feature("nosqli"),
            Some(("rules_engine", "nosql_injection")),
        );
    }

    #[test]
    fn open_redirect_maps_to_rules_engine() {
        // GAP-009 (2026-05-09) — dedicated open-redirect class.
        assert_eq!(
            rule_to_feature("open_redirect"),
            Some(("rules_engine", "open_redirect")),
        );
        assert_eq!(
            rule_to_feature("openredir"),
            Some(("rules_engine", "open_redirect")),
        );
    }

    #[test]
    fn phase_f_detectors_map_to_rules_engine() {
        // 2026-05-20 committee interop fix — canary / velocity /
        // behavior_signals must be toggleable so the BTC can put
        // them into log_only during a focused test phase.
        assert_eq!(
            rule_to_feature("canary"),
            Some(("rules_engine", "canary")),
        );
        // velocity + behavior_signals emit dynamic per-rule tags;
        // they map to the single policy name by prefix.
        assert_eq!(
            rule_to_feature("velocity_login_to_withdrawal"),
            Some(("rules_engine", "velocity")),
        );
        assert_eq!(
            rule_to_feature("velocity_login_to_deposit"),
            Some(("rules_engine", "velocity")),
        );
        assert_eq!(
            rule_to_feature("behavior_no_ua"),
            Some(("rules_engine", "behavior_signals")),
        );
        assert_eq!(
            rule_to_feature("behavior_zero_depth"),
            Some(("rules_engine", "behavior_signals")),
        );
        // proto_pollution rides the body_abuse policy (same detector).
        assert_eq!(
            rule_to_feature("proto_pollution"),
            Some(("rules_engine", "body_abuse")),
        );
    }

    #[test]
    fn phase_f_log_only_is_honoured() {
        // End-to-end: a set_profile that log_only's velocity must
        // make the data-plane mode lookup return LogOnly for a
        // dynamic velocity tag.
        let store = ModeStore::new(Mode::Enforce);
        store.set_policy("rules_engine", "velocity", Mode::LogOnly);
        assert_eq!(
            mode_for_rule(&store, Some("velocity_login_to_withdrawal")),
            Mode::LogOnly,
        );
        // canary still enforces because only velocity was flipped.
        assert_eq!(mode_for_rule(&store, Some("canary")), Mode::Enforce);
    }

    #[test]
    fn comma_joined_rule_uses_first_segment() {
        assert_eq!(
            rule_to_feature("sqli,xss"),
            Some(("rules_engine", "sqli")),
        );
        assert_eq!(
            rule_to_feature("path_traversal,ssrf,xxe"),
            Some(("rules_engine", "path_traversal")),
        );
    }

    #[test]
    fn legacy_alias_normalises() {
        // `header_inj` is the audit-log abbreviation; capabilities
        // expose `header_injection`.
        assert_eq!(
            rule_to_feature("header_inj"),
            Some(("rules_engine", "header_injection")),
        );
        // xxe / mass_assignment are real detector tags but the
        // capabilities surface bundles them under body_abuse.
        assert_eq!(
            rule_to_feature("xxe"),
            Some(("rules_engine", "body_abuse")),
        );
    }

    #[test]
    fn access_control_rule_ids_route_correctly() {
        assert_eq!(
            rule_to_feature("blacklist"),
            Some(("access_control", "blacklist")),
        );
    }

    #[test]
    fn rate_limit_rule_id_routes_correctly() {
        assert_eq!(
            rule_to_feature("ip-rate-limit"),
            Some(("rate_limit", "per_ip")),
        );
    }

    #[test]
    fn ddos_rule_id_routes_to_ddos_feature() {
        assert_eq!(rule_to_feature("ddos"), Some(("ddos", "per_ip")));
        // log_only on the ddos feature resolves for the ddos rule_id.
        let store = ModeStore::new(Mode::Enforce);
        store.set_feature("ddos", Mode::LogOnly);
        assert_eq!(mode_for_rule(&store, Some("ddos")), Mode::LogOnly);
        // other features unaffected.
        assert_eq!(mode_for_rule(&store, Some("sqli")), Mode::Enforce);
    }

    #[test]
    fn risk_score_vs_strikes() {
        assert_eq!(
            rule_to_feature("risk-strikes"),
            Some(("risk_engine", "strikes")),
        );
        assert_eq!(
            rule_to_feature("risk-score"),
            Some(("risk_engine", "score")),
        );
        assert_eq!(
            rule_to_feature("risk-challenge"),
            Some(("risk_engine", "score")),
        );
    }

    #[test]
    fn system_level_rule_returns_none() {
        assert_eq!(rule_to_feature("body-too-large"), None);
        assert_eq!(rule_to_feature("mtls_required"), None);
        assert_eq!(rule_to_feature("unmatched_route"), None);
        assert_eq!(rule_to_feature("websocket_no_upstream_pool"), None);
    }

    #[test]
    fn mode_for_rule_unmapped_stays_enforce_but_none_follows_default() {
        let store = ModeStore::new(Mode::LogOnly);
        // Unknown/system rule_id — engine-level safety gate; ignores the
        // LogOnly default (operators can't log_only it via set_profile).
        assert_eq!(mode_for_rule(&store, Some("body-too-large")), Mode::Enforce);
        // None rule_id (a clean `allow`, no policy fired) — reflects the
        // ambient default, so a global `set_profile {scope:all,
        // mode:log_only}` is visible as log_only on EVERY response (DR-T3),
        // not contradicted by benign traffic.
        assert_eq!(mode_for_rule(&store, None), Mode::LogOnly);
        // With an enforce default, None → enforce.
        let store_enforce = ModeStore::new(Mode::Enforce);
        assert_eq!(mode_for_rule(&store_enforce, None), Mode::Enforce);
    }

    #[test]
    fn mode_for_rule_respects_per_feature_override() {
        let store = ModeStore::new(Mode::Enforce);
        store.set_feature("rules_engine", Mode::LogOnly);
        assert_eq!(mode_for_rule(&store, Some("sqli")), Mode::LogOnly);
        assert_eq!(mode_for_rule(&store, Some("xss")), Mode::LogOnly);
        // access_control still enforce
        assert_eq!(mode_for_rule(&store, Some("blacklist")), Mode::Enforce);
    }

    #[test]
    fn mode_for_rule_respects_per_policy_override() {
        let store = ModeStore::new(Mode::Enforce);
        store.set_policy("rules_engine", "sqli", Mode::LogOnly);
        // Only sqli is log_only.
        assert_eq!(mode_for_rule(&store, Some("sqli")), Mode::LogOnly);
        assert_eq!(mode_for_rule(&store, Some("xss")), Mode::Enforce);
    }
}
