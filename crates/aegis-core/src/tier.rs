#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Critical,
    High,
    Medium,
    /// 2026-05-04: renamed from `CatchAll` → `Low`. The role-based
    /// "fallback for unmatched paths" name conflated the security
    /// level with the routing role; the routing role now lives on
    /// `RouteConfig.default: bool` (PR2). Tiers are pure
    /// risk-level labels: critical / high / medium / low.
    /// `catch_all` is kept as a serde alias for backward compat —
    /// existing YAML configs with `tier_override: catch_all`
    /// keep parsing without changes.
    #[serde(alias = "catch_all", alias = "catchall")]
    Low,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FailureMode {
    FailClose,
    FailOpen,
}

impl Tier {
    pub fn default_failure_mode(self) -> FailureMode {
        match self {
            Tier::Critical => FailureMode::FailClose,
            _ => FailureMode::FailOpen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_tier_defaults_to_fail_close() {
        assert_eq!(Tier::Critical.default_failure_mode(), FailureMode::FailClose);
    }

    #[test]
    fn high_tier_defaults_to_fail_open() {
        assert_eq!(Tier::High.default_failure_mode(), FailureMode::FailOpen);
    }

    #[test]
    fn medium_tier_defaults_to_fail_open() {
        assert_eq!(Tier::Medium.default_failure_mode(), FailureMode::FailOpen);
    }

    #[test]
    fn low_tier_defaults_to_fail_open() {
        assert_eq!(Tier::Low.default_failure_mode(), FailureMode::FailOpen);
    }

    #[test]
    fn tier_deserializes_from_snake_case() {
        let tier: Tier = serde_yaml::from_str("critical").unwrap();
        assert_eq!(tier, Tier::Critical);

        let tier: Tier = serde_yaml::from_str("low").unwrap();
        assert_eq!(tier, Tier::Low);
    }

    /// Backward-compat — YAML configs with `tier_override: catch_all`
    /// still deserialize to `Tier::Low` so old configs keep working.
    #[test]
    fn tier_accepts_legacy_catch_all_alias() {
        let tier: Tier = serde_yaml::from_str("catch_all").unwrap();
        assert_eq!(tier, Tier::Low);
        let tier: Tier = serde_yaml::from_str("catchall").unwrap();
        assert_eq!(tier, Tier::Low);
    }

    #[test]
    fn tier_is_copy() {
        let t = Tier::High;
        let t2 = t;
        assert_eq!(t, t2);
    }
}
