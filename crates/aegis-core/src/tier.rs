#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Critical,
    High,
    Medium,
    CatchAll,
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
    fn catch_all_tier_defaults_to_fail_open() {
        assert_eq!(Tier::CatchAll.default_failure_mode(), FailureMode::FailOpen);
    }

    #[test]
    fn tier_deserializes_from_snake_case() {
        let tier: Tier = serde_yaml::from_str("critical").unwrap();
        assert_eq!(tier, Tier::Critical);

        let tier: Tier = serde_yaml::from_str("catch_all").unwrap();
        assert_eq!(tier, Tier::CatchAll);
    }

    #[test]
    fn tier_is_copy() {
        let t = Tier::High;
        let t2 = t;
        assert_eq!(t, t2);
    }
}
