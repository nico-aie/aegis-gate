#[derive(Clone, Debug)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    pub rule_id: Option<String>,
    pub risk_score: u32,
}

#[derive(Clone, Debug)]
pub enum Action {
    Allow,
    Block { status: u16 },
    Challenge { level: ChallengeLevel },
    RateLimited { retry_after_s: u32 },
}

#[derive(Copy, Clone, Debug)]
pub enum ChallengeLevel {
    Js,
    Pow,
    Captcha,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_allow_has_zero_risk() {
        let d = Decision {
            action: Action::Allow,
            reason: "clean request".into(),
            rule_id: None,
            risk_score: 0,
        };
        assert_eq!(d.risk_score, 0);
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn decision_block_carries_status() {
        let d = Decision {
            action: Action::Block { status: 403 },
            reason: "sqli detected".into(),
            rule_id: Some("sqli-1".into()),
            risk_score: 85,
        };
        assert!(matches!(d.action, Action::Block { status: 403 }));
        assert_eq!(d.rule_id.as_deref(), Some("sqli-1"));
    }

    #[test]
    fn decision_challenge_levels() {
        let js = Action::Challenge { level: ChallengeLevel::Js };
        let pow = Action::Challenge { level: ChallengeLevel::Pow };
        let captcha = Action::Challenge { level: ChallengeLevel::Captcha };

        assert!(matches!(js, Action::Challenge { level: ChallengeLevel::Js }));
        assert!(matches!(pow, Action::Challenge { level: ChallengeLevel::Pow }));
        assert!(matches!(captcha, Action::Challenge { level: ChallengeLevel::Captcha }));
    }

    #[test]
    fn decision_rate_limited_has_retry_after() {
        let d = Decision {
            action: Action::RateLimited { retry_after_s: 60 },
            reason: "rate exceeded".into(),
            rule_id: Some("rl-global".into()),
            risk_score: 45,
        };
        assert!(matches!(d.action, Action::RateLimited { retry_after_s: 60 }));
    }

    #[test]
    fn decision_is_clone() {
        let d = Decision {
            action: Action::Allow,
            reason: "test".into(),
            rule_id: None,
            risk_score: 10,
        };
        let d2 = d.clone();
        assert_eq!(d2.reason, "test");
    }
}
