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
    /// 2026-05-17 (core F-CRITICAL-006): v2.3 §3 mandates 6
    /// decision classes; this enum had only 4. `Timeout` is the
    /// action emitted when a request's deadline (read / upstream
    /// / total) elapsed. The mirroring
    /// `aegis_control::interop::headers::Action::Timeout` already
    /// exists (commit ade9883); this lines up the core enum.
    Timeout { deadline_ms: u32 },
    /// 2026-05-17 (core F-CRITICAL-006): v2.3 §3 — emitted when
    /// the WAF declines to send the request upstream because of
    /// upstream-health state (open circuit breaker, no healthy
    /// member). Distinct from `Block` because the rejection is
    /// upstream-protection, not client-attribution. Mirrors
    /// `aegis_control::interop::headers::Action::CircuitBreaker`.
    CircuitBreaker { retry_after_s: u32 },
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
    fn decision_timeout_carries_deadline_ms() {
        // v2.3 §3 — F-CRITICAL-006 regression.
        let d = Decision {
            action: Action::Timeout { deadline_ms: 30_000 },
            reason: "upstream read timed out".into(),
            rule_id: Some("upstream.read_timeout".into()),
            risk_score: 0,
        };
        assert!(matches!(d.action, Action::Timeout { deadline_ms: 30_000 }));
    }

    #[test]
    fn decision_circuit_breaker_carries_retry_after() {
        // v2.3 §3 — F-CRITICAL-006 regression.
        let d = Decision {
            action: Action::CircuitBreaker { retry_after_s: 5 },
            reason: "no healthy upstream member".into(),
            rule_id: Some("upstream.no_healthy_member".into()),
            risk_score: 0,
        };
        assert!(matches!(d.action, Action::CircuitBreaker { retry_after_s: 5 }));
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
