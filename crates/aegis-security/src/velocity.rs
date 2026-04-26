use std::time::Duration;

use aegis_core::state::StateBackend;

/// A velocity rule: max N actions within a window.
#[derive(Clone, Debug)]
pub struct VelocityRule {
    pub id: String,
    pub action_name: String,
    pub limit: u64,
    pub window_s: u32,
    /// Risk score to add on breach.
    pub risk_delta: u32,
    /// Whether to block on breach.
    pub block_on_breach: bool,
}

/// Result of a velocity check.
#[derive(Debug)]
pub struct VelocityResult {
    pub allowed: bool,
    pub count: u64,
    pub rule_id: String,
    pub risk_delta: u32,
}

/// Check transaction velocity for a given user/action.
///
/// `discriminator`: typically `{user_id}` or `{ip}:{action}`.
pub async fn check(
    state: &dyn StateBackend,
    rule: &VelocityRule,
    discriminator: &str,
) -> aegis_core::Result<VelocityResult> {
    let key = format!("vel:{}:{}", rule.id, discriminator);
    let window = Duration::from_secs(u64::from(rule.window_s));
    let result = state.incr_window(&key, window, rule.limit).await?;

    let allowed = if rule.block_on_breach {
        result.allowed
    } else {
        true // just raise risk, don't block
    };

    Ok(VelocityResult {
        allowed,
        count: result.count,
        rule_id: rule.id.clone(),
        risk_delta: if !result.allowed { rule.risk_delta } else { 0 },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    struct MockState {
        windows: Mutex<HashMap<String, (u64, Instant)>>,
    }

    impl MockState {
        fn new() -> Self {
            Self {
                windows: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl StateBackend for MockState {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, key: &str, window: Duration, limit: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            let mut map = self.windows.lock().unwrap();
            let now = Instant::now();
            let entry = map.entry(key.to_string()).or_insert((0, now));
            if now.duration_since(entry.1) > window {
                entry.0 = 0;
                entry.1 = now;
            }
            entry.0 += 1;
            Ok(aegis_core::SlidingWindowResult {
                count: entry.0,
                allowed: entry.0 <= limit,
                retry_after: None,
            })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _k: &aegis_core::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _k: &aegis_core::RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _ip: std::net::IpAddr, _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: std::net::IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _n: &str, _t: Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _n: &str) -> aegis_core::Result<bool> { Ok(true) }
    }

    fn deposit_rule() -> VelocityRule {
        VelocityRule {
            id: "deposit-limit".into(),
            action_name: "deposit".into(),
            limit: 10,
            window_s: 300, // 5 min
            risk_delta: 50,
            block_on_breach: true,
        }
    }

    fn login_rule() -> VelocityRule {
        VelocityRule {
            id: "login-limit".into(),
            action_name: "login".into(),
            limit: 5,
            window_s: 60,
            risk_delta: 30,
            block_on_breach: false, // risk only
        }
    }

    #[tokio::test]
    async fn under_limit_allowed() {
        let state = MockState::new();
        let rule = deposit_rule();
        for _ in 0..10 {
            let r = check(&state, &rule, "user-1").await.unwrap();
            assert!(r.allowed);
            assert_eq!(r.risk_delta, 0);
        }
    }

    #[tokio::test]
    async fn exceed_limit_blocked() {
        let state = MockState::new();
        let rule = deposit_rule();
        for _ in 0..10 {
            check(&state, &rule, "user-2").await.unwrap();
        }
        let r = check(&state, &rule, "user-2").await.unwrap();
        assert!(!r.allowed);
        assert_eq!(r.risk_delta, 50);
        assert_eq!(r.count, 11);
    }

    #[tokio::test]
    async fn risk_only_rule_allows_but_adds_risk() {
        let state = MockState::new();
        let rule = login_rule();
        for _ in 0..5 {
            check(&state, &rule, "user-3").await.unwrap();
        }
        let r = check(&state, &rule, "user-3").await.unwrap();
        assert!(r.allowed); // block_on_breach is false
        assert_eq!(r.risk_delta, 30);
    }

    #[tokio::test]
    async fn different_users_independent() {
        let state = MockState::new();
        let rule = deposit_rule();
        for _ in 0..10 {
            check(&state, &rule, "user-a").await.unwrap();
        }
        // user-a is at limit, user-b is fresh.
        let ra = check(&state, &rule, "user-a").await.unwrap();
        let rb = check(&state, &rule, "user-b").await.unwrap();
        assert!(!ra.allowed);
        assert!(rb.allowed);
    }

    #[tokio::test]
    async fn multiple_deposits_from_one_user_blocks() {
        let state = MockState::new();
        let rule = deposit_rule();
        let mut blocked = false;
        for i in 0..15 {
            let r = check(&state, &rule, "heavy-depositor").await.unwrap();
            if !r.allowed {
                blocked = true;
                assert!(i >= 10, "blocked too early at request {i}");
                break;
            }
        }
        assert!(blocked, "should have been blocked");
    }

    #[tokio::test]
    async fn rule_id_in_result() {
        let state = MockState::new();
        let rule = deposit_rule();
        let r = check(&state, &rule, "user-x").await.unwrap();
        assert_eq!(r.rule_id, "deposit-limit");
    }
}
