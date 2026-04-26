use aegis_core::risk::RiskKey;
use aegis_core::state::StateBackend;

use crate::detectors::Signal;

/// Risk engine: accumulate signals into a per-key risk score with decay.
pub struct RiskEngine {
    /// Score half-life in seconds. Default: 300 (5 min).
    pub half_life_s: f64,
    /// Maximum risk score.
    pub max_score: u32,
    /// Canary tags that set score to max immediately.
    pub canary_tags: Vec<String>,
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self {
            half_life_s: 300.0,
            max_score: 100,
            canary_tags: vec![
                "recon_path".into(),
            ],
        }
    }
}

/// Risk thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Allow,
    Challenge,
    Block,
}

impl RiskEngine {
    pub fn new(half_life_s: f64, max_score: u32) -> Self {
        Self {
            half_life_s,
            max_score,
            canary_tags: vec!["recon_path".into()],
        }
    }

    /// Ingest signals and return the updated risk score.
    pub async fn score(
        &self,
        state: &dyn StateBackend,
        key: &RiskKey,
        signals: &[Signal],
    ) -> aegis_core::Result<u32> {
        if signals.is_empty() {
            return state.get_risk(key).await;
        }

        // Check for canary signals → instant max.
        for sig in signals {
            if self.canary_tags.contains(&sig.tag) {
                state.add_risk(key, self.max_score as i32, self.max_score).await?;
                return Ok(self.max_score);
            }
        }

        // Sum signal scores.
        let delta: u32 = signals.iter().map(|s| s.score).sum();
        let new_score = state
            .add_risk(key, delta as i32, self.max_score)
            .await?;

        Ok(new_score)
    }

    /// Classify risk level from score.
    pub fn classify(&self, score: u32) -> RiskLevel {
        if score < 30 {
            RiskLevel::Allow
        } else if score <= 70 {
            RiskLevel::Challenge
        } else {
            RiskLevel::Block
        }
    }

    /// Compute decay factor for a given elapsed time.
    pub fn decay_factor(&self, elapsed_s: f64) -> f64 {
        (-elapsed_s * (2.0_f64.ln()) / self.half_life_s).exp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    struct MockState {
        risks: Mutex<HashMap<String, u32>>,
    }

    impl MockState {
        fn new() -> Self {
            Self {
                risks: Mutex::new(HashMap::new()),
            }
        }
    }

    fn risk_key_str(key: &RiskKey) -> String {
        format!("risk:{}:{:?}:{:?}", key.ip, key.device_fp, key.session)
    }

    #[async_trait::async_trait]
    impl StateBackend for MockState {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _k: &str, _w: Duration, _l: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, key: &RiskKey) -> aegis_core::Result<u32> {
            let k = risk_key_str(key);
            Ok(*self.risks.lock().unwrap().get(&k).unwrap_or(&0))
        }
        async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> aegis_core::Result<u32> {
            let k = risk_key_str(key);
            let mut map = self.risks.lock().unwrap();
            let current = *map.get(&k).unwrap_or(&0);
            let new_val = (current as i64 + delta as i64).clamp(0, max as i64) as u32;
            map.insert(k, new_val);
            Ok(new_val)
        }
        async fn auto_block(&self, _ip: IpAddr, _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _n: &str, _t: Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _n: &str) -> aegis_core::Result<bool> { Ok(true) }
    }

    fn test_key() -> RiskKey {
        RiskKey {
            ip: "10.0.0.1".parse().unwrap(),
            device_fp: None,
            session: None,
            tenant_id: None,
        }
    }

    fn signal(tag: &str, score: u32) -> Signal {
        Signal {
            score,
            tag: tag.into(),
            field: "test".into(),
        }
    }

    #[tokio::test]
    async fn empty_signals_returns_current() {
        let state = MockState::new();
        let engine = RiskEngine::default();
        let s = engine.score(&state, &test_key(), &[]).await.unwrap();
        assert_eq!(s, 0);
    }

    #[tokio::test]
    async fn signals_accumulate() {
        let state = MockState::new();
        let engine = RiskEngine::default();
        let key = test_key();
        engine.score(&state, &key, &[signal("sqli", 40)]).await.unwrap();
        let s = engine.score(&state, &key, &[signal("xss", 35)]).await.unwrap();
        assert_eq!(s, 75);
    }

    #[tokio::test]
    async fn score_capped_at_max() {
        let state = MockState::new();
        let engine = RiskEngine::new(300.0, 100);
        let key = test_key();
        engine.score(&state, &key, &[signal("sqli", 60)]).await.unwrap();
        let s = engine.score(&state, &key, &[signal("xss", 60)]).await.unwrap();
        assert_eq!(s, 100);
    }

    #[tokio::test]
    async fn canary_sets_max() {
        let state = MockState::new();
        let engine = RiskEngine::default();
        let key = test_key();
        let s = engine.score(&state, &key, &[signal("recon_path", 25)]).await.unwrap();
        assert_eq!(s, 100);
    }

    #[test]
    fn classify_thresholds() {
        let engine = RiskEngine::default();
        assert_eq!(engine.classify(0), RiskLevel::Allow);
        assert_eq!(engine.classify(29), RiskLevel::Allow);
        assert_eq!(engine.classify(30), RiskLevel::Challenge);
        assert_eq!(engine.classify(50), RiskLevel::Challenge);
        assert_eq!(engine.classify(70), RiskLevel::Challenge);
        assert_eq!(engine.classify(71), RiskLevel::Block);
        assert_eq!(engine.classify(100), RiskLevel::Block);
    }

    #[test]
    fn decay_factor_at_half_life_is_half() {
        let engine = RiskEngine::new(300.0, 100);
        let f = engine.decay_factor(300.0);
        assert!((f - 0.5).abs() < 0.001);
    }

    #[test]
    fn decay_factor_at_zero_is_one() {
        let engine = RiskEngine::new(300.0, 100);
        let f = engine.decay_factor(0.0);
        assert!((f - 1.0).abs() < 0.001);
    }

    #[test]
    fn decay_factor_at_double_half_life_is_quarter() {
        let engine = RiskEngine::new(300.0, 100);
        let f = engine.decay_factor(600.0);
        assert!((f - 0.25).abs() < 0.001);
    }
}
