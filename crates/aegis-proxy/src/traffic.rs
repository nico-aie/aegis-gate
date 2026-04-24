use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// ──────────────────────── Canary Split ─────────────────────────

/// One arm of a traffic split.
#[derive(Debug, Clone)]
pub struct SplitEntry {
    pub pool: String,
    pub weight: u32,
}

/// Weighted random pick across split entries.  Thread-safe via atomic counter
/// for deterministic round-robin-style distribution (weighted).
pub struct CanarySplitter {
    entries: Vec<SplitEntry>,
    total_weight: u32,
    counter: AtomicU64,
}

impl CanarySplitter {
    pub fn new(entries: Vec<SplitEntry>) -> Self {
        let total_weight: u32 = entries.iter().map(|e| e.weight).sum();
        Self {
            entries,
            total_weight,
            counter: AtomicU64::new(0),
        }
    }

    /// Pick a pool based on weighted round-robin.
    /// Optionally override via header or cookie steering.
    pub fn pick(
        &self,
        steer_header: Option<&str>,
        steer_cookie: Option<&str>,
    ) -> &str {
        // Header steering short-circuits.
        if let Some(pool) = steer_header {
            if let Some(e) = self.entries.iter().find(|e| e.pool == pool) {
                return &e.pool;
            }
        }
        // Cookie steering short-circuits.
        if let Some(pool) = steer_cookie {
            if let Some(e) = self.entries.iter().find(|e| e.pool == pool) {
                return &e.pool;
            }
        }

        if self.entries.len() == 1 {
            return &self.entries[0].pool;
        }

        let idx = self.counter.fetch_add(1, Ordering::Relaxed);
        let slot = (idx % self.total_weight as u64) as u32;
        let mut acc = 0u32;
        for entry in &self.entries {
            acc += entry.weight;
            if slot < acc {
                return &entry.pool;
            }
        }
        &self.entries.last().unwrap().pool
    }
}

// ──────────────────────── Retries ──────────────────────────────

/// Per-pool retry configuration.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub per_try_timeout: Duration,
    pub retry_on: Vec<u16>, // status codes to retry on
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            per_try_timeout: Duration::from_secs(5),
            retry_on: vec![502, 503, 504],
        }
    }
}

/// Cluster-level retry budget — limits total retries as a ratio.
pub struct RetryBudget {
    total_requests: AtomicU64,
    total_retries: AtomicU64,
    max_ratio: f64,
}

impl RetryBudget {
    pub fn new(max_ratio: f64) -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            total_retries: AtomicU64::new(0),
            max_ratio,
        }
    }

    /// Record a primary request.
    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Check if a retry is allowed, and if so record it.
    pub fn try_retry(&self) -> bool {
        let reqs = self.total_requests.load(Ordering::Relaxed);
        let retries = self.total_retries.load(Ordering::Relaxed);

        if reqs == 0 {
            return true;
        }

        let ratio = retries as f64 / reqs as f64;
        if ratio >= self.max_ratio {
            return false;
        }

        self.total_retries.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Whether a status code is retryable according to config.
    pub fn is_retryable(status: u16, cfg: &RetryConfig) -> bool {
        cfg.retry_on.contains(&status)
    }

    pub fn retry_ratio(&self) -> f64 {
        let reqs = self.total_requests.load(Ordering::Relaxed);
        let retries = self.total_retries.load(Ordering::Relaxed);
        if reqs == 0 {
            0.0
        } else {
            retries as f64 / reqs as f64
        }
    }
}

// ──────────────────────── Shadow Mirror ────────────────────────

/// Shadow mirroring config — fire-and-forget clone to a second pool.
#[derive(Debug, Clone)]
pub struct ShadowConfig {
    /// The pool to mirror to.
    pub mirror_pool: String,
    /// Optional sampling percentage (0.0–1.0). Default 1.0 = mirror all.
    pub sample_rate: f64,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        Self {
            mirror_pool: String::new(),
            sample_rate: 1.0,
        }
    }
}

/// Decides whether a given request should be shadowed based on sample_rate.
pub fn should_mirror(cfg: &ShadowConfig, counter: u64) -> bool {
    if cfg.sample_rate >= 1.0 {
        return true;
    }
    if cfg.sample_rate <= 0.0 {
        return false;
    }
    // Deterministic sampling via modulo.
    let threshold = (cfg.sample_rate * 100.0) as u64;
    (counter % 100) < threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Canary Split tests ───

    #[test]
    fn single_pool_always_picked() {
        let splitter = CanarySplitter::new(vec![SplitEntry {
            pool: "v1".into(),
            weight: 100,
        }]);
        for _ in 0..100 {
            assert_eq!(splitter.pick(None, None), "v1");
        }
    }

    #[test]
    fn weighted_split_distribution() {
        let splitter = CanarySplitter::new(vec![
            SplitEntry { pool: "v1".into(), weight: 95 },
            SplitEntry { pool: "v2".into(), weight: 5 },
        ]);

        let mut v1_count = 0u64;
        let mut v2_count = 0u64;
        let total = 10_000u64;

        for _ in 0..total {
            match splitter.pick(None, None) {
                "v1" => v1_count += 1,
                "v2" => v2_count += 1,
                _ => panic!("unexpected pool"),
            }
        }

        // Within 1% tolerance.
        let v1_pct = v1_count as f64 / total as f64;
        assert!(
            (v1_pct - 0.95).abs() < 0.01,
            "v1 percentage {v1_pct} not within 1% of 0.95"
        );
    }

    #[test]
    fn header_steering_overrides() {
        let splitter = CanarySplitter::new(vec![
            SplitEntry { pool: "v1".into(), weight: 95 },
            SplitEntry { pool: "v2".into(), weight: 5 },
        ]);
        assert_eq!(splitter.pick(Some("v2"), None), "v2");
    }

    #[test]
    fn cookie_steering_overrides() {
        let splitter = CanarySplitter::new(vec![
            SplitEntry { pool: "v1".into(), weight: 95 },
            SplitEntry { pool: "v2".into(), weight: 5 },
        ]);
        assert_eq!(splitter.pick(None, Some("v2")), "v2");
    }

    #[test]
    fn invalid_steering_falls_back() {
        let splitter = CanarySplitter::new(vec![
            SplitEntry { pool: "v1".into(), weight: 95 },
            SplitEntry { pool: "v2".into(), weight: 5 },
        ]);
        // "v3" doesn't exist, falls back to weighted pick.
        let pool = splitter.pick(Some("v3"), None);
        assert!(pool == "v1" || pool == "v2");
    }

    // ─── Retry tests ───

    #[test]
    fn retry_budget_allows_within_ratio() {
        let budget = RetryBudget::new(0.2);
        for _ in 0..100 {
            budget.record_request();
        }
        // 20% of 100 = 20 retries allowed.
        for _ in 0..20 {
            assert!(budget.try_retry());
        }
        // 21st should be denied.
        assert!(!budget.try_retry());
    }

    #[test]
    fn retry_budget_empty_allows() {
        let budget = RetryBudget::new(0.1);
        assert!(budget.try_retry());
    }

    #[test]
    fn is_retryable_checks_config() {
        let cfg = RetryConfig::default();
        assert!(RetryBudget::is_retryable(502, &cfg));
        assert!(RetryBudget::is_retryable(503, &cfg));
        assert!(!RetryBudget::is_retryable(200, &cfg));
        assert!(!RetryBudget::is_retryable(404, &cfg));
    }

    #[test]
    fn retry_ratio_calculation() {
        let budget = RetryBudget::new(0.5);
        for _ in 0..10 {
            budget.record_request();
        }
        for _ in 0..3 {
            budget.try_retry();
        }
        let ratio = budget.retry_ratio();
        assert!((ratio - 0.3).abs() < 0.01);
    }

    // ─── Shadow Mirror tests ───

    #[test]
    fn full_sample_always_mirrors() {
        let cfg = ShadowConfig {
            mirror_pool: "shadow".into(),
            sample_rate: 1.0,
        };
        for i in 0..100 {
            assert!(should_mirror(&cfg, i));
        }
    }

    #[test]
    fn zero_sample_never_mirrors() {
        let cfg = ShadowConfig {
            mirror_pool: "shadow".into(),
            sample_rate: 0.0,
        };
        for i in 0..100 {
            assert!(!should_mirror(&cfg, i));
        }
    }

    #[test]
    fn partial_sample_rate() {
        let cfg = ShadowConfig {
            mirror_pool: "shadow".into(),
            sample_rate: 0.5,
        };
        let mirrored: u64 = (0..100).filter(|&i| should_mirror(&cfg, i)).count() as u64;
        assert_eq!(mirrored, 50);
    }
}
