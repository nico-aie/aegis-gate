use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::detectors::Signal;

/// Features tracked per risk key for behavioral analysis.
#[derive(Debug)]
struct Session {
    request_times: Vec<Instant>,
    paths: Vec<String>,
    error_count: u32,
    total_count: u32,
    has_cookie: bool,
}

impl Session {
    fn new() -> Self {
        Self {
            request_times: Vec::new(),
            paths: Vec::new(),
            error_count: 0,
            total_count: 0,
            has_cookie: false,
        }
    }
}

/// Behavioral analyzer — detects anomalies in request patterns.
pub struct BehavioralAnalyzer {
    /// Per-key sessions.
    sessions: Mutex<HashMap<String, Session>>,
    /// Max session entries.
    max_sessions: usize,
    /// Analysis window in seconds.
    window_s: u64,
}

impl BehavioralAnalyzer {
    pub fn new(max_sessions: usize, window_s: u64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions,
            window_s,
        }
    }

    /// Record a request and return any behavioral signals.
    pub fn observe(
        &self,
        key: &str,
        path: &str,
        is_error: bool,
        has_cookie: bool,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();
        let mut map = self.sessions.lock().unwrap();

        // Evict if at capacity.
        if map.len() >= self.max_sessions && !map.contains_key(key) {
            // Simple eviction: remove the oldest entry.
            if let Some(oldest_key) = map.keys().next().cloned() {
                map.remove(&oldest_key);
            }
        }

        let session = map.entry(key.to_string()).or_insert_with(Session::new);
        let now = Instant::now();

        // Prune old entries.
        let cutoff = now - std::time::Duration::from_secs(self.window_s);
        session.request_times.retain(|t| *t > cutoff);

        session.request_times.push(now);
        session.total_count += 1;
        session.has_cookie = has_cookie;

        if !session.paths.contains(&path.to_string()) {
            session.paths.push(path.to_string());
        }

        if is_error {
            session.error_count += 1;
        }

        let request_count = session.request_times.len();

        // 1. High request rate.
        if request_count > 50 {
            signals.push(Signal {
                score: 20,
                tag: "behavior_high_rate".into(),
                field: "rate".into(),
            });
        }

        // 2. High path diversity (directory scanning).
        let path_count = session.paths.len();
        if path_count > 30 && request_count > 20 {
            let diversity = path_count as f64 / request_count as f64;
            if diversity > 0.8 {
                signals.push(Signal {
                    score: 25,
                    tag: "behavior_high_diversity".into(),
                    field: "paths".into(),
                });
            }
        }

        // 3. High error ratio.
        if session.total_count > 10 {
            let error_ratio = session.error_count as f64 / session.total_count as f64;
            if error_ratio > 0.5 {
                signals.push(Signal {
                    score: 20,
                    tag: "behavior_high_errors".into(),
                    field: "errors".into(),
                });
            }
        }

        // 4. Low inter-arrival jitter (very regular requests = automated).
        if request_count > 10 {
            let jitter = compute_jitter(&session.request_times);
            if jitter < 0.05 {
                signals.push(Signal {
                    score: 15,
                    tag: "behavior_low_jitter".into(),
                    field: "timing".into(),
                });
            }
        }

        // 5. No cookies (stateless bot pattern).
        if !has_cookie && session.total_count > 5 {
            signals.push(Signal {
                score: 10,
                tag: "behavior_no_cookie".into(),
                field: "cookie".into(),
            });
        }

        signals
    }

    /// Clear all sessions.
    pub fn clear(&self) {
        self.sessions.lock().unwrap().clear();
    }

    /// Number of tracked sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new(100_000, 60)
    }
}

/// Compute coefficient of variation of inter-arrival times.
fn compute_jitter(times: &[Instant]) -> f64 {
    if times.len() < 3 {
        return 1.0; // Not enough data.
    }

    let mut intervals: Vec<f64> = Vec::new();
    for w in times.windows(2) {
        intervals.push(w[1].duration_since(w[0]).as_secs_f64());
    }

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < 1e-9 {
        return 0.0; // All at once.
    }

    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let std_dev = variance.sqrt();
    std_dev / mean // Coefficient of variation.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_browsing_no_signals() {
        let analyzer = BehavioralAnalyzer::new(1000, 60);
        // Simulate 5 requests with cookies, different paths, no errors.
        for i in 0..5 {
            let s = analyzer.observe("user1", &format!("/page/{i}"), false, true);
            assert!(s.is_empty(), "unexpected signal on request {i}: {s:?}");
        }
    }

    #[test]
    fn high_rate_detected() {
        let analyzer = BehavioralAnalyzer::new(1000, 60);
        for i in 0..55 {
            let _ = analyzer.observe("flood", &format!("/p/{}", i % 5), false, true);
        }
        // The 55th request should trigger high_rate.
        let s = analyzer.observe("flood", "/p/0", false, true);
        assert!(s.iter().any(|s| s.tag == "behavior_high_rate"), "expected high_rate: {s:?}");
    }

    #[test]
    fn high_path_diversity_detected() {
        let analyzer = BehavioralAnalyzer::new(1000, 60);
        // 35 unique paths out of 35 requests = diversity 1.0.
        for i in 0..35 {
            let _ = analyzer.observe("scanner", &format!("/unique-path-{i}"), false, true);
        }
        let s = analyzer.observe("scanner", "/unique-path-99", false, true);
        assert!(s.iter().any(|s| s.tag == "behavior_high_diversity"), "expected diversity: {s:?}");
    }

    #[test]
    fn high_error_ratio_detected() {
        let analyzer = BehavioralAnalyzer::new(1000, 60);
        // 15 requests, 10 errors.
        for i in 0..15 {
            let _ = analyzer.observe("bruteforce", "/login", i < 10, true);
        }
        let s = analyzer.observe("bruteforce", "/login", true, true);
        assert!(s.iter().any(|s| s.tag == "behavior_high_errors"), "expected errors: {s:?}");
    }

    #[test]
    fn no_cookie_detected() {
        let analyzer = BehavioralAnalyzer::new(1000, 60);
        for _ in 0..8 {
            let _ = analyzer.observe("bot", "/api/data", false, false);
        }
        let s = analyzer.observe("bot", "/api/data", false, false);
        assert!(s.iter().any(|s| s.tag == "behavior_no_cookie"), "expected no_cookie: {s:?}");
    }

    #[test]
    fn session_eviction() {
        let analyzer = BehavioralAnalyzer::new(3, 60);
        for i in 0..5 {
            analyzer.observe(&format!("key-{i}"), "/path", false, true);
        }
        assert!(analyzer.session_count() <= 3);
    }

    #[test]
    fn clear_works() {
        let analyzer = BehavioralAnalyzer::new(1000, 60);
        analyzer.observe("k1", "/a", false, true);
        analyzer.observe("k2", "/b", false, true);
        assert_eq!(analyzer.session_count(), 2);
        analyzer.clear();
        assert_eq!(analyzer.session_count(), 0);
    }

    #[test]
    fn jitter_computation() {
        let now = Instant::now();
        // Perfectly regular intervals → low jitter.
        let regular: Vec<Instant> = (0..10)
            .map(|i| now + std::time::Duration::from_millis(i * 100))
            .collect();
        let j = compute_jitter(&regular);
        assert!(j < 0.1, "expected low jitter: {j}");
    }

    #[test]
    fn jitter_high_for_irregular() {
        let now = Instant::now();
        // Very irregular intervals.
        let irregular = vec![
            now,
            now + std::time::Duration::from_millis(10),
            now + std::time::Duration::from_millis(500),
            now + std::time::Duration::from_millis(510),
            now + std::time::Duration::from_millis(2000),
        ];
        let j = compute_jitter(&irregular);
        assert!(j > 0.5, "expected high jitter: {j}");
    }
}
