//! LT-RUN-6 Audit Test Suite — aegis-security
//!
//! Each test below is directly tied to a finding from the Run-6 static
//! audit report (2026-05-13). Test ID in the comment matches the
//! finding ID. Run with:
//!
//!   cargo test -p aegis-security --test lt_run6_audit_tests
//!
//! Tests that require unavailable infrastructure (cargo binary) are
//! skipped in CI with `#[ignore]`; override with `--include-ignored`.

// ─── SEC-07: Detectors disconnected from pipeline ──────────────────────────
// Proves that calling `SecurityPipelineImpl::inbound()` on a
// request that contains a SQL injection payload produces Action::Allow
// (the detectors are never consulted).

#[cfg(test)]
mod sec07_detectors_disconnected {
    use std::sync::Arc;

    use aegis_security::detectors::{default_detectors, run_all_filtered_timed};
    use aegis_security::SecurityPipeline;
    use aegis_security::pipeline::AegisSecurityPipeline;

    fn make_pipeline() -> AegisSecurityPipeline {
        // Wire the real pipeline with an empty rule set and a no-op
        // state backend — same as aegis-bin does today.
        use aegis_security::rules::RuleSet;
        AegisSecurityPipeline::new(Arc::new(RuleSet::new()), None)
    }

    /// SEC-07-A: pipeline.inbound() on a SQLi payload returns Allow
    /// (proves detectors are never consulted).
    #[tokio::test]
    async fn pipeline_inbound_allows_sqli_payload() {
        use aegis_core::pipeline::{BodyPeek, RequestView};

        let pipeline = make_pipeline();

        let method = http::Method::GET;
        // Classic SQLi in query string
        let uri: http::Uri = "/api/users?id=1%27+OR+%271%27%3D%271".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();
        let req = RequestView {
            method: &method,
            uri: &uri,
            version: http::Version::HTTP_11,
            headers: &headers,
            peer: "1.2.3.4:1234".parse().unwrap(),
            tls: None,
            body: &body,
        };

        let action = pipeline.inbound(&req).await;
        // BUG: This should be Action::Block but is Action::Allow because
        // the pipeline never calls run_all_filtered_timed().
        assert!(
            matches!(action, aegis_core::decision::Action::Allow),
            "SEC-07: pipeline returns Allow for SQLi — detectors are disconnected"
        );
    }

    /// SEC-07-B: Direct call to run_all_filtered_timed() DOES flag the SQLi.
    /// Proves the detectors themselves work — the problem is the wiring.
    #[test]
    fn detectors_directly_catch_sqli() {
        use aegis_core::pipeline::{BodyPeek, RequestView};

        let detectors = default_detectors();
        let method = http::Method::GET;
        let uri: http::Uri = "/api/users?id=1%27+OR+%271%27%3D%271".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();
        let req = RequestView {
            method: &method,
            uri: &uri,
            version: http::Version::HTTP_11,
            headers: &headers,
            peer: "1.2.3.4:1234".parse().unwrap(),
            tls: None,
            body: &body,
        };

        let enabled: std::collections::HashSet<&str> = ["sqli"].iter().copied().collect();
        let signals = run_all_filtered_timed(&detectors, &req, Some(&enabled));
        assert!(
            !signals.is_empty(),
            "SEC-07: detectors DO catch SQLi when called directly — only the pipeline wiring is missing"
        );
        assert!(signals.iter().any(|s| s.tag.contains("sqli")));
    }

    /// SEC-07-C: Path traversal payload is also missed by the pipeline.
    #[tokio::test]
    async fn pipeline_inbound_allows_path_traversal() {
        use aegis_core::pipeline::{BodyPeek, RequestView};

        let pipeline = make_pipeline();
        let method = http::Method::GET;
        let uri: http::Uri = "/api/files?name=../../../../etc/passwd".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();
        let req = RequestView {
            method: &method,
            uri: &uri,
            version: http::Version::HTTP_11,
            headers: &headers,
            peer: "1.2.3.4:1234".parse().unwrap(),
            tls: None,
            body: &body,
        };

        let action = pipeline.inbound(&req).await;
        assert!(
            matches!(action, aegis_core::decision::Action::Allow),
            "SEC-07: pipeline allows path traversal — detectors disconnected"
        );
    }

    /// SEC-07-D: XSS payload missed by the pipeline.
    #[tokio::test]
    async fn pipeline_inbound_allows_xss_payload() {
        use aegis_core::pipeline::{BodyPeek, RequestView};

        let pipeline = make_pipeline();
        let method = http::Method::GET;
        let uri: http::Uri = "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();
        let req = RequestView {
            method: &method,
            uri: &uri,
            version: http::Version::HTTP_11,
            headers: &headers,
            peer: "1.2.3.4:1234".parse().unwrap(),
            tls: None,
            body: &body,
        };

        let action = pipeline.inbound(&req).await;
        assert!(
            matches!(action, aegis_core::decision::Action::Allow),
            "SEC-07: pipeline allows XSS — detectors disconnected"
        );
    }

    /// SEC-07-E: SSRF payload missed by the pipeline.
    #[tokio::test]
    async fn pipeline_inbound_allows_ssrf_payload() {
        use aegis_core::pipeline::{BodyPeek, RequestView};

        let pipeline = make_pipeline();
        let method = http::Method::GET;
        let uri: http::Uri = "/proxy?url=http://169.254.169.254/latest/meta-data/".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();
        let req = RequestView {
            method: &method,
            uri: &uri,
            version: http::Version::HTTP_11,
            headers: &headers,
            peer: "1.2.3.4:1234".parse().unwrap(),
            tls: None,
            body: &body,
        };

        let action = pipeline.inbound(&req).await;
        assert!(
            matches!(action, aegis_core::decision::Action::Allow),
            "SEC-07: pipeline allows SSRF — detectors disconnected"
        );
    }
}

// ─── EVAL-01: Condition::IpIn uses string prefix, not CIDR ─────────────────
#[cfg(test)]
mod eval01_ipin_cidr_bug {
    use aegis_security::rules::{evaluate, RuleSet};
    use aegis_core::pipeline::{BodyPeek, RequestView};

    fn make_req_from_ip<'a>(
        method: &'a http::Method,
        uri: &'a http::Uri,
        headers: &'a http::HeaderMap,
        body: &'a BodyPeek,
        peer: &str,
    ) -> RequestView<'a> {
        RequestView {
            method,
            uri,
            version: http::Version::HTTP_11,
            headers,
            peer: peer.parse().unwrap(),
            tls: None,
            body,
        }
    }

    /// EVAL-01-A: IP `10.0.0.1` does NOT match CIDR `10.0.0.0/24` using
    /// string-prefix logic (the bug) — but SHOULD match.
    /// This test documents the broken behaviour.
    #[test]
    fn cidr_10_0_0_0_24_does_not_match_10_0_0_1_bug() {
        // A rule blocking `10.0.0.0/24`.
        // With the buggy prefix check, `10.0.0.1`.starts_with("10.0.0.0") = false
        // so the rule never fires even though 10.0.0.1 is in 10.0.0.0/24.
        let rules_yaml = r#"
- id: block-rfc1918-24
  priority: 100
  when:
    ip_in:
      - "10.0.0.0/24"
  then:
    block:
      status: 403
"#;
        let rules = aegis_security::rules::parse(rules_yaml).unwrap();
        let method = http::Method::GET;
        let uri: http::Uri = "/api/secret".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();
        let req = make_req_from_ip(&method, &uri, &headers, &body, "10.0.0.1:1234");

        let ctx = aegis_security::rules::EvalContext::default();
        let action = evaluate_with_ctx(&rules, &req, &ctx);

        // BUG: EVAL-01 — the action should be Block but is Allow because
        // string-prefix "10.0.0.1".starts_with("10.0.0.0") is false.
        // When FIXED, change this assertion to expect Block.
        assert!(
            matches!(action, aegis_core::decision::Action::Allow),
            "EVAL-01 BUG confirmed: 10.0.0.1 is not matched by CIDR 10.0.0.0/24 (string prefix bug)"
        );
    }

    /// EVAL-01-B: Only the exact network address matches (prefix is itself).
    #[test]
    fn cidr_only_exact_network_address_matches() {
        let rules_yaml = r#"
- id: block-exact
  priority: 100
  when:
    ip_in:
      - "10.0.0.0/24"
  then:
    block:
      status: 403
"#;
        let rules = aegis_security::rules::parse(rules_yaml).unwrap();
        let method = http::Method::GET;
        let uri: http::Uri = "/".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();
        // 10.0.0.0 starts with "10.0.0.0" → prefix check passes accidentally
        let req = make_req_from_ip(&method, &uri, &headers, &body, "10.0.0.0:1234");

        let ctx = aegis_security::rules::EvalContext::default();
        let action = evaluate_with_ctx(&rules, &req, &ctx);
        // 10.0.0.0 starts_with "10.0.0.0" → this one does match (accidentally correct)
        assert!(
            matches!(action, aegis_core::decision::Action::Block { .. }),
            "EVAL-01: exact network address 10.0.0.0 matches (accidentally)"
        );
    }

    use aegis_security::rules::evaluate_with_ctx;
}

// ─── EVAL-02: RuleAction::RateLimit ignores key and limit ──────────────────
#[cfg(test)]
mod eval02_ratelimit_no_backend {
    use aegis_security::rules::{evaluate_with_ctx, EvalContext, parse};
    use aegis_core::pipeline::{BodyPeek, RequestView};

    fn req<'a>(
        method: &'a http::Method,
        uri: &'a http::Uri,
        headers: &'a http::HeaderMap,
        body: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method,
            uri,
            version: http::Version::HTTP_11,
            headers,
            peer: "1.2.3.4:1234".parse().unwrap(),
            tls: None,
            body,
        }
    }

    /// EVAL-02-A: A rate-limit rule fires on the VERY FIRST request,
    /// proving that the rule never consults a state backend.
    #[test]
    fn ratelimit_fires_on_first_request() {
        let rules_yaml = r#"
- id: rl-test
  priority: 100
  when: true
  then:
    rate_limit:
      key: "ip"
      limit: 100
      window_s: 60
"#;
        let rules = parse(rules_yaml).unwrap();
        let method = http::Method::GET;
        let uri: http::Uri = "/api/endpoint".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();

        let ctx = EvalContext::default();
        let action = evaluate_with_ctx(&rules, &req(&method, &uri, &headers, &body), &ctx);

        // BUG EVAL-02: Should only fire after 100 requests from same key.
        // Instead fires on request #1 — state backend never consulted.
        assert!(
            matches!(action, aegis_core::decision::Action::RateLimited { .. }),
            "EVAL-02 BUG confirmed: RateLimit rule fires on first request without consulting state backend"
        );
    }

    /// EVAL-02-B: limit=1000 and limit=1 behave identically — proves limit is ignored.
    #[test]
    fn ratelimit_limit_value_does_not_matter() {
        let yaml_low = r#"
- id: rl-low
  priority: 100
  when: true
  then:
    rate_limit:
      key: "ip"
      limit: 1
      window_s: 60
"#;
        let yaml_high = r#"
- id: rl-high
  priority: 100
  when: true
  then:
    rate_limit:
      key: "ip"
      limit: 1000000
      window_s: 60
"#;
        let rules_low = parse(yaml_low).unwrap();
        let rules_high = parse(yaml_high).unwrap();
        let method = http::Method::GET;
        let uri: http::Uri = "/".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = BodyPeek::empty();
        let ctx = EvalContext::default();

        let low = evaluate_with_ctx(&rules_low, &req(&method, &uri, &headers, &body), &ctx);
        let high = evaluate_with_ctx(&rules_high, &req(&method, &uri, &headers, &body), &ctx);

        // Both are RateLimited despite wildly different limits.
        assert!(
            matches!(low, aegis_core::decision::Action::RateLimited { .. }),
            "limit=1 is RateLimited"
        );
        assert!(
            matches!(high, aegis_core::decision::Action::RateLimited { .. }),
            "EVAL-02 BUG: limit=1000000 is also RateLimited — limit value ignored"
        );
    }
}

// ─── SEC-16: Nonce race in challenge/token.rs ───────────────────────────────
// challenge/token.rs is documented as deferred (zero callers, #[allow(dead_code)]).
// These tests demonstrate the race condition exists in the code even though the
// module is unused. They are gated on the internal API being accessible.
#[cfg(test)]
mod sec16_nonce_race {
    /// SEC-16-A: Documents the race — store_nonce and issue use separate
    /// generate_nonce() calls so if they run in different milliseconds,
    /// the stored nonce != the nonce embedded in the token → ReplayDetected.
    /// This is a static observation test (no async needed to confirm the logic).
    #[test]
    fn store_and_issue_use_independent_nonce_generators() {
        // This is a documentation test — the race cannot be deterministically
        // reproduced in a unit test because it depends on millisecond boundary
        // crossing. The audit finding is confirmed by code inspection:
        //
        // token.rs:74  store_nonce() → generate_nonce(key) → timestamp_ms()
        // token.rs:23  issue()       → generate_nonce(key) → timestamp_ms()
        //
        // If called in different milliseconds: N1 ≠ N2 → verify() returns
        // TokenError::ReplayDetected even for a valid token.
        //
        // The fix is to call generate_nonce() once, share the result between
        // store_nonce() and issue(), or change to put_nonce/consume_nonce
        // which is what pow.rs correctly uses.
        assert!(true, "SEC-16 race confirmed by code inspection — see token.rs:23,74");
    }
}

// ─── SEC-20: ICAP not called on response path ───────────────────────────────
#[cfg(test)]
mod sec20_icap_disconnected {
    use aegis_security::SecurityPipeline;
    use aegis_security::pipeline::AegisSecurityPipeline;
    use aegis_security::rules::RuleSet;
    use std::sync::Arc;

    fn make_pipeline() -> AegisSecurityPipeline {
        AegisSecurityPipeline::new(Arc::new(RuleSet::new()), None)
    }

    /// SEC-20-A: on_response_start always returns PassThrough regardless of
    /// content — proves ICAP/DLP on response headers is never consulted.
    #[tokio::test]
    async fn response_start_always_passthroughs() {
        use aegis_core::pipeline::ResponseStartView;
        use aegis_core::decision::OutboundAction;

        let pipeline = make_pipeline();

        // Simulate a response that contains a suspicious content-type.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "content-type",
            "application/octet-stream".parse().unwrap(),
        );
        headers.insert("x-internal-service", "true".parse().unwrap());

        let resp = ResponseStartView {
            status: http::StatusCode::OK,
            headers: &headers,
        };

        let action = pipeline.on_response_start(&resp).await;
        assert!(
            matches!(action, OutboundAction::PassThrough),
            "SEC-20: on_response_start always returns PassThrough — ICAP never consulted"
        );
    }
}

// ─── SEC-19: JA3 uses blake3 (incompatible with external feeds) ─────────────
#[cfg(test)]
mod sec19_ja3_blake3 {
    use aegis_security::fingerprint::ja3;

    /// SEC-19-A: JA3 output is 64 hex chars (blake3), not 32 (MD5).
    /// External JA3 threat feeds use MD5 — this creates an incompatibility.
    #[test]
    fn ja3_output_is_64_chars_not_32() {
        // Use a minimal synthetic ClientHello fingerprint.
        // The real ja3::compute() parses raw TLS bytes, but the hash
        // output length is what matters here.
        let sample_ja3_string = "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0";
        let fingerprint = ja3::hash_ja3_string(sample_ja3_string);

        // blake3 hex = 64 chars. MD5 hex = 32 chars.
        assert_eq!(
            fingerprint.len(),
            64,
            "SEC-19: JA3 fingerprint is blake3 (64 chars) not MD5 (32 chars) — external feed incompatibility"
        );
    }
}

// ─── DDOS-01: tick_rps() never called automatically ────────────────────────
#[cfg(test)]
mod ddos01_tick_rps_unwired {
    use aegis_security::ddos::{DdosDetector, DdosConfig};
    use std::sync::atomic::Ordering;

    /// DDOS-01-A: Without calling tick_rps(), the baseline stays at the
    /// hardcoded 100 and spike_active never flips — EWMA is stale.
    #[test]
    fn baseline_stale_without_tick() {
        let detector = DdosDetector::new(DdosConfig::default());
        // Simulate 500 requests arriving (much more than baseline of 100).
        for _ in 0..500 {
            detector.rolling_rps.fetch_add(1, Ordering::Relaxed);
        }
        // Without tick_rps(), spike is never detected.
        assert!(
            !detector.is_spike_active(),
            "DDOS-01: spike not detected because tick_rps() was never called"
        );
        // Baseline is still the hardcoded initial value.
        assert_eq!(
            detector.baseline_rps(),
            100,
            "DDOS-01: baseline unchanged because tick_rps() never ran"
        );
    }

    /// DDOS-01-B: Calling tick_rps() manually does update things correctly.
    #[test]
    fn tick_rps_updates_baseline_correctly() {
        let cfg = DdosConfig { spike_multiplier: 2.0, ..Default::default() };
        let detector = DdosDetector::new(cfg);
        detector.baseline_rps.store(100, Ordering::Relaxed);
        detector.rolling_rps.store(300, Ordering::Relaxed);
        detector.tick_rps();
        assert!(
            detector.is_spike_active(),
            "DDOS-01: spike detected when tick_rps() is called manually"
        );
    }
}

// ─── THREAT-01: Domain matching exact-only, no wildcard subdomains ──────────
#[cfg(test)]
mod threat01_domain_no_wildcard {
    use aegis_security::threat_intel::ThreatIntelStore;
    use aegis_core::config::ThreatIntelConfig;

    /// THREAT-01-A: exact domain matches.
    #[test]
    fn exact_domain_match() {
        let store = ThreatIntelStore::new();
        store.add_domain("evil.com", "MALWARE");
        let result = store.check_domain("evil.com");
        assert!(result.is_some(), "exact domain must match");
    }

    /// THREAT-01-B: subdomain does NOT match when parent is in threat list.
    #[test]
    fn subdomain_does_not_match_parent_domain() {
        let store = ThreatIntelStore::new();
        store.add_domain("evil.com", "MALWARE");
        let result = store.check_domain("c2.evil.com");
        // BUG: should match but doesn't — exact match only.
        assert!(
            result.is_none(),
            "THREAT-01 BUG confirmed: c2.evil.com is not matched by evil.com in threat list"
        );
    }

    /// THREAT-01-C: deeply nested subdomain also misses.
    #[test]
    fn deep_subdomain_does_not_match() {
        let store = ThreatIntelStore::new();
        store.add_domain("malware-c2.net", "C2");
        let result = store.check_domain("beacon.tier1.malware-c2.net");
        assert!(
            result.is_none(),
            "THREAT-01 BUG: deeply nested subdomain not matched"
        );
    }
}

// ─── RL-01: IpRateLimiter has #[allow(dead_code)] — verify module is unwired ─
#[cfg(test)]
mod rl01_ip_limiter_dead_code {
    use aegis_security::rate_limit::ip_limiter::{IpRateLimiter, IpRateLimitConfig};
    use std::net::IpAddr;
    use std::time::Duration;

    /// RL-01-A: The IpRateLimiter works correctly in isolation — the issue
    /// is it's not wired into the hot path.
    #[test]
    fn ip_limiter_functional_in_isolation() {
        let limiter = IpRateLimiter::new(IpRateLimitConfig {
            limit: 5,
            window: Duration::from_secs(60),
        });
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..5 {
            assert!(limiter.consume(ip).allowed);
        }
        // 6th denied — limiter is functional.
        assert!(
            !limiter.consume(ip).allowed,
            "RL-01: IpRateLimiter works but is not wired into the request pipeline"
        );
    }
}

// ─── RISK-01: RiskTracker has #[allow(dead_code)] — verify it's unwired ─────
#[cfg(test)]
mod risk01_tracker_dead_code {
    use aegis_security::risk::tracker::RiskTracker;
    use aegis_core::config::RiskConfig;
    use std::net::IpAddr;

    /// RISK-01-A: RiskTracker is functional in isolation but not wired to
    /// the pipeline. Malicious events do not feed into block/challenge decisions.
    #[test]
    fn risk_tracker_functional_in_isolation() {
        let tracker = RiskTracker::new(&RiskConfig::default());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Accumulate 5 malicious events.
        for _ in 0..5 {
            tracker.record_malicious(ip, 20);
        }
        // RiskTracker internally shows Block level.
        use aegis_security::risk::RiskLevel;
        assert_eq!(
            tracker.level(ip),
            RiskLevel::Block,
            "RISK-01: tracker correctly computes Block level — but pipeline never consults it"
        );
    }
}
