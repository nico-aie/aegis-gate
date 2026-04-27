/// Definition of Done integration tests for aegis-control (M3).
///
/// Verifies:
/// 1. Full login flow (argon2id + session + CSRF + rate limit + TOTP + mTLS)
/// 2. Audit chain verify passes on clean chain, fails on tampered
/// 3. SIEM forwarder delivers to ≥3 sinks
/// 4. FIPS compliance profile rejects non-FIPS algo
/// 5. SLO fast-burn alert fires on regression, clears on recovery

// ===== 1. Full login flow =================================================

mod login_flow {
    use aegis_control::admin_auth::{
        csrf, mtls, password, rate_limit, session, totp,
    };

    #[test]
    fn full_flow_password_session_csrf_totp() {
        // Step 1: Hash and verify password (argon2id).
        let hash = password::hash_password("admin-secret").unwrap();
        assert!(password::verify_password(&hash, "admin-secret"));
        assert!(!password::verify_password(&hash, "wrong"));

        // Step 2: Create session.
        let key = [42u8; 32];
        let store = session::SessionStore::new(key);
        let (session_id, cookie) = store.create("10.0.0.1", "Mozilla/5.0");
        let record = store.validate(&cookie).unwrap();
        assert_eq!(record.ip, "10.0.0.1");
        assert!(!record.totp_verified);

        // Step 3: CSRF token.
        let csrf_token = csrf::generate_token();
        assert_eq!(
            csrf::validate(Some(&csrf_token), Some(&csrf_token)),
            csrf::CsrfResult::Valid
        );
        assert_eq!(
            csrf::validate(Some(&csrf_token), None),
            csrf::CsrfResult::MissingHeader
        );

        // Step 4: TOTP verification.
        let secret = b"12345678901234567890123456789012";
        let time = 1_700_000_000u64;
        let config = totp::TotpConfig::default();
        let code = totp::generate(secret, time, &config);
        assert!(totp::verify(secret, &code, time, &config));
        store.mark_totp_verified(&session_id);
        let record = store.validate(&cookie).unwrap();
        assert!(record.totp_verified);

        // Step 5: Session revocation.
        assert!(store.revoke(&session_id));
        assert!(store.validate(&cookie).is_none());
    }

    #[test]
    fn login_rate_limit_and_lockout() {
        let config = rate_limit::LoginRateLimitConfig {
            ip_max_attempts: 3,
            ip_window: std::time::Duration::from_secs(60),
            user_max_attempts: 5,
            user_window: std::time::Duration::from_secs(60),
            lockout_threshold: 5,
            lockout_duration: std::time::Duration::from_secs(10),
        };
        let limiter = rate_limit::LoginRateLimiter::new(config);

        // First 3 attempts OK.
        for _ in 0..3 {
            assert_eq!(
                limiter.check("1.2.3.4", "admin"),
                rate_limit::LoginOutcome::Allowed
            );
            limiter.record_failure("1.2.3.4", "admin");
        }

        // 4th from same IP: rate-limited.
        assert!(matches!(
            limiter.check("1.2.3.4", "admin"),
            rate_limit::LoginOutcome::RateLimited { .. }
        ));

        // Different IP, same user: still allowed (only 3 user attempts).
        assert_eq!(
            limiter.check("5.6.7.8", "admin"),
            rate_limit::LoginOutcome::Allowed
        );

        // Push to user lockout (5 total).
        limiter.record_failure("5.6.7.8", "admin");
        limiter.record_failure("9.9.9.9", "admin");

        // Now locked out for any IP.
        assert!(matches!(
            limiter.check("10.0.0.1", "admin"),
            rate_limit::LoginOutcome::LockedOut { .. }
        ));
    }

    #[test]
    fn mtls_auth_and_ip_allowlist() {
        let config = mtls::MtlsConfig {
            enabled: true,
            ca_ref: "test-ca".into(),
            allowed_sans: vec!["admin@aegis.local".into()],
        };

        // Valid SAN.
        assert!(matches!(
            mtls::verify_client_cert(&config, Some("admin@aegis.local")),
            mtls::MtlsResult::Authenticated { .. }
        ));

        // Wrong SAN.
        assert!(matches!(
            mtls::verify_client_cert(&config, Some("evil@attacker.com")),
            mtls::MtlsResult::RejectedSan { .. }
        ));

        // IP allowlist.
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(mtls::check_ip_allowlist("10.1.2.3", &nets));
        assert!(!mtls::check_ip_allowlist("192.168.1.1", &nets));
    }
}

// ===== 2. Audit chain verify ==============================================

mod audit_chain_verify {
    use aegis_control::audit::chain::ChainWriter;
    use aegis_control::audit::verify::{verify_entries, verify_ndjson, VerifyResult};
    use aegis_core::audit::{AuditClass, AuditEvent};

    fn test_event(id: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            request_id: id.into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn clean_chain_verifies() {
        let mut w = ChainWriter::new();
        for i in 0..10 {
            w.append(test_event(&format!("req-{i}")));
        }

        // Verify entries directly.
        assert_eq!(verify_entries(w.entries()), VerifyResult::Clean { entries: 10 });

        // Verify NDJSON serialized form.
        assert_eq!(verify_ndjson(&w.to_ndjson()), VerifyResult::Clean { entries: 10 });
    }

    #[test]
    fn tampered_chain_fails() {
        let mut w = ChainWriter::new();
        for i in 0..5 {
            w.append(test_event(&format!("req-{i}")));
        }

        // Tamper with the NDJSON.
        let ndjson = w.to_ndjson().replace("req-2", "req-TAMPERED");
        let result = verify_ndjson(&ndjson);
        assert!(matches!(result, VerifyResult::Broken { line: 3, .. }));
    }

    #[test]
    fn tampered_hash_detected() {
        let mut w = ChainWriter::new();
        for i in 0..3 {
            w.append(test_event(&format!("req-{i}")));
        }

        let mut entries = w.entries().to_vec();
        entries[1].hash = "0000000000000000000000000000000000000000000000000000000000000000".into();
        let result = verify_entries(&entries);
        assert!(matches!(result, VerifyResult::Broken { line: 2, .. }));
    }
}

// ===== 3. SIEM multi-sink delivery ========================================

mod siem_multi_sink {
    use aegis_control::audit::sinks::{AuditSink, jsonl, syslog, kafka, splunk_hec, ecs, cef, leef, ocsf};
    use aegis_core::audit::{AuditClass, AuditEvent};

    fn test_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-siem".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "sqli".into(),
            client_ip: "1.2.3.4".into(),
            route_id: Some("api".into()),
            rule_id: Some("sqli-1".into()),
            risk_score: Some(90),
            fields: serde_json::json!({"detector": "sqli"}),
        }
    }

    #[tokio::test]
    async fn delivers_to_3_plus_sinks() {
        let ev = test_event();

        // Sink 1: JSONL.
        let jsonl_sink = jsonl::JsonlSink::new(jsonl::JsonlConfig::default());
        jsonl_sink.write(&ev).await.unwrap();
        assert_eq!(jsonl_sink.lines().len(), 1);

        // Sink 2: Syslog.
        let syslog_sink = syslog::SyslogSink::new(syslog::SyslogConfig::default());
        syslog_sink.write(&ev).await.unwrap();
        assert_eq!(syslog_sink.messages().len(), 1);

        // Sink 3: Kafka.
        let kafka_sink = kafka::KafkaSink::new(kafka::KafkaConfig::default());
        kafka_sink.write(&ev).await.unwrap();
        assert_eq!(kafka_sink.messages().len(), 1);

        // Sink 4: Splunk HEC.
        let hec_sink = splunk_hec::HecSink::new(splunk_hec::HecConfig {
            url: "https://splunk:8088".into(),
            token: "test".into(),
            index: "waf".into(),
            source_type: "aegis:audit".into(),
        });
        hec_sink.write(&ev).await.unwrap();
        assert_eq!(hec_sink.payloads().len(), 1);

        // Verify formatters for remaining sinks produce valid output.
        let cef_line = cef::format_cef(&ev);
        assert!(cef_line.starts_with("CEF:0|"));
        assert!(cef_line.contains("sqli"));

        let leef_line = leef::format_leef(&ev);
        assert!(leef_line.starts_with("LEEF:2.0|"));

        let ocsf_json = ocsf::format_ocsf(&ev);
        let v: serde_json::Value = serde_json::from_str(&ocsf_json).unwrap();
        assert_eq!(v["class_uid"], 2001);

        let ecs_json = ecs::format_ecs(&ev);
        let v: serde_json::Value = serde_json::from_str(&ecs_json).unwrap();
        assert_eq!(v["observer"]["product"], "Aegis WAF");
    }

    #[tokio::test]
    async fn all_sinks_have_unique_ids() {
        let s1 = jsonl::JsonlSink::new(jsonl::JsonlConfig::default());
        let s2 = syslog::SyslogSink::new(syslog::SyslogConfig::default());
        let s3 = kafka::KafkaSink::new(kafka::KafkaConfig::default());
        let s4 = splunk_hec::HecSink::new(splunk_hec::HecConfig {
            url: "".into(), token: "".into(), index: "".into(), source_type: "".into(),
        });
        let ids: Vec<&str> = vec![s1.id(), s2.id(), s3.id(), s4.id()];
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len());
    }
}

// ===== 4. FIPS compliance =================================================

mod fips_compliance {
    use aegis_control::compliance;
    use aegis_core::config::{ComplianceMode, ComplianceProfile, WafConfig};

    fn minimal_cfg() -> WafConfig {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        aegis_core::config::load_config_str(yaml).unwrap()
    }

    #[test]
    fn fips_rejects_non_fips_algo_in_disallow_list() {
        let mut cfg = minimal_cfg();
        cfg.compliance = Some(ComplianceProfile {
            modes: vec![],
            min_tls_version: None,
            disallow_algorithms: vec!["AES-256-GCM".into()],
            pii_pseudonymize: false,
        });
        let err = compliance::apply(&[ComplianceMode::Fips], &mut cfg).unwrap_err();
        assert!(err.to_string().contains("FIPS"));
    }

    #[test]
    fn fips_sets_min_tls_12() {
        let mut cfg = minimal_cfg();
        compliance::apply(&[ComplianceMode::Fips], &mut cfg).unwrap();
        let profile = cfg.compliance.as_ref().unwrap();
        assert!(profile
            .min_tls_version
            .as_deref()
            .is_some_and(|v| compliance::version_at_least(v, "1.2")));
    }

    #[test]
    fn fips_disallows_legacy_ciphers() {
        let mut cfg = minimal_cfg();
        compliance::apply(&[ComplianceMode::Fips], &mut cfg).unwrap();
        let profile = cfg.compliance.as_ref().unwrap();
        for algo in compliance::FIPS_DISALLOWED {
            assert!(
                profile.disallow_algorithms.iter().any(|a| a == algo),
                "expected {algo} in disallow list"
            );
        }
    }

    #[test]
    fn fips_rejects_tls_below_12() {
        let mut cfg = minimal_cfg();
        cfg.compliance = Some(ComplianceProfile {
            modes: vec![],
            min_tls_version: Some("1.0".into()),
            disallow_algorithms: Vec::new(),
            pii_pseudonymize: false,
        });
        let err = compliance::apply(&[ComplianceMode::Fips], &mut cfg).unwrap_err();
        assert!(err.to_string().contains("min_tls_version"));
    }
}

// ===== 5. SLO fast-burn fires + clears ====================================

mod slo_alert_lifecycle {
    use aegis_control::slo::*;

    fn fast_burn_objective() -> Vec<SloObjective> {
        vec![SloObjective {
            sli: SliKind::DataPlaneAvailability,
            target: 0.999, // 0.1% error budget
            window_days: 30,
            burn_rates: vec![BurnRateWindow {
                window_hours: 1,
                budget_pct: 2.0,
                severity: AlertSeverity::Page,
            }],
        }]
    }

    #[test]
    fn fast_burn_fires_on_synthetic_regression() {
        let engine = SloEngine::new(fast_burn_objective());

        // Inject errors: 10% error rate (100x the 0.1% budget).
        for _ in 0..200 {
            engine.record(SliSample {
                kind: SliKind::DataPlaneAvailability,
                value: 0.9,
                ts: chrono::Utc::now(),
            });
        }

        let alerts = engine.evaluate();
        assert!(!alerts.is_empty(), "fast-burn alert should fire");
        assert_eq!(alerts[0].severity, AlertSeverity::Page);
        assert!(alerts[0].resolved_at.is_none());
        assert!(alerts[0].budget_consumed_pct > 2.0);
        assert!(alerts[0].runbook_url.contains("runbooks.aegis.local"));
    }

    #[test]
    fn fast_burn_clears_on_recovery() {
        let engine = SloEngine::new(fast_burn_objective());

        // Fire the alert.
        for _ in 0..200 {
            engine.record(SliSample {
                kind: SliKind::DataPlaneAvailability,
                value: 0.9,
                ts: chrono::Utc::now(),
            });
        }
        engine.evaluate();
        assert_eq!(engine.active_alerts().len(), 1);

        // Recover: flood with healthy samples to push out the bad ones.
        for _ in 0..10_000 {
            engine.record(SliSample {
                kind: SliKind::DataPlaneAvailability,
                value: 1.0,
                ts: chrono::Utc::now(),
            });
        }

        let alerts = engine.evaluate();
        assert!(!alerts.is_empty(), "should get resolve event");
        assert!(alerts[0].resolved_at.is_some(), "alert should be resolved");
        assert!(engine.active_alerts().is_empty(), "no active alerts after recovery");
    }

    #[test]
    fn multi_burn_rate_windows() {
        let engine = SloEngine::new(default_objectives());

        // Record healthy data.
        for _ in 0..100 {
            engine.record(SliSample {
                kind: SliKind::DataPlaneAvailability,
                value: 1.0,
                ts: chrono::Utc::now(),
            });
            engine.record(SliSample {
                kind: SliKind::AuditDeliveryRate,
                value: 1.0,
                ts: chrono::Utc::now(),
            });
        }

        let alerts = engine.evaluate();
        assert!(alerts.is_empty(), "no alerts when healthy");

        let status = engine.budget_status();
        assert_eq!(status.len(), 2);
        for bs in &status {
            assert!(bs.budget_remaining_pct > 99.0);
        }
    }
}
