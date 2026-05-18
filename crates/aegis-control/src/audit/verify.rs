/// Audit chain verifier.
///
/// Walk spool from start, recompute chain, report first broken line.
use super::chain::{chain_hash, genesis_hash, ChainEntry};

/// Verification result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Clean { entries: usize },
    Broken {
        line: usize,
        expected: String,
        actual: String,
    },
    ParseError { line: usize, message: String },
    Empty,
}

/// Verify an NDJSON spool string.
pub fn verify_ndjson(ndjson: &str) -> VerifyResult {
    if ndjson.trim().is_empty() {
        return VerifyResult::Empty;
    }

    let mut prev_hash = genesis_hash();
    let mut count = 0;

    for (i, line) in ndjson.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let entry: ChainEntry = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(err) => {
                return VerifyResult::ParseError {
                    line: i + 1,
                    message: err.to_string(),
                };
            }
        };

        let expected = chain_hash(&prev_hash, &entry.event);
        if expected != entry.hash {
            return VerifyResult::Broken {
                line: i + 1,
                expected,
                actual: entry.hash,
            };
        }

        prev_hash = entry.hash;
        count += 1;
    }

    VerifyResult::Clean { entries: count }
}

/// 2026-05-17 F-CRITICAL-013 (control audit): verify every
/// `audit-YYYY-MM-DD.ndjson` file in a directory as ONE continuous
/// chain. Walks files in date order (oldest first), seeding each
/// file's `prev_hash` from the running tail rather than restarting
/// at genesis. Pre-fix every daily file was verified independently
/// from genesis, so an attacker could delete an entire daily file
/// and the remaining files would individually verify clean.
///
/// Returns:
/// - `VerifyResult::Empty` if no `audit-YYYY-MM-DD.ndjson` files
///   matched (the directory may exist with foreign content).
/// - `VerifyResult::Broken { line, ... }` with the GLOBAL line
///   number across files (file boundaries don't reset the counter).
/// - `VerifyResult::Clean { entries }` total entries verified.
/// - `VerifyResult::ParseError` on the first malformed line.
///
/// Foreign files in the directory (anything that doesn't match
/// `audit-YYYY-MM-DD.ndjson`) are silently skipped — same policy
/// as the TTL pruner.
pub fn verify_directory(dir: &std::path::Path) -> std::io::Result<VerifyResult> {
    use crate::audit::sinks::jsonl::parse_audit_filename;

    let mut files: Vec<(chrono::NaiveDate, std::path::PathBuf)> = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VerifyResult::Empty);
        }
        Err(e) => return Err(e),
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let Some(name_s) = name.to_str() else { continue };
        let Some(d) = parse_audit_filename(name_s) else {
            continue;
        };
        files.push((d, ent.path()));
    }
    if files.is_empty() {
        return Ok(VerifyResult::Empty);
    }
    files.sort_by_key(|(d, _)| *d);

    let mut prev_hash = genesis_hash();
    let mut total = 0usize;

    for (_, path) in &files {
        let body = std::fs::read_to_string(path)?;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            total += 1;
            let entry: ChainEntry = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(err) => {
                    return Ok(VerifyResult::ParseError {
                        line: total,
                        message: err.to_string(),
                    });
                }
            };
            let expected = chain_hash(&prev_hash, &entry.event);
            if expected != entry.hash {
                return Ok(VerifyResult::Broken {
                    line: total,
                    expected,
                    actual: entry.hash,
                });
            }
            prev_hash = entry.hash;
        }
    }

    if total == 0 {
        Ok(VerifyResult::Empty)
    } else {
        Ok(VerifyResult::Clean { entries: total })
    }
}

/// Verify a slice of ChainEntries directly.
pub fn verify_entries(entries: &[ChainEntry]) -> VerifyResult {
    if entries.is_empty() {
        return VerifyResult::Empty;
    }

    let mut prev_hash = genesis_hash();

    for (i, entry) in entries.iter().enumerate() {
        let expected = chain_hash(&prev_hash, &entry.event);
        if expected != entry.hash {
            return VerifyResult::Broken {
                line: i + 1,
                expected,
                actual: entry.hash.clone(),
            };
        }
        prev_hash = entry.hash.clone();
    }

    VerifyResult::Clean {
        entries: entries.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain::ChainWriter;
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
            method: None,
            path: None,
            mode: None,
            fields: serde_json::Value::Null,
        }
    }

    fn build_chain(n: usize) -> ChainWriter {
        let mut w = ChainWriter::new();
        for i in 0..n {
            w.append(test_event(&format!("req-{i}")));
        }
        w
    }

    // Clean chain tests.
    #[test]
    fn verify_clean_chain_ndjson() {
        let w = build_chain(5);
        let result = verify_ndjson(&w.to_ndjson());
        assert_eq!(result, VerifyResult::Clean { entries: 5 });
    }

    #[test]
    fn verify_clean_chain_entries() {
        let w = build_chain(3);
        let result = verify_entries(w.entries());
        assert_eq!(result, VerifyResult::Clean { entries: 3 });
    }

    #[test]
    fn verify_single_entry() {
        let w = build_chain(1);
        let result = verify_entries(w.entries());
        assert_eq!(result, VerifyResult::Clean { entries: 1 });
    }

    // Tampered chain tests.
    #[test]
    fn verify_tampered_hash() {
        let w = build_chain(3);
        let mut ndjson = w.to_ndjson();
        // Tamper with first entry's hash.
        ndjson = ndjson.replacen(&w.entries()[0].hash, "0000000000000000000000000000000000000000000000000000000000000000", 1);
        let result = verify_ndjson(&ndjson);
        assert!(matches!(result, VerifyResult::Broken { line: 1, .. }));
    }

    #[test]
    fn verify_tampered_event() {
        let w = build_chain(3);
        let mut ndjson = w.to_ndjson();
        // Tamper with event data in the second line.
        ndjson = ndjson.replace("req-1", "req-TAMPERED");
        let result = verify_ndjson(&ndjson);
        assert!(matches!(result, VerifyResult::Broken { line: 2, .. }));
    }

    #[test]
    fn verify_tampered_middle() {
        let mut w = ChainWriter::new();
        let e0 = w.append(test_event("req-0"));
        let _e1 = w.append(test_event("req-1"));
        let e2 = w.append(test_event("req-2"));

        // Replace entry 1 with a fake entry.
        let mut entries = w.entries().to_vec();
        entries[1] = ChainEntry {
            hash: "bad_hash".into(),
            event: test_event("req-fake"),
        };

        let result = verify_entries(&entries);
        assert!(matches!(result, VerifyResult::Broken { line: 2, .. }));
        // Entry 0 and 2 untouched, but chain breaks at 1.
        let _ = (e0, e2); // Suppress unused warnings.
    }

    #[test]
    fn verify_entries_tampered_first() {
        let w = build_chain(2);
        let mut entries = w.entries().to_vec();
        entries[0].hash = "wrong".into();
        let result = verify_entries(&entries);
        assert!(matches!(result, VerifyResult::Broken { line: 1, .. }));
    }

    // Edge cases.
    #[test]
    fn verify_empty_ndjson() {
        assert_eq!(verify_ndjson(""), VerifyResult::Empty);
    }

    #[test]
    fn verify_empty_entries() {
        assert_eq!(verify_entries(&[]), VerifyResult::Empty);
    }

    #[test]
    fn verify_whitespace_ndjson() {
        assert_eq!(verify_ndjson("   \n  \n  "), VerifyResult::Empty);
    }

    #[test]
    fn verify_parse_error() {
        let result = verify_ndjson("not valid json");
        assert!(matches!(result, VerifyResult::ParseError { line: 1, .. }));
    }

    #[test]
    fn verify_parse_error_line2() {
        let w = build_chain(1);
        let ndjson = format!("{}\nnot json", w.to_ndjson());
        let result = verify_ndjson(&ndjson);
        assert!(matches!(result, VerifyResult::ParseError { line: 2, .. }));
    }

    // Broken result details.
    #[test]
    fn broken_result_has_expected_and_actual() {
        let w = build_chain(2);
        let mut entries = w.entries().to_vec();
        entries[0].hash = "fakehash".into();
        if let VerifyResult::Broken { expected, actual, .. } = verify_entries(&entries) {
            assert_ne!(expected, actual);
            assert_eq!(actual, "fakehash");
        } else {
            panic!("expected Broken");
        }
    }

    // Large chain.
    #[test]
    fn verify_large_chain() {
        let w = build_chain(100);
        let result = verify_entries(w.entries());
        assert_eq!(result, VerifyResult::Clean { entries: 100 });
    }

    #[test]
    fn verify_large_ndjson() {
        let w = build_chain(50);
        let result = verify_ndjson(&w.to_ndjson());
        assert_eq!(result, VerifyResult::Clean { entries: 50 });
    }

    /// 2026-05-17 F-CRITICAL-013 (control audit): `verify_directory`
    /// walks every `audit-YYYY-MM-DD.ndjson` in date order as one
    /// continuous chain, seeding `prev_hash` from the running tail
    /// rather than restarting at genesis on every file. This test
    /// uses the live `JsonlSink` to lay down two daily files; the
    /// directory walk must accept them as one chain.
    #[tokio::test]
    async fn verify_directory_walks_files_in_date_order_as_one_chain() {
        use crate::audit::sinks::jsonl::{JsonlConfig, JsonlSink};
        use chrono::TimeZone;

        let dir = tempdir();
        let cfg = JsonlConfig {
            path: dir.clone(),
            ..Default::default()
        };
        let sink = JsonlSink::open(cfg).await.unwrap();
        for (y, m, d, h) in [
            (2026, 4, 30, 10),
            (2026, 4, 30, 23),
            (2026, 5, 1, 1),
            (2026, 5, 1, 12),
        ] {
            let ts = chrono::Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap();
            sink.write_one(&ev_at(ts)).await.unwrap();
        }
        sink.flush().await.unwrap();

        let res = verify_directory(&dir).unwrap();
        assert_eq!(res, VerifyResult::Clean { entries: 4 });
    }

    /// 2026-05-17 F-CRITICAL-013: the multi-day attack-mask test.
    /// Pre-fix, deleting an entire daily file left the remaining
    /// files individually verify-clean (each restarted at genesis).
    /// With the cross-day chain seed, deleting day A breaks the
    /// chain at day B's first entry — directory verifier surfaces
    /// the gap.
    #[tokio::test]
    async fn verify_directory_detects_deleted_daily_file() {
        use crate::audit::sinks::jsonl::{daily_file_path, JsonlConfig, JsonlSink};
        use chrono::{NaiveDate, TimeZone};

        let dir = tempdir();
        let cfg = JsonlConfig {
            path: dir.clone(),
            ..Default::default()
        };
        let sink = JsonlSink::open(cfg).await.unwrap();
        for (y, m, d) in [(2026, 4, 30), (2026, 5, 1), (2026, 5, 2)] {
            let ts = chrono::Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap();
            sink.write_one(&ev_at(ts)).await.unwrap();
        }
        sink.flush().await.unwrap();

        // Sanity: all 3 chain clean together.
        assert!(matches!(
            verify_directory(&dir).unwrap(),
            VerifyResult::Clean { entries: 3 }
        ));

        // Delete the middle day's file — attacker tries to hide it.
        let middle = daily_file_path(&dir, NaiveDate::from_ymd_opt(2026, 5, 1).unwrap());
        std::fs::remove_file(&middle).unwrap();

        // Now verification must NOT pass clean — the may-2 file's
        // first entry was hashed with may-1's last hash, which is
        // gone, so the chain breaks at the third (post-skip) entry.
        match verify_directory(&dir).unwrap() {
            VerifyResult::Broken { .. } => { /* expected */ }
            other => panic!("expected Broken after deleting middle file, got {other:?}"),
        }
    }

    fn ev_at(ts: chrono::DateTime<chrono::Utc>) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts,
            request_id: "test".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(50),
            method: None,
            path: None,
            mode: None,
            fields: serde_json::Value::Null,
        }
    }

    fn tempdir() -> std::path::PathBuf {
        // Unique-per-call: nanos + atomic counter. Pure nanos
        // collided under parallel `cargo test` runs on the same
        // tokio worker; the counter eliminates that race.
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir()
            .join(format!("aegis-verify-dir-{nanos}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
