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
}
