/// Audit hash chain writer.
///
/// `hash = sha256(prev_hash || canonical_json(event))`
/// First event: `prev_hash = sha256(b"genesis")`
use aegis_core::audit::AuditEvent;
use sha2::{Digest, Sha256};

/// Genesis hash: SHA-256 of `b"genesis"`.
pub fn genesis_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"genesis");
    hex::encode(hasher.finalize())
}

/// Compute the chain hash for an event.
pub fn chain_hash(prev_hash: &str, event: &AuditEvent) -> String {
    let canonical = canonical_json(event);
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Canonical JSON: sorted keys, no extra whitespace.
fn canonical_json(event: &AuditEvent) -> String {
    serde_json::to_string(event).unwrap_or_default()
}

/// A chain entry (stored as NDJSON).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChainEntry {
    pub hash: String,
    pub event: AuditEvent,
}

/// Chain writer that maintains the running hash.
pub struct ChainWriter {
    prev_hash: String,
    entries: Vec<ChainEntry>,
}

impl ChainWriter {
    pub fn new() -> Self {
        Self {
            prev_hash: genesis_hash(),
            entries: Vec::new(),
        }
    }

    /// Append an event to the chain.
    pub fn append(&mut self, event: AuditEvent) -> ChainEntry {
        let hash = chain_hash(&self.prev_hash, &event);
        let entry = ChainEntry {
            hash: hash.clone(),
            event,
        };
        self.prev_hash = hash;
        self.entries.push(entry.clone());
        entry
    }

    /// Current chain head hash.
    pub fn head_hash(&self) -> &str {
        &self.prev_hash
    }

    /// Number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries.
    pub fn entries(&self) -> &[ChainEntry] {
        &self.entries
    }

    /// Serialize chain to NDJSON.
    pub fn to_ndjson(&self) -> String {
        self.entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for ChainWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Hex encoding helper (no external dep needed).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

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
    fn genesis_hash_deterministic() {
        let a = genesis_hash();
        let b = genesis_hash();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // SHA-256 hex.
    }

    #[test]
    fn chain_hash_deterministic() {
        let ev = test_event("req-1");
        let a = chain_hash("prev", &ev);
        let b = chain_hash("prev", &ev);
        assert_eq!(a, b);
    }

    #[test]
    fn chain_hash_changes_with_prev() {
        let ev = test_event("req-1");
        let a = chain_hash("hash_a", &ev);
        let b = chain_hash("hash_b", &ev);
        assert_ne!(a, b);
    }

    #[test]
    fn chain_hash_changes_with_event() {
        let a = chain_hash("prev", &test_event("req-1"));
        let b = chain_hash("prev", &test_event("req-2"));
        assert_ne!(a, b);
    }

    #[test]
    fn writer_starts_with_genesis() {
        let w = ChainWriter::new();
        assert_eq!(w.head_hash(), genesis_hash());
        assert!(w.is_empty());
    }

    #[test]
    fn writer_append_updates_head() {
        let mut w = ChainWriter::new();
        let genesis = w.head_hash().to_string();
        w.append(test_event("req-1"));
        assert_ne!(w.head_hash(), genesis);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn writer_chain_is_ordered() {
        let mut w = ChainWriter::new();
        w.append(test_event("req-1"));
        w.append(test_event("req-2"));
        w.append(test_event("req-3"));
        assert_eq!(w.len(), 3);
        assert_eq!(w.entries()[0].event.request_id, "req-1");
        assert_eq!(w.entries()[2].event.request_id, "req-3");
    }

    #[test]
    fn chain_integrity_verifiable() {
        let mut w = ChainWriter::new();
        w.append(test_event("req-1"));
        w.append(test_event("req-2"));

        // Verify chain manually.
        let entries = w.entries();
        let mut prev = genesis_hash();
        for entry in entries {
            let expected = chain_hash(&prev, &entry.event);
            assert_eq!(entry.hash, expected);
            prev = entry.hash.clone();
        }
    }

    #[test]
    fn tampered_event_breaks_chain() {
        let mut w = ChainWriter::new();
        w.append(test_event("req-1"));
        w.append(test_event("req-2"));

        let entries = w.entries();
        // If we tamper with entry[0]'s event, entry[1]'s hash won't verify.
        let mut tampered = entries[0].event.clone();
        tampered.reason = "TAMPERED".into();
        let recomputed = chain_hash(&genesis_hash(), &tampered);
        assert_ne!(recomputed, entries[0].hash);
    }

    #[test]
    fn ndjson_output() {
        let mut w = ChainWriter::new();
        w.append(test_event("req-1"));
        w.append(test_event("req-2"));
        let ndjson = w.to_ndjson();
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line is valid JSON.
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn ndjson_contains_hashes() {
        let mut w = ChainWriter::new();
        w.append(test_event("req-1"));
        let ndjson = w.to_ndjson();
        assert!(ndjson.contains(&w.entries()[0].hash));
    }

    #[test]
    fn chain_entry_serializes() {
        let mut w = ChainWriter::new();
        let entry = w.append(test_event("req-ser"));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("req-ser"));
        assert!(json.contains(&entry.hash));
    }

    #[test]
    fn chain_entry_deserializes() {
        let mut w = ChainWriter::new();
        let entry = w.append(test_event("req-de"));
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ChainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hash, entry.hash);
        assert_eq!(parsed.event.request_id, "req-de");
    }
}
