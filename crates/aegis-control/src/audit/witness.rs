/// Witness export: periodic signing of chain head.
///
/// Leader-only task signs the chain head hash with the cluster key
/// and exports to an append-only storage target.
use serde::{Deserialize, Serialize};

/// Witness record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessRecord {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub chain_head_hash: String,
    pub signature: String,
    pub node_id: String,
    pub entry_count: u64,
}

/// Sign a chain head hash with the given key.
pub fn sign_chain_head(head_hash: &str, key: &[u8; 32], node_id: &str, entry_count: u64) -> WitnessRecord {
    let sig_input = format!("{head_hash}:{node_id}:{entry_count}");
    let sig = blake3::keyed_hash(key, sig_input.as_bytes());
    WitnessRecord {
        ts: chrono::Utc::now(),
        chain_head_hash: head_hash.into(),
        signature: sig.to_hex().to_string(),
        node_id: node_id.into(),
        entry_count,
    }
}

/// Verify a witness record against its chain head.
pub fn verify_witness(record: &WitnessRecord, key: &[u8; 32]) -> bool {
    let sig_input = format!(
        "{}:{}:{}",
        record.chain_head_hash, record.node_id, record.entry_count
    );
    let expected = blake3::keyed_hash(key, sig_input.as_bytes());
    expected.to_hex().to_string() == record.signature
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [42u8; 32];

    #[test]
    fn sign_and_verify() {
        let record = sign_chain_head("abc123", &TEST_KEY, "node-1", 100);
        assert!(verify_witness(&record, &TEST_KEY));
    }

    #[test]
    fn verify_fails_wrong_key() {
        let record = sign_chain_head("abc123", &TEST_KEY, "node-1", 100);
        let wrong_key = [99u8; 32];
        assert!(!verify_witness(&record, &wrong_key));
    }

    #[test]
    fn verify_fails_tampered_hash() {
        let mut record = sign_chain_head("abc123", &TEST_KEY, "node-1", 100);
        record.chain_head_hash = "tampered".into();
        assert!(!verify_witness(&record, &TEST_KEY));
    }

    #[test]
    fn verify_fails_tampered_count() {
        let mut record = sign_chain_head("abc123", &TEST_KEY, "node-1", 100);
        record.entry_count = 999;
        assert!(!verify_witness(&record, &TEST_KEY));
    }

    #[test]
    fn record_serializes() {
        let record = sign_chain_head("hash", &TEST_KEY, "n1", 10);
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("hash"));
        assert!(json.contains("n1"));
    }

    #[test]
    fn record_roundtrip() {
        let record = sign_chain_head("hash", &TEST_KEY, "n1", 10);
        let json = serde_json::to_string(&record).unwrap();
        let parsed: WitnessRecord = serde_json::from_str(&json).unwrap();
        assert!(verify_witness(&parsed, &TEST_KEY));
    }
}
