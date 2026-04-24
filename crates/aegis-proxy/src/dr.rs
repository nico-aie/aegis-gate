//! Disaster Recovery: snapshot and restore.
//!
//! `./waf snapshot --out /tmp/cfg.tar.zst` — effective config + rules + version
//! stamp.  `./waf restore <file>` — dry-run validator before activating.

use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

/// Metadata included in every snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMeta {
    pub version: u32,
    pub created_at: u64, // Unix epoch seconds
    pub node_id: String,
    pub config_hash: String,
}

impl SnapshotMeta {
    pub fn new(node_id: &str, config_hash: &str) -> Self {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            version: 1,
            created_at: ts,
            node_id: node_id.to_string(),
            config_hash: config_hash.to_string(),
        }
    }
}

/// Create a snapshot: bundle config bytes + metadata into a single blob.
/// In production, this would be a tar.zst archive signed with a cluster key.
pub fn create_snapshot(
    config_bytes: &[u8],
    meta: &SnapshotMeta,
) -> Result<Vec<u8>, std::io::Error> {
    let meta_json = serde_json::to_vec(meta)
        .map_err(std::io::Error::other)?;

    let mut bundle = Vec::new();
    // Simple format: [4 bytes meta_len][meta_json][config_bytes]
    let meta_len = meta_json.len() as u32;
    bundle.write_all(&meta_len.to_le_bytes())?;
    bundle.write_all(&meta_json)?;
    bundle.write_all(config_bytes)?;
    Ok(bundle)
}

/// Restore a snapshot: parse the bundle back into metadata + config bytes.
pub fn restore_snapshot(bundle: &[u8]) -> Result<(SnapshotMeta, Vec<u8>), std::io::Error> {
    if bundle.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot too small",
        ));
    }

    let meta_len =
        u32::from_le_bytes(bundle[..4].try_into().unwrap()) as usize;

    if bundle.len() < 4 + meta_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot truncated",
        ));
    }

    let meta: SnapshotMeta = serde_json::from_slice(&bundle[4..4 + meta_len])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let config_bytes = bundle[4 + meta_len..].to_vec();
    Ok((meta, config_bytes))
}

/// Write a snapshot to disk.
pub fn save_snapshot(path: &Path, bundle: &[u8]) -> Result<(), std::io::Error> {
    std::fs::write(path, bundle)
}

/// Load a snapshot from disk.
pub fn load_snapshot(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(path)
}

/// Dry-run validate: parse the config bytes to check they're valid YAML.
pub fn dry_run_validate(config_bytes: &[u8]) -> Result<(), String> {
    let _: serde_yaml::Value = serde_yaml::from_slice(config_bytes)
        .map_err(|e| format!("invalid YAML: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Vec<u8> {
        br#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: test
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#
        .to_vec()
    }

    #[test]
    fn snapshot_roundtrip() {
        let config = sample_config();
        let meta = SnapshotMeta::new("node-1", "abc123");

        let bundle = create_snapshot(&config, &meta).unwrap();
        let (restored_meta, restored_config) = restore_snapshot(&bundle).unwrap();

        assert_eq!(restored_meta.version, 1);
        assert_eq!(restored_meta.node_id, "node-1");
        assert_eq!(restored_meta.config_hash, "abc123");
        assert_eq!(restored_config, config);
    }

    #[test]
    fn restore_invalid_bundle() {
        assert!(restore_snapshot(b"ab").is_err());
    }

    #[test]
    fn save_and_load_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.bin");

        let config = sample_config();
        let meta = SnapshotMeta::new("node-2", "def456");
        let bundle = create_snapshot(&config, &meta).unwrap();

        save_snapshot(&path, &bundle).unwrap();
        let loaded = load_snapshot(&path).unwrap();
        assert_eq!(loaded, bundle);
    }

    #[test]
    fn dry_run_valid_config() {
        let config = sample_config();
        assert!(dry_run_validate(&config).is_ok());
    }

    #[test]
    fn dry_run_invalid_config() {
        let result = dry_run_validate(b"not: [valid: yaml: {");
        assert!(result.is_err());
    }

    #[test]
    fn meta_has_timestamp() {
        let meta = SnapshotMeta::new("n", "h");
        assert!(meta.created_at > 0);
    }
}
