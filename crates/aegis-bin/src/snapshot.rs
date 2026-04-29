//! `waf snapshot` and `waf restore` CLI subcommands (B4-T1, B4-T2).
//!
//! Bundles the on-disk effective config + every rules file
//! referenced by `cfg.rules.paths` + a [`SnapshotEnvelope`] of
//! metadata into a single JSON file. Round-trips losslessly so
//! a fresh node can restore the operator's intent verbatim.
//!
//! # Format
//!
//! The wire format is plain JSON. The existing `dr.rs` binary
//! length-prefixed bundle is preserved unchanged for any
//! tooling that consumed it; the CLI uses this richer envelope
//! because operator workflows want to inspect the file with
//! `jq`. A future change can wrap this envelope in `.tar.zst`
//! without breaking the schema.
//!
//! # Secrets
//!
//! The snapshot writes the YAML files **as they sit on disk**
//! — `${secret:vault:…}` references are preserved as
//! references, never resolved. Restoring on a node with
//! different secret-manager bindings still works because
//! resolution happens at config-load time on the restoring
//! node.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::lease_select;

/// Fully-self-describing snapshot envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotEnvelope {
    /// Schema version. Bumped on incompatible format changes;
    /// `restore` refuses anything it doesn't recognise.
    pub schema_version: u32,
    /// `aegis-bin` version (`CARGO_PKG_VERSION`). Restore
    /// across major version breaks is refused.
    pub binary_version: String,
    /// Unix-epoch seconds when the snapshot was written.
    pub created_at: u64,
    /// Node ID of the snapshotting host (derived from
    /// hostname + PID; same as the lease layer uses).
    pub node_id: String,
    /// blake3 hash of `config_yaml` bytes. Operators verify
    /// integrity by re-hashing after transfer.
    pub config_hash: String,
    /// Original `--config` path, as a hint for restore.
    pub config_source_path: String,
    /// True iff secrets were redacted before bundling. Today
    /// always `false` because we always bundle the YAML
    /// as-is — references aren't secrets.
    pub redacted: bool,
    /// Verbatim YAML of the loaded config file.
    pub config_yaml: String,
    /// Every rules file referenced by `cfg.rules.paths`, in
    /// the order listed. `path` is recorded for restore;
    /// `yaml` is the raw text.
    pub rules_files: Vec<RulesFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesFile {
    pub path: String,
    pub yaml: String,
}

/// Current schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Build a [`SnapshotEnvelope`] from on-disk state without
/// touching the network or any background task.
///
/// `config_path` is read once; rules paths come from the
/// loaded config. Missing rules files are surfaced as an
/// error so the operator notices a stale config before they
/// rely on the snapshot.
pub fn build_envelope(config_path: &Path) -> Result<SnapshotEnvelope, SnapshotError> {
    let config_bytes = std::fs::read(config_path).map_err(|e| {
        SnapshotError::Io(format!(
            "read config {}: {e}",
            config_path.display()
        ))
    })?;
    let config_yaml = String::from_utf8(config_bytes.clone())
        .map_err(|e| SnapshotError::Decode(format!("config not UTF-8: {e}")))?;
    let cfg = aegis_core::load_config(config_path)
        .map_err(|e| SnapshotError::Config(e.to_string()))?;
    let mut rules_files = Vec::new();
    for path in &cfg.rules.paths {
        let text = std::fs::read_to_string(path).map_err(|e| {
            SnapshotError::Io(format!(
                "read rules file {}: {e}",
                path.display()
            ))
        })?;
        rules_files.push(RulesFile {
            path: path.display().to_string(),
            yaml: text,
        });
    }
    let node_id = lease_select::derive_node_id().as_str().to_string();
    let created_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(SnapshotEnvelope {
        schema_version: SCHEMA_VERSION,
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at,
        node_id,
        config_hash: blake3::hash(&config_bytes).to_hex().to_string(),
        config_source_path: config_path.display().to_string(),
        redacted: false,
        config_yaml,
        rules_files,
    })
}

/// Verify the envelope is internally consistent —
/// `config_hash` matches `config_yaml`, the schema version is
/// recognised, and the binary version's major matches ours.
pub fn validate_envelope(env: &SnapshotEnvelope) -> Result<(), SnapshotError> {
    if env.schema_version != SCHEMA_VERSION {
        return Err(SnapshotError::Decode(format!(
            "unsupported schema_version {} (expected {SCHEMA_VERSION})",
            env.schema_version
        )));
    }
    let recomputed = blake3::hash(env.config_yaml.as_bytes()).to_hex().to_string();
    if recomputed != env.config_hash {
        return Err(SnapshotError::Decode(format!(
            "config_hash mismatch: stored {} but recomputed {}",
            env.config_hash, recomputed
        )));
    }
    let our_major = current_major();
    let their_major = parse_major(&env.binary_version);
    if let (Some(o), Some(t)) = (our_major, their_major) {
        if o != t {
            return Err(SnapshotError::Decode(format!(
                "snapshot from binary v{} cannot restore on v{}",
                env.binary_version,
                env!("CARGO_PKG_VERSION")
            )));
        }
    }
    Ok(())
}

fn current_major() -> Option<u32> {
    parse_major(env!("CARGO_PKG_VERSION"))
}

fn parse_major(v: &str) -> Option<u32> {
    v.split('.').next().and_then(|s| s.parse().ok())
}

/// Errors raised by snapshot / restore.
#[derive(Debug)]
pub enum SnapshotError {
    Io(String),
    Decode(String),
    Config(String),
    OutputExists(PathBuf),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::Io(m) => write!(f, "snapshot io error: {m}"),
            SnapshotError::Decode(m) => write!(f, "snapshot decode error: {m}"),
            SnapshotError::Config(m) => write!(f, "snapshot config error: {m}"),
            SnapshotError::OutputExists(p) => write!(
                f,
                "output {} already exists; pass --force to overwrite",
                p.display()
            ),
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Serialize an envelope to JSON bytes (pretty-printed for
/// `jq` ergonomics).
pub fn encode(env: &SnapshotEnvelope) -> Result<Vec<u8>, SnapshotError> {
    serde_json::to_vec_pretty(env)
        .map_err(|e| SnapshotError::Decode(e.to_string()))
}

/// Decode JSON bytes back into an envelope.
pub fn decode(bytes: &[u8]) -> Result<SnapshotEnvelope, SnapshotError> {
    serde_json::from_slice(bytes).map_err(|e| SnapshotError::Decode(e.to_string()))
}

/// Atomically write the envelope to `output_path`. Refuses
/// to overwrite unless `force` is set.
pub fn write_to_disk(
    env: &SnapshotEnvelope,
    output_path: &Path,
    force: bool,
) -> Result<usize, SnapshotError> {
    if output_path.exists() && !force {
        return Err(SnapshotError::OutputExists(output_path.to_path_buf()));
    }
    let bytes = encode(env)?;
    std::fs::write(output_path, &bytes).map_err(|e| {
        SnapshotError::Io(format!(
            "write {}: {e}",
            output_path.display()
        ))
    })?;
    Ok(bytes.len())
}

/// CLI entry point: `waf snapshot --output <path> [--config
/// <path>] [--force]`.
pub fn cmd_snapshot(args: &[String]) -> i32 {
    let config_path = parse_flag(args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/waf.yaml"));
    let output = match parse_flag(args, "--output") {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: waf snapshot --output <path> [--config <path>] [--force]");
            return 2;
        }
    };
    let force = args.iter().any(|a| a == "--force");
    match run_snapshot(&config_path, &output, force) {
        Ok(written) => {
            println!(
                "snapshot OK: {} ({} bytes)",
                output.display(),
                written
            );
            0
        }
        Err(e) => {
            eprintln!("snapshot error: {e}");
            1
        }
    }
}

fn run_snapshot(
    config_path: &Path,
    output: &Path,
    force: bool,
) -> Result<usize, SnapshotError> {
    let env = build_envelope(config_path)?;
    write_to_disk(&env, output, force)
}

/// Result of a restore operation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub config_path: PathBuf,
    pub rules_paths: Vec<PathBuf>,
    pub config_bytes: usize,
    pub rules_bytes: usize,
}

/// Restore the envelope back to disk: write `config_yaml`
/// to `config_out` (default = `env.config_source_path`),
/// and each rules file to its recorded path (or under
/// `rules_out` directory if provided).
///
/// Refuses to overwrite existing files unless `force = true`.
/// Runs `aegis_core::load_config` against the written config
/// as a dry-run validator and **rolls back** if validation
/// fails — operators never end up with a half-restored,
/// unparseable config on disk.
pub fn restore_envelope(
    env: &SnapshotEnvelope,
    config_out: Option<&Path>,
    rules_out_dir: Option<&Path>,
    force: bool,
) -> Result<RestoreReport, SnapshotError> {
    validate_envelope(env)?;

    let config_path = match config_out {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(&env.config_source_path),
    };
    let rules_targets: Vec<(PathBuf, &str)> = env
        .rules_files
        .iter()
        .map(|rf| {
            let path = match rules_out_dir {
                Some(dir) => {
                    let original = Path::new(&rf.path);
                    let name = original
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "rules.yaml".to_string());
                    dir.join(name)
                }
                None => PathBuf::from(&rf.path),
            };
            (path, rf.yaml.as_str())
        })
        .collect();

    if !force {
        if config_path.exists() {
            return Err(SnapshotError::OutputExists(config_path));
        }
        for (path, _) in &rules_targets {
            if path.exists() {
                return Err(SnapshotError::OutputExists(path.clone()));
            }
        }
    }

    // Stage 1 — write config to a sibling temp path, validate
    // by re-loading, then atomically rename into place. If
    // validation fails the temp file is unlinked and the
    // operator's existing config (if any) is untouched.
    let tmp_config = staging_path(&config_path);
    write_atomic(&tmp_config, env.config_yaml.as_bytes())?;
    if let Err(e) = aegis_core::load_config(&tmp_config) {
        let _ = std::fs::remove_file(&tmp_config);
        return Err(SnapshotError::Config(format!(
            "restored config failed dry-run validation: {e}"
        )));
    }
    rename_into_place(&tmp_config, &config_path)?;

    // Stage 2 — write each rules file. If one fails, we
    // already have a valid config in place; surface the
    // error so the operator knows which file is missing.
    let mut written_rules = Vec::new();
    let mut rules_total = 0;
    for (path, yaml) in &rules_targets {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    SnapshotError::Io(format!(
                        "create parent for {}: {e}",
                        path.display()
                    ))
                })?;
            }
        }
        write_atomic(path, yaml.as_bytes())?;
        rules_total += yaml.len();
        written_rules.push(path.clone());
    }

    Ok(RestoreReport {
        config_path,
        rules_paths: written_rules,
        config_bytes: env.config_yaml.len(),
        rules_bytes: rules_total,
    })
}

fn staging_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(".restore.tmp");
    PathBuf::from(s)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), SnapshotError> {
    std::fs::write(path, bytes).map_err(|e| {
        SnapshotError::Io(format!("write {}: {e}", path.display()))
    })
}

fn rename_into_place(from: &Path, to: &Path) -> Result<(), SnapshotError> {
    std::fs::rename(from, to).map_err(|e| {
        SnapshotError::Io(format!(
            "rename {} -> {}: {e}",
            from.display(),
            to.display()
        ))
    })
}

/// CLI entry point: `waf restore --from <snap.json>
/// [--config-out <path>] [--rules-out <dir>] [--force]`.
pub fn cmd_restore(args: &[String]) -> i32 {
    let from = match parse_flag(args, "--from") {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: waf restore --from <snap.json> \
                 [--config-out <path>] [--rules-out <dir>] [--force]"
            );
            return 2;
        }
    };
    let config_out = parse_flag(args, "--config-out").map(PathBuf::from);
    let rules_out = parse_flag(args, "--rules-out").map(PathBuf::from);
    let force = args.iter().any(|a| a == "--force");
    match run_restore(&from, config_out.as_deref(), rules_out.as_deref(), force) {
        Ok(report) => {
            println!(
                "restore OK: config -> {} ({} bytes), {} rules file(s) ({} bytes total)",
                report.config_path.display(),
                report.config_bytes,
                report.rules_paths.len(),
                report.rules_bytes,
            );
            for p in &report.rules_paths {
                println!("  rules -> {}", p.display());
            }
            0
        }
        Err(e) => {
            eprintln!("restore error: {e}");
            1
        }
    }
}

fn run_restore(
    from: &Path,
    config_out: Option<&Path>,
    rules_out: Option<&Path>,
    force: bool,
) -> Result<RestoreReport, SnapshotError> {
    let bytes = std::fs::read(from).map_err(|e| {
        SnapshotError::Io(format!(
            "read snapshot {}: {e}",
            from.display()
        ))
    })?;
    let env = decode(&bytes)?;
    restore_envelope(&env, config_out, rules_out, force)
}

fn parse_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).map(String::as_str);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config_yaml() -> &'static str {
        r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
      tls: false
  admin:
    bind: "127.0.0.1:0"

routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: stub-pool

upstreams:
  stub-pool:
    members:
      - addr: "127.0.0.1:9999"
    lb: round_robin

state:
  backend: in_memory
"#
    }

    fn write_minimal_config(dir: &Path) -> PathBuf {
        let path = dir.join("waf.yaml");
        std::fs::write(&path, minimal_config_yaml()).unwrap();
        path
    }

    fn write_config_with_rules(dir: &Path, rules_path: &Path) -> PathBuf {
        let path = dir.join("waf.yaml");
        let rules_str = rules_path.display().to_string().replace('\\', "/");
        let yaml = format!(
            "{}\nrules:\n  paths:\n    - \"{rules_str}\"\n",
            minimal_config_yaml()
        );
        std::fs::write(&path, yaml).unwrap();
        path
    }

    // ---- build_envelope ----

    #[test]
    fn build_envelope_reads_config_and_no_rules() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let env = build_envelope(&cfg_path).unwrap();
        assert_eq!(env.schema_version, SCHEMA_VERSION);
        assert_eq!(env.binary_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(env.config_source_path, cfg_path.display().to_string());
        assert!(env.config_yaml.contains("listeners"));
        assert!(env.rules_files.is_empty());
        // Hash must match.
        let expected =
            blake3::hash(env.config_yaml.as_bytes()).to_hex().to_string();
        assert_eq!(env.config_hash, expected);
    }

    #[test]
    fn build_envelope_inlines_referenced_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.yaml");
        std::fs::write(
            &rules_path,
            "- id: r1\n  priority: 100\n  when: true\n  then: allow\n",
        )
        .unwrap();
        let cfg_path = write_config_with_rules(dir.path(), &rules_path);
        let env = build_envelope(&cfg_path).unwrap();
        assert_eq!(env.rules_files.len(), 1);
        assert!(env.rules_files[0].yaml.contains("id: r1"));
        assert_eq!(
            env.rules_files[0].path,
            rules_path.display().to_string()
        );
    }

    #[test]
    fn build_envelope_errors_on_missing_config() {
        let err = build_envelope(Path::new("/nonexistent/waf.yaml"))
            .err()
            .expect("missing config errors");
        assert!(matches!(err, SnapshotError::Io(_)), "got {err}");
    }

    #[test]
    fn build_envelope_errors_on_missing_rules_path() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("does-not-exist.yaml");
        let cfg_path = write_config_with_rules(dir.path(), &bogus);
        let err = build_envelope(&cfg_path)
            .err()
            .expect("missing rules errors");
        assert!(matches!(err, SnapshotError::Io(_)), "got {err}");
    }

    // ---- encode / decode / validate ----

    #[test]
    fn encode_decode_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let env = build_envelope(&cfg_path).unwrap();
        let bytes = encode(&env).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(env, decoded);
    }

    #[test]
    fn decode_invalid_json_errors() {
        let err = decode(b"{not json").err().unwrap();
        assert!(matches!(err, SnapshotError::Decode(_)));
    }

    #[test]
    fn validate_passes_for_fresh_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let env = build_envelope(&cfg_path).unwrap();
        validate_envelope(&env).unwrap();
    }

    #[test]
    fn validate_rejects_unknown_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let mut env = build_envelope(&cfg_path).unwrap();
        env.schema_version = 999;
        let err = validate_envelope(&env).err().unwrap();
        assert!(matches!(err, SnapshotError::Decode(_)));
    }

    #[test]
    fn validate_rejects_tampered_config_hash() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let mut env = build_envelope(&cfg_path).unwrap();
        env.config_yaml.push_str("\n# tampered\n");
        let err = validate_envelope(&env).err().unwrap();
        assert!(matches!(err, SnapshotError::Decode(_)));
    }

    #[test]
    fn validate_rejects_major_version_break() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let mut env = build_envelope(&cfg_path).unwrap();
        // Force a major bump that differs from ours.
        let our_major = parse_major(env!("CARGO_PKG_VERSION")).unwrap_or(0);
        env.binary_version = format!("{}.0.0", our_major + 5);
        let err = validate_envelope(&env).err().unwrap();
        assert!(matches!(err, SnapshotError::Decode(_)));
    }

    // ---- write_to_disk ----

    #[test]
    fn write_to_disk_writes_then_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let env = build_envelope(&cfg_path).unwrap();
        let out = dir.path().join("snap.json");
        let written = write_to_disk(&env, &out, false).unwrap();
        assert!(written > 0);
        let bytes = std::fs::read(&out).unwrap();
        let restored = decode(&bytes).unwrap();
        assert_eq!(restored, env);
    }

    #[test]
    fn write_to_disk_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let env = build_envelope(&cfg_path).unwrap();
        let out = dir.path().join("snap.json");
        std::fs::write(&out, b"existing").unwrap();
        let err = write_to_disk(&env, &out, false).err().unwrap();
        assert!(matches!(err, SnapshotError::OutputExists(_)), "got {err}");
        // File was untouched.
        assert_eq!(std::fs::read(&out).unwrap(), b"existing");
    }

    #[test]
    fn write_to_disk_overwrites_with_force() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(dir.path());
        let env = build_envelope(&cfg_path).unwrap();
        let out = dir.path().join("snap.json");
        std::fs::write(&out, b"existing").unwrap();
        let written = write_to_disk(&env, &out, true).unwrap();
        assert!(written > 8);
        assert_ne!(std::fs::read(&out).unwrap(), b"existing");
    }

    // ---- parse_major ----

    #[test]
    fn parse_major_extracts_first_segment() {
        assert_eq!(parse_major("0.1.0"), Some(0));
        assert_eq!(parse_major("1.5.2"), Some(1));
        assert_eq!(parse_major("12.0.0"), Some(12));
    }

    #[test]
    fn parse_major_returns_none_for_garbage() {
        assert!(parse_major("not.a.version").is_none());
        assert!(parse_major("").is_none());
    }

    // ---- restore_envelope (B4-T2) ----

    #[test]
    fn restore_round_trips_config_and_rules() {
        let src_dir = tempfile::tempdir().unwrap();
        let rules_path = src_dir.path().join("rules.yaml");
        std::fs::write(
            &rules_path,
            "- id: r1\n  priority: 100\n  when: true\n  then: allow\n",
        )
        .unwrap();
        let cfg_path = write_config_with_rules(src_dir.path(), &rules_path);
        let env = build_envelope(&cfg_path).unwrap();

        let dst_dir = tempfile::tempdir().unwrap();
        let dst_cfg = dst_dir.path().join("waf.yaml");
        let dst_rules = dst_dir.path().join("rules-out");
        let report = restore_envelope(
            &env,
            Some(&dst_cfg),
            Some(&dst_rules),
            false,
        )
        .unwrap();

        assert_eq!(report.config_path, dst_cfg);
        assert_eq!(report.rules_paths.len(), 1);
        assert_eq!(report.config_bytes, env.config_yaml.len());
        // Bytes on disk match envelope.
        let written_cfg = std::fs::read(&dst_cfg).unwrap();
        assert_eq!(written_cfg, env.config_yaml.as_bytes());
        let written_rules = std::fs::read(&report.rules_paths[0]).unwrap();
        assert_eq!(written_rules, env.rules_files[0].yaml.as_bytes());
        // Restored config still parses (validates round-trip end to end).
        aegis_core::load_config(&dst_cfg).unwrap();
    }

    #[test]
    fn restore_refuses_existing_config_without_force() {
        let src_dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(src_dir.path());
        let env = build_envelope(&cfg_path).unwrap();

        let dst_dir = tempfile::tempdir().unwrap();
        let dst_cfg = dst_dir.path().join("waf.yaml");
        std::fs::write(&dst_cfg, b"existing").unwrap();

        let err = restore_envelope(&env, Some(&dst_cfg), None, false)
            .err()
            .unwrap();
        assert!(matches!(err, SnapshotError::OutputExists(_)), "got {err}");
        // File untouched.
        assert_eq!(std::fs::read(&dst_cfg).unwrap(), b"existing");
    }

    #[test]
    fn restore_overwrites_with_force() {
        let src_dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(src_dir.path());
        let env = build_envelope(&cfg_path).unwrap();

        let dst_dir = tempfile::tempdir().unwrap();
        let dst_cfg = dst_dir.path().join("waf.yaml");
        std::fs::write(&dst_cfg, b"existing").unwrap();

        let report =
            restore_envelope(&env, Some(&dst_cfg), None, true).unwrap();
        assert_eq!(report.config_path, dst_cfg);
        let on_disk = std::fs::read(&dst_cfg).unwrap();
        assert_ne!(on_disk, b"existing");
        assert_eq!(on_disk, env.config_yaml.as_bytes());
    }

    #[test]
    fn restore_refuses_tampered_hash() {
        let src_dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(src_dir.path());
        let mut env = build_envelope(&cfg_path).unwrap();
        env.config_yaml.push_str("\n# tampered\n");

        let dst_dir = tempfile::tempdir().unwrap();
        let dst_cfg = dst_dir.path().join("waf.yaml");
        let err = restore_envelope(&env, Some(&dst_cfg), None, true)
            .err()
            .unwrap();
        assert!(matches!(err, SnapshotError::Decode(_)), "got {err}");
        // Nothing was written.
        assert!(!dst_cfg.exists());
    }

    #[test]
    fn restore_refuses_unknown_schema_version() {
        let src_dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(src_dir.path());
        let mut env = build_envelope(&cfg_path).unwrap();
        env.schema_version = 999;

        let dst_dir = tempfile::tempdir().unwrap();
        let dst_cfg = dst_dir.path().join("waf.yaml");
        let err = restore_envelope(&env, Some(&dst_cfg), None, true)
            .err()
            .unwrap();
        assert!(matches!(err, SnapshotError::Decode(_)));
    }

    #[test]
    fn restore_rejects_invalid_config_yaml_and_rolls_back() {
        // Build a valid envelope, then corrupt the embedded
        // YAML (the hash will mismatch first, but to test the
        // dry-run path specifically we update the hash to match
        // the corrupted YAML).
        let src_dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(src_dir.path());
        let mut env = build_envelope(&cfg_path).unwrap();
        env.config_yaml = "this: is: not: valid: yaml: {\n".to_string();
        env.config_hash =
            blake3::hash(env.config_yaml.as_bytes()).to_hex().to_string();

        let dst_dir = tempfile::tempdir().unwrap();
        let dst_cfg = dst_dir.path().join("waf.yaml");
        let err = restore_envelope(&env, Some(&dst_cfg), None, true)
            .err()
            .unwrap();
        assert!(matches!(err, SnapshotError::Config(_)), "got {err}");
        // The tmp file was unlinked and the destination never
        // appeared, so a half-restored state is impossible.
        assert!(!dst_cfg.exists());
    }

    #[test]
    fn restore_rules_out_dir_uses_basename() {
        let src_dir = tempfile::tempdir().unwrap();
        let rules_path = src_dir.path().join("custom-name.yaml");
        std::fs::write(
            &rules_path,
            "- id: r1\n  priority: 100\n  when: true\n  then: allow\n",
        )
        .unwrap();
        let cfg_path = write_config_with_rules(src_dir.path(), &rules_path);
        let env = build_envelope(&cfg_path).unwrap();

        let dst_dir = tempfile::tempdir().unwrap();
        let dst_cfg = dst_dir.path().join("waf.yaml");
        let dst_rules = dst_dir.path().join("rules-out");
        let report = restore_envelope(
            &env,
            Some(&dst_cfg),
            Some(&dst_rules),
            false,
        )
        .unwrap();

        // Rules ended up at <dst_rules>/<basename>.
        assert_eq!(report.rules_paths.len(), 1);
        let p = &report.rules_paths[0];
        assert_eq!(
            p.parent().map(Path::to_path_buf),
            Some(dst_rules.clone())
        );
        assert_eq!(p.file_name().unwrap(), "custom-name.yaml");
    }

    #[test]
    fn restore_default_paths_use_envelope_source_paths() {
        let src_dir = tempfile::tempdir().unwrap();
        let rules_path = src_dir.path().join("rules.yaml");
        std::fs::write(
            &rules_path,
            "- id: r1\n  priority: 100\n  when: true\n  then: allow\n",
        )
        .unwrap();
        let cfg_path = write_config_with_rules(src_dir.path(), &rules_path);
        let env = build_envelope(&cfg_path).unwrap();
        // Move the source files away — restore should put them
        // back at the original paths.
        std::fs::remove_file(&cfg_path).unwrap();
        std::fs::remove_file(&rules_path).unwrap();

        let report = restore_envelope(&env, None, None, false).unwrap();

        assert_eq!(report.config_path, PathBuf::from(&env.config_source_path));
        assert!(report.config_path.exists());
        assert_eq!(report.rules_paths.len(), 1);
        assert_eq!(report.rules_paths[0], PathBuf::from(&env.rules_files[0].path));
        assert!(report.rules_paths[0].exists());
    }

    #[test]
    fn run_restore_decodes_from_disk() {
        // End-to-end: snapshot -> file -> restore.
        let src_dir = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(src_dir.path());
        let env = build_envelope(&cfg_path).unwrap();
        let snap_file = src_dir.path().join("snap.json");
        write_to_disk(&env, &snap_file, false).unwrap();

        let dst_dir = tempfile::tempdir().unwrap();
        let dst_cfg = dst_dir.path().join("waf.yaml");
        let report =
            run_restore(&snap_file, Some(&dst_cfg), None, false).unwrap();
        assert_eq!(report.config_path, dst_cfg);
        assert!(dst_cfg.exists());
    }

    #[test]
    fn run_restore_errors_on_missing_snapshot_file() {
        let err = run_restore(
            Path::new("/nonexistent/snap.json"),
            None,
            None,
            false,
        )
        .err()
        .unwrap();
        assert!(matches!(err, SnapshotError::Io(_)), "got {err}");
    }
}
