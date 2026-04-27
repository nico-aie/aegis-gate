// GitOps config loader.
//
// Poll or webhook from a configured Git repository. Verify commit
// signatures (GPG/SSH) against `allowed_signers`. Dry-run validate
// before applying; swap via ConfigBroadcast. Break-glass: direct API
// edit creates a branch + PR automatically.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// GitOps loader configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitOpsConfig {
    pub repo_url: String,
    pub branch: String,
    pub poll_interval_secs: u64,
    pub config_path: String,
    pub allowed_signers: Vec<String>,
    pub require_signed_commits: bool,
}

impl Default for GitOpsConfig {
    fn default() -> Self {
        Self {
            repo_url: String::new(),
            branch: "main".into(),
            poll_interval_secs: 60,
            config_path: "waf.yaml".into(),
            allowed_signers: Vec::new(),
            require_signed_commits: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Commit representation
// ---------------------------------------------------------------------------

/// A commit from the Git repository.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitCommit {
    pub sha: String,
    pub message: String,
    pub author: String,
    pub timestamp: DateTime<Utc>,
    pub signature: Option<CommitSignature>,
}

/// Commit signature metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitSignature {
    pub signer: String,
    pub method: SignatureMethod,
    pub verified: bool,
}

/// Signature type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureMethod {
    Gpg,
    Ssh,
}

// ---------------------------------------------------------------------------
// Git client trait (for mocking)
// ---------------------------------------------------------------------------

/// Abstraction over git operations so tests can mock.
#[async_trait::async_trait]
pub trait GitClient: Send + Sync {
    /// Fetch the latest commit on the configured branch.
    async fn fetch_head(&self) -> Result<GitCommit, GitOpsError>;

    /// Read the config file content at a given commit SHA.
    async fn read_file(&self, sha: &str, path: &str) -> Result<String, GitOpsError>;

    /// Create a branch from the current HEAD.
    async fn create_branch(&self, branch_name: &str) -> Result<(), GitOpsError>;

    /// Commit a file change and push.
    async fn commit_and_push(
        &self,
        branch: &str,
        path: &str,
        content: &str,
        message: &str,
    ) -> Result<String, GitOpsError>;

    /// Open a pull request from a branch to the main branch.
    async fn open_pr(
        &self,
        from_branch: &str,
        to_branch: &str,
        title: &str,
        body: &str,
    ) -> Result<PullRequest, GitOpsError>;
}

/// Pull request info.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PullRequest {
    pub number: u64,
    pub url: String,
    pub title: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// GitOps-specific errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitOpsError {
    FetchFailed(String),
    UnsignedCommit { sha: String },
    UnknownSigner { sha: String, signer: String },
    ValidationFailed(String),
    ApplyFailed(String),
    BranchCreationFailed(String),
    PrCreationFailed(String),
}

impl std::fmt::Display for GitOpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FetchFailed(msg) => write!(f, "fetch failed: {msg}"),
            Self::UnsignedCommit { sha } => write!(f, "unsigned commit: {sha}"),
            Self::UnknownSigner { sha, signer } => {
                write!(f, "unknown signer {signer} on commit {sha}")
            }
            Self::ValidationFailed(msg) => write!(f, "validation failed: {msg}"),
            Self::ApplyFailed(msg) => write!(f, "apply failed: {msg}"),
            Self::BranchCreationFailed(msg) => write!(f, "branch creation failed: {msg}"),
            Self::PrCreationFailed(msg) => write!(f, "PR creation failed: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Verify a commit's signature against the allowed signers list.
pub fn verify_signature(
    commit: &GitCommit,
    config: &GitOpsConfig,
) -> Result<(), GitOpsError> {
    if !config.require_signed_commits {
        return Ok(());
    }

    let sig = commit.signature.as_ref().ok_or_else(|| GitOpsError::UnsignedCommit {
        sha: commit.sha.clone(),
    })?;

    if !sig.verified {
        return Err(GitOpsError::UnsignedCommit {
            sha: commit.sha.clone(),
        });
    }

    if !config.allowed_signers.iter().any(|s| s == &sig.signer) {
        return Err(GitOpsError::UnknownSigner {
            sha: commit.sha.clone(),
            signer: sig.signer.clone(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Config validator (dry-run)
// ---------------------------------------------------------------------------

/// Validate config content before applying (dry-run).
/// Returns Ok(()) if valid, Err with detail if not.
pub fn dry_run_validate(content: &str) -> Result<(), GitOpsError> {
    // Must be valid YAML.
    let value: Result<serde_json::Value, _> = serde_yaml::from_str(content);
    match value {
        Ok(_) => Ok(()),
        Err(e) => Err(GitOpsError::ValidationFailed(e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Apply log (tracks what was applied)
// ---------------------------------------------------------------------------

/// Record of an applied config change.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyRecord {
    pub ts: DateTime<Utc>,
    pub commit_sha: String,
    pub commit_message: String,
    pub author: String,
    pub outcome: ApplyOutcome,
}

/// Outcome of an apply attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplyOutcome {
    Applied,
    Rejected { reason: String },
    DryRunFailed { reason: String },
}

// ---------------------------------------------------------------------------
// GitOps loader
// ---------------------------------------------------------------------------

/// The GitOps loader: polls, verifies, validates, and applies config.
pub struct GitOpsLoader {
    config: GitOpsConfig,
    last_applied_sha: Mutex<Option<String>>,
    apply_log: Mutex<Vec<ApplyRecord>>,
}

impl GitOpsLoader {
    pub fn new(config: GitOpsConfig) -> Self {
        Self {
            config,
            last_applied_sha: Mutex::new(None),
            apply_log: Mutex::new(Vec::new()),
        }
    }

    /// Attempt to sync: fetch head, verify sig, validate, and apply.
    pub async fn sync(
        &self,
        client: &dyn GitClient,
    ) -> Result<ApplyRecord, GitOpsError> {
        let commit = client.fetch_head().await?;

        // Skip if already applied.
        {
            let last = self.last_applied_sha.lock().unwrap();
            if last.as_deref() == Some(&commit.sha) {
                let record = ApplyRecord {
                    ts: Utc::now(),
                    commit_sha: commit.sha.clone(),
                    commit_message: commit.message.clone(),
                    author: commit.author.clone(),
                    outcome: ApplyOutcome::Applied, // Already current.
                };
                return Ok(record);
            }
        }

        // Verify signature.
        if let Err(e) = verify_signature(&commit, &self.config) {
            let record = ApplyRecord {
                ts: Utc::now(),
                commit_sha: commit.sha.clone(),
                commit_message: commit.message.clone(),
                author: commit.author.clone(),
                outcome: ApplyOutcome::Rejected {
                    reason: e.to_string(),
                },
            };
            self.apply_log.lock().unwrap().push(record.clone());
            return Err(e);
        }

        // Read config file.
        let content = client
            .read_file(&commit.sha, &self.config.config_path)
            .await?;

        // Dry-run validate.
        if let Err(e) = dry_run_validate(&content) {
            let record = ApplyRecord {
                ts: Utc::now(),
                commit_sha: commit.sha.clone(),
                commit_message: commit.message.clone(),
                author: commit.author.clone(),
                outcome: ApplyOutcome::DryRunFailed {
                    reason: e.to_string(),
                },
            };
            self.apply_log.lock().unwrap().push(record.clone());
            return Err(e);
        }

        // Apply (update last SHA).
        *self.last_applied_sha.lock().unwrap() = Some(commit.sha.clone());

        let record = ApplyRecord {
            ts: Utc::now(),
            commit_sha: commit.sha.clone(),
            commit_message: commit.message.clone(),
            author: commit.author.clone(),
            outcome: ApplyOutcome::Applied,
        };
        self.apply_log.lock().unwrap().push(record.clone());
        Ok(record)
    }

    /// Break-glass: push a direct API edit as a branch + PR.
    pub async fn break_glass_edit(
        &self,
        client: &dyn GitClient,
        new_content: &str,
        reason: &str,
        actor: &str,
    ) -> Result<PullRequest, GitOpsError> {
        // Validate first.
        dry_run_validate(new_content)?;

        let branch_name = format!(
            "break-glass/{}-{}",
            actor,
            Utc::now().format("%Y%m%d-%H%M%S")
        );

        client.create_branch(&branch_name).await?;

        let commit_msg = format!("break-glass: {reason} (by {actor})");
        client
            .commit_and_push(&branch_name, &self.config.config_path, new_content, &commit_msg)
            .await?;

        let pr = client
            .open_pr(
                &branch_name,
                &self.config.branch,
                &format!("[break-glass] {reason}"),
                &format!(
                    "Direct API edit by **{actor}**.\n\nReason: {reason}\n\n> This PR was auto-created by the break-glass flow."
                ),
            )
            .await?;

        Ok(pr)
    }

    /// Get the last applied commit SHA.
    pub fn last_applied_sha(&self) -> Option<String> {
        self.last_applied_sha.lock().unwrap().clone()
    }

    /// Get the apply log.
    pub fn apply_log(&self) -> Vec<ApplyRecord> {
        self.apply_log.lock().unwrap().clone()
    }

    /// Get the config.
    pub fn config(&self) -> &GitOpsConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // -- Mock Git client ---------------------------------------------------

    struct MockGitClient {
        head: StdMutex<GitCommit>,
        files: StdMutex<std::collections::HashMap<String, String>>,
        branches_created: StdMutex<Vec<String>>,
        commits_pushed: StdMutex<Vec<(String, String, String)>>,
        prs_opened: StdMutex<Vec<PullRequest>>,
    }

    impl MockGitClient {
        fn new(commit: GitCommit) -> Self {
            Self {
                head: StdMutex::new(commit),
                files: StdMutex::new(std::collections::HashMap::new()),
                branches_created: StdMutex::new(Vec::new()),
                commits_pushed: StdMutex::new(Vec::new()),
                prs_opened: StdMutex::new(Vec::new()),
            }
        }

        fn set_file(&self, path: &str, content: &str) {
            self.files
                .lock()
                .unwrap()
                .insert(path.into(), content.into());
        }
    }

    #[async_trait::async_trait]
    impl GitClient for MockGitClient {
        async fn fetch_head(&self) -> Result<GitCommit, GitOpsError> {
            Ok(self.head.lock().unwrap().clone())
        }

        async fn read_file(&self, _sha: &str, path: &str) -> Result<String, GitOpsError> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| GitOpsError::FetchFailed(format!("file not found: {path}")))
        }

        async fn create_branch(&self, branch_name: &str) -> Result<(), GitOpsError> {
            self.branches_created
                .lock()
                .unwrap()
                .push(branch_name.into());
            Ok(())
        }

        async fn commit_and_push(
            &self,
            branch: &str,
            path: &str,
            content: &str,
            _message: &str,
        ) -> Result<String, GitOpsError> {
            self.commits_pushed.lock().unwrap().push((
                branch.into(),
                path.into(),
                content.into(),
            ));
            Ok("new-sha-123".into())
        }

        async fn open_pr(
            &self,
            _from: &str,
            _to: &str,
            title: &str,
            _body: &str,
        ) -> Result<PullRequest, GitOpsError> {
            let pr = PullRequest {
                number: 42,
                url: "https://git.example.com/pr/42".into(),
                title: title.into(),
            };
            self.prs_opened.lock().unwrap().push(pr.clone());
            Ok(pr)
        }
    }

    // -- Helpers -----------------------------------------------------------

    fn signed_commit(sha: &str, signer: &str) -> GitCommit {
        GitCommit {
            sha: sha.into(),
            message: "update config".into(),
            author: "dev@example.com".into(),
            timestamp: Utc::now(),
            signature: Some(CommitSignature {
                signer: signer.into(),
                method: SignatureMethod::Gpg,
                verified: true,
            }),
        }
    }

    fn unsigned_commit(sha: &str) -> GitCommit {
        GitCommit {
            sha: sha.into(),
            message: "sneaky change".into(),
            author: "anon@example.com".into(),
            timestamp: Utc::now(),
            signature: None,
        }
    }

    fn test_config() -> GitOpsConfig {
        GitOpsConfig {
            repo_url: "https://git.example.com/aegis/config".into(),
            branch: "main".into(),
            poll_interval_secs: 30,
            config_path: "waf.yaml".into(),
            allowed_signers: vec!["dev@example.com".into(), "ops@example.com".into()],
            require_signed_commits: true,
        }
    }

    const VALID_YAML: &str = "listeners:\n  - addr: 0.0.0.0:443\n";
    const INVALID_YAML: &str = "listeners: [unclosed";

    // -- Signature verification tests --------------------------------------

    #[test]
    fn verify_signed_commit_ok() {
        let commit = signed_commit("abc123", "dev@example.com");
        assert!(verify_signature(&commit, &test_config()).is_ok());
    }

    #[test]
    fn verify_unsigned_commit_rejected() {
        let commit = unsigned_commit("abc123");
        let result = verify_signature(&commit, &test_config());
        assert!(matches!(result, Err(GitOpsError::UnsignedCommit { .. })));
    }

    #[test]
    fn verify_unknown_signer_rejected() {
        let commit = signed_commit("abc123", "evil@attacker.com");
        let result = verify_signature(&commit, &test_config());
        assert!(matches!(result, Err(GitOpsError::UnknownSigner { .. })));
    }

    #[test]
    fn verify_unverified_signature_rejected() {
        let mut commit = signed_commit("abc123", "dev@example.com");
        commit.signature.as_mut().unwrap().verified = false;
        let result = verify_signature(&commit, &test_config());
        assert!(matches!(result, Err(GitOpsError::UnsignedCommit { .. })));
    }

    #[test]
    fn verify_disabled_allows_unsigned() {
        let commit = unsigned_commit("abc123");
        let mut cfg = test_config();
        cfg.require_signed_commits = false;
        assert!(verify_signature(&commit, &cfg).is_ok());
    }

    #[test]
    fn verify_second_allowed_signer() {
        let commit = signed_commit("abc123", "ops@example.com");
        assert!(verify_signature(&commit, &test_config()).is_ok());
    }

    // -- Dry-run validation tests ------------------------------------------

    #[test]
    fn dry_run_valid_yaml() {
        assert!(dry_run_validate(VALID_YAML).is_ok());
    }

    #[test]
    fn dry_run_invalid_yaml() {
        let result = dry_run_validate(INVALID_YAML);
        assert!(matches!(result, Err(GitOpsError::ValidationFailed(_))));
    }

    #[test]
    fn dry_run_empty_yaml() {
        assert!(dry_run_validate("").is_ok());
    }

    #[test]
    fn dry_run_json_as_yaml() {
        assert!(dry_run_validate(r#"{"key": "value"}"#).is_ok());
    }

    // -- Sync tests --------------------------------------------------------

    #[tokio::test]
    async fn sync_signed_commit_applied() {
        let commit = signed_commit("sha-001", "dev@example.com");
        let client = MockGitClient::new(commit);
        client.set_file("waf.yaml", VALID_YAML);

        let loader = GitOpsLoader::new(test_config());
        let record = loader.sync(&client).await.unwrap();

        assert_eq!(record.outcome, ApplyOutcome::Applied);
        assert_eq!(record.commit_sha, "sha-001");
        assert_eq!(loader.last_applied_sha(), Some("sha-001".into()));
    }

    #[tokio::test]
    async fn sync_unsigned_commit_rejected() {
        let commit = unsigned_commit("sha-bad");
        let client = MockGitClient::new(commit);
        client.set_file("waf.yaml", VALID_YAML);

        let loader = GitOpsLoader::new(test_config());
        let result = loader.sync(&client).await;

        assert!(matches!(result, Err(GitOpsError::UnsignedCommit { .. })));
        assert!(loader.last_applied_sha().is_none());
        // Rejection recorded in apply log.
        let log = loader.apply_log();
        assert_eq!(log.len(), 1);
        assert!(matches!(log[0].outcome, ApplyOutcome::Rejected { .. }));
    }

    #[tokio::test]
    async fn sync_invalid_config_dry_run_fails() {
        let commit = signed_commit("sha-002", "dev@example.com");
        let client = MockGitClient::new(commit);
        client.set_file("waf.yaml", INVALID_YAML);

        let loader = GitOpsLoader::new(test_config());
        let result = loader.sync(&client).await;

        assert!(matches!(result, Err(GitOpsError::ValidationFailed(_))));
        assert!(loader.last_applied_sha().is_none());
        let log = loader.apply_log();
        assert_eq!(log.len(), 1);
        assert!(matches!(log[0].outcome, ApplyOutcome::DryRunFailed { .. }));
    }

    #[tokio::test]
    async fn sync_skips_already_applied() {
        let commit = signed_commit("sha-003", "dev@example.com");
        let client = MockGitClient::new(commit);
        client.set_file("waf.yaml", VALID_YAML);

        let loader = GitOpsLoader::new(test_config());
        loader.sync(&client).await.unwrap();
        let record = loader.sync(&client).await.unwrap();

        // Second sync is a no-op (same SHA).
        assert_eq!(record.outcome, ApplyOutcome::Applied);
        // Only one entry in the log (first sync).
        assert_eq!(loader.apply_log().len(), 1);
    }

    #[tokio::test]
    async fn sync_applies_new_sha_after_previous() {
        let commit1 = signed_commit("sha-100", "dev@example.com");
        let client = MockGitClient::new(commit1);
        client.set_file("waf.yaml", VALID_YAML);

        let loader = GitOpsLoader::new(test_config());
        loader.sync(&client).await.unwrap();
        assert_eq!(loader.last_applied_sha(), Some("sha-100".into()));

        // New commit.
        *client.head.lock().unwrap() = signed_commit("sha-200", "ops@example.com");
        loader.sync(&client).await.unwrap();
        assert_eq!(loader.last_applied_sha(), Some("sha-200".into()));
        assert_eq!(loader.apply_log().len(), 2);
    }

    #[tokio::test]
    async fn sync_unknown_signer_rejected() {
        let commit = signed_commit("sha-evil", "evil@attacker.com");
        let client = MockGitClient::new(commit);
        client.set_file("waf.yaml", VALID_YAML);

        let loader = GitOpsLoader::new(test_config());
        let result = loader.sync(&client).await;
        assert!(matches!(result, Err(GitOpsError::UnknownSigner { .. })));
    }

    // -- Break-glass tests -------------------------------------------------

    #[tokio::test]
    async fn break_glass_creates_branch_and_pr() {
        let commit = signed_commit("sha-current", "dev@example.com");
        let client = MockGitClient::new(commit);

        let loader = GitOpsLoader::new(test_config());
        let pr = loader
            .break_glass_edit(&client, VALID_YAML, "emergency fix", "admin")
            .await
            .unwrap();

        assert_eq!(pr.number, 42);
        assert!(pr.title.contains("break-glass"));
        assert!(pr.title.contains("emergency fix"));

        let branches = client.branches_created.lock().unwrap();
        assert_eq!(branches.len(), 1);
        assert!(branches[0].starts_with("break-glass/admin-"));

        let commits = client.commits_pushed.lock().unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].2, VALID_YAML); // content
    }

    #[tokio::test]
    async fn break_glass_validates_first() {
        let commit = signed_commit("sha-current", "dev@example.com");
        let client = MockGitClient::new(commit);

        let loader = GitOpsLoader::new(test_config());
        let result = loader
            .break_glass_edit(&client, INVALID_YAML, "bad config", "admin")
            .await;

        assert!(matches!(result, Err(GitOpsError::ValidationFailed(_))));
        // No branch or PR created.
        assert!(client.branches_created.lock().unwrap().is_empty());
        assert!(client.prs_opened.lock().unwrap().is_empty());
    }

    // -- Config tests ------------------------------------------------------

    #[test]
    fn default_config_values() {
        let cfg = GitOpsConfig::default();
        assert_eq!(cfg.branch, "main");
        assert_eq!(cfg.poll_interval_secs, 60);
        assert_eq!(cfg.config_path, "waf.yaml");
        assert!(cfg.require_signed_commits);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let cfg = test_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: GitOpsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.repo_url, cfg.repo_url);
        assert_eq!(parsed.allowed_signers.len(), 2);
    }

    // -- Error display tests -----------------------------------------------

    #[test]
    fn error_display_unsigned() {
        let e = GitOpsError::UnsignedCommit {
            sha: "abc".into(),
        };
        assert!(e.to_string().contains("unsigned"));
    }

    #[test]
    fn error_display_unknown_signer() {
        let e = GitOpsError::UnknownSigner {
            sha: "abc".into(),
            signer: "evil".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("evil"));
        assert!(msg.contains("abc"));
    }

    #[test]
    fn error_display_validation() {
        let e = GitOpsError::ValidationFailed("bad yaml".into());
        assert!(e.to_string().contains("validation failed"));
    }

    // -- Apply log tests ---------------------------------------------------

    #[test]
    fn apply_record_serialization() {
        let record = ApplyRecord {
            ts: Utc::now(),
            commit_sha: "sha-1".into(),
            commit_message: "msg".into(),
            author: "dev".into(),
            outcome: ApplyOutcome::Applied,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("Applied"));
    }

    #[test]
    fn apply_outcome_equality() {
        assert_eq!(ApplyOutcome::Applied, ApplyOutcome::Applied);
        assert_ne!(
            ApplyOutcome::Applied,
            ApplyOutcome::Rejected {
                reason: "x".into()
            }
        );
    }

    // -- Signature method tests --------------------------------------------

    #[test]
    fn signature_method_ssh() {
        let sig = CommitSignature {
            signer: "key".into(),
            method: SignatureMethod::Ssh,
            verified: true,
        };
        assert_eq!(sig.method, SignatureMethod::Ssh);
    }

    #[test]
    fn commit_signature_serialization() {
        let sig = CommitSignature {
            signer: "dev@example.com".into(),
            method: SignatureMethod::Gpg,
            verified: true,
        };
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("Gpg"));
        assert!(json.contains("dev@example.com"));
    }

    // -- Pull request tests ------------------------------------------------

    #[test]
    fn pull_request_serialization() {
        let pr = PullRequest {
            number: 1,
            url: "https://example.com/pr/1".into(),
            title: "test".into(),
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PullRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.number, 1);
    }
}
