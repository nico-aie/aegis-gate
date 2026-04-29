//! Concrete `GitClient` driver that shells out to the system
//! `git` binary (B3-T1 — Phase B).
//!
//! Why shell-out, not `gix` / `git2`:
//!
//! - **Lightest dep tree.** `tokio::process` is already pulled
//!   by `tokio = "full"`; pure-Rust `gix` adds ~50 transitive
//!   crates and `git2` adds a C dep tree.
//! - **Inherits operator config for free.** Auth flows
//!   through `git`'s credential helpers (`.git-credentials`,
//!   the OS keychain, the SSH agent). Signature verification
//!   uses the operator's existing GPG/SSH keyring via
//!   `git verify-commit`.
//! - **Easier to debug.** Operators can run the same
//!   subcommands manually to reproduce the driver's exact
//!   behaviour.
//!
//! ## Container note
//!
//! Deployments must include a `git` binary (≥ 2.20 for the
//! options used here). The `git` invocations: `clone`,
//! `fetch`, `rev-parse`, `verify-commit`, `show`,
//! `cat-file`, `log`. All standard.
//!
//! ## Lease gating
//!
//! This driver does **not** wrap itself in
//! `cluster_lease::spawn_with_lease("leader:gitops", ...)`
//! because `aegis-control` doesn't depend on `aegis-proxy`.
//! Boot wiring (in `aegis-proxy::run` or `aegis-bin`) is where
//! the lease wrap happens — same pattern as ACME today. A
//! TODO at the boot site documents the seam.

use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use tokio::process::Command;

use super::{
    CommitSignature, GitClient, GitCommit, GitOpsError, PullRequest, SignatureMethod,
};

/// Concrete poll driver: shells out to `git` against a local
/// working clone.
///
/// `work_dir` is a stable filesystem path the driver owns; it
/// clones into it on first call and reuses the worktree on
/// subsequent fetches. Operators provide a writable directory
/// (typically `<state-dir>/gitops/<repo-name>`) at boot.
pub struct GitPollDriver {
    work_dir: PathBuf,
    repo_url: String,
    branch: String,
    /// Path of the file the loader watches inside the repo
    /// (e.g. `waf.yaml`). Reserved for the "follow this file's
    /// last-modifying commit" enhancement; today the trait
    /// passes path explicitly via `read_file(sha, path)`, so
    /// this just records the operator's intent for future
    /// extensions.
    #[allow(dead_code)]
    config_path: String,
}

impl GitPollDriver {
    /// Build a driver. Use [`GitPollDriver::ensure_clone`] at
    /// boot to make sure the working clone exists before the
    /// first poll cycle.
    pub fn new(
        work_dir: impl Into<PathBuf>,
        repo_url: impl Into<String>,
        branch: impl Into<String>,
        config_path: impl Into<String>,
    ) -> Self {
        Self {
            work_dir: work_dir.into(),
            repo_url: repo_url.into(),
            branch: branch.into(),
            config_path: config_path.into(),
        }
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    /// Create the working clone if it doesn't already exist.
    /// Idempotent — re-running on an existing clone is a
    /// no-op. Call once at boot before spawning the poll
    /// loop.
    pub async fn ensure_clone(&self) -> Result<(), GitOpsError> {
        if self.work_dir.join(".git").exists() {
            return Ok(());
        }

        // Make the parent so `git clone` can land into a
        // fresh subdir. We don't pre-create `work_dir` itself
        // because `git clone` rejects a non-empty target.
        if let Some(parent) = self.work_dir.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                GitOpsError::FetchFailed(format!(
                    "creating gitops parent dir {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let work_dir_str = self
            .work_dir
            .to_str()
            .ok_or_else(|| {
                GitOpsError::FetchFailed("work_dir is not valid UTF-8".into())
            })?
            .to_string();

        let output = Command::new("git")
            .args([
                "clone",
                "--branch",
                &self.branch,
                "--depth",
                // Shallow-clone the latest 50 commits — enough
                // history for `verify-commit` chain checks
                // without pulling decades of repo history.
                "50",
                &self.repo_url,
                &work_dir_str,
            ])
            .output()
            .await
            .map_err(|e| GitOpsError::FetchFailed(format!("spawning git clone: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GitOpsError::FetchFailed(format!(
                "git clone failed: {stderr}"
            )));
        }
        Ok(())
    }

    /// Run `git` in the working clone with the given args.
    /// Returns stdout on success, error on non-zero exit.
    async fn git(&self, args: &[&str]) -> Result<String, GitOpsError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.work_dir)
            .args(args)
            .output()
            .await
            .map_err(|e| {
                GitOpsError::FetchFailed(format!(
                    "spawning git {}: {e}",
                    args.first().copied().unwrap_or("?")
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let cmd = args.join(" ");
            return Err(GitOpsError::FetchFailed(format!(
                "git {cmd} failed: {stderr}"
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Fetch + extract the branch's current HEAD commit metadata.
    async fn current_head(&self) -> Result<GitCommit, GitOpsError> {
        // Fetch first so we observe upstream changes.
        self.git(&["fetch", "origin", &self.branch]).await?;

        // Resolve to the SHA on the remote-tracking branch
        // (origin/<branch>) — never the local checkout, which
        // may have been mutated by an admin commit_and_push
        // call.
        let remote_ref = format!("origin/{}", self.branch);
        let sha = self
            .git(&["rev-parse", &remote_ref])
            .await?
            .trim()
            .to_string();

        let message = self
            .git(&["log", "-1", "--format=%B", &sha])
            .await?
            .trim_end_matches('\n')
            .to_string();
        let author = self
            .git(&["log", "-1", "--format=%an <%ae>", &sha])
            .await?
            .trim()
            .to_string();
        let unix = self
            .git(&["log", "-1", "--format=%at", &sha])
            .await?
            .trim()
            .parse::<i64>()
            .map_err(|e| GitOpsError::FetchFailed(format!("bad commit timestamp: {e}")))?;
        let timestamp = Utc
            .timestamp_opt(unix, 0)
            .single()
            .unwrap_or_else(Utc::now);

        let signature = self.read_signature(&sha).await;

        Ok(GitCommit {
            sha,
            message,
            author,
            timestamp,
            signature,
        })
    }

    /// Run `git verify-commit` and parse the result. Returns
    /// `None` for unsigned commits or when verification fails;
    /// the caller's signature-policy logic in
    /// `gitops::verify_signature` then rejects the commit if
    /// `require_signed_commits` is true.
    async fn read_signature(&self, sha: &str) -> Option<CommitSignature> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.work_dir)
            .args(["verify-commit", "--raw", sha])
            .output()
            .await
            .ok()?;

        // verify-commit writes its parseable output to stderr
        // even on success — the unix-tool convention here is
        // "stdout is for humans, stderr is structured".
        let stderr = String::from_utf8_lossy(&output.stderr);

        // No signature at all: stderr is empty / no GOODSIG.
        if !stderr.contains("GOODSIG") && !stderr.contains("VALIDSIG") {
            return None;
        }

        let signer = parse_signer(&stderr).unwrap_or_else(|| "unknown".to_string());
        let method = if stderr.contains("[GNUPG:] GOODSIG") {
            SignatureMethod::Gpg
        } else {
            // git supports SSH-signed commits with `gpg.format = ssh`;
            // both flow through verify-commit but produce
            // "git: Good \"git\" signature" on stderr without
            // GNUPG markers. Treat anything non-GNUPG as SSH.
            SignatureMethod::Ssh
        };

        Some(CommitSignature {
            signer,
            method,
            verified: true,
        })
    }
}

/// Parse the signer (key UID) from `git verify-commit --raw`'s
/// stderr output. Pure helper — usable from tests.
pub fn parse_signer(stderr: &str) -> Option<String> {
    // GPG output: `[GNUPG:] GOODSIG <KEYID> <UID>`
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("[GNUPG:] GOODSIG ") {
            // KEYID is hex; everything after the next space is the UID.
            let mut parts = rest.splitn(2, ' ');
            let _keyid = parts.next();
            if let Some(uid) = parts.next() {
                return Some(uid.trim().to_string());
            }
        }
        if let Some(rest) = line.strip_prefix("[GNUPG:] VALIDSIG ") {
            // VALIDSIG has the fingerprint as the first token.
            if let Some(fp) = rest.split_whitespace().next() {
                return Some(format!("gpg:{fp}"));
            }
        }
    }
    // SSH output: `Good "git" signature for <PRINCIPAL> with ...`
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("Good \"git\" signature for ") {
            // Take everything up to " with "
            if let Some(end) = rest.find(" with ") {
                return Some(rest[..end].trim().to_string());
            }
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[async_trait::async_trait]
impl GitClient for GitPollDriver {
    async fn fetch_head(&self) -> Result<GitCommit, GitOpsError> {
        self.current_head().await
    }

    async fn read_file(&self, sha: &str, path: &str) -> Result<String, GitOpsError> {
        // `git show <sha>:<path>` — works for both our branch
        // HEAD and arbitrary historical commits.
        let spec = format!("{sha}:{path}");
        self.git(&["show", &spec]).await
    }

    async fn create_branch(&self, _branch_name: &str) -> Result<(), GitOpsError> {
        // The poll driver is a read-only client. Operators
        // initiating "break-glass" admin changes should use a
        // separate client implementation that has push
        // credentials. Leaving this as an explicit error
        // rather than a silent no-op so the seam is obvious.
        Err(GitOpsError::BranchCreationFailed(
            "poll_driver is read-only; use a write-capable GitClient impl for break-glass admin changes".into(),
        ))
    }

    async fn commit_and_push(
        &self,
        _branch: &str,
        _path: &str,
        _content: &str,
        _message: &str,
    ) -> Result<String, GitOpsError> {
        Err(GitOpsError::BranchCreationFailed(
            "poll_driver is read-only".into(),
        ))
    }

    async fn open_pr(
        &self,
        _from_branch: &str,
        _to_branch: &str,
        _title: &str,
        _body: &str,
    ) -> Result<PullRequest, GitOpsError> {
        Err(GitOpsError::PrCreationFailed(
            "poll_driver is read-only — PR creation needs a forge-aware client (GitHub / GitLab API)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signer_from_gpg_goodsig() {
        let stderr = "[GNUPG:] NEWSIG\n\
                      [GNUPG:] GOODSIG ABC123DEF456 Alice Operator <alice@example.com>\n\
                      [GNUPG:] VALIDSIG ABC123DEF456...";
        let signer = parse_signer(stderr).unwrap();
        assert_eq!(signer, "Alice Operator <alice@example.com>");
    }

    #[test]
    fn parse_signer_from_validsig_when_no_goodsig() {
        // Some signed commits (e.g. expired keys with `--always`)
        // produce VALIDSIG without GOODSIG.
        let stderr = "[GNUPG:] VALIDSIG ABCDEF1234567890 2025-01-01 …";
        let signer = parse_signer(stderr).unwrap();
        assert_eq!(signer, "gpg:ABCDEF1234567890");
    }

    #[test]
    fn parse_signer_from_ssh() {
        let stderr =
            "Good \"git\" signature for alice@example.com with ED25519 key ...\n";
        let signer = parse_signer(stderr).unwrap();
        assert_eq!(signer, "alice@example.com");
    }

    #[test]
    fn parse_signer_from_ssh_without_with_clause() {
        let stderr = "Good \"git\" signature for alice@example.com\n";
        let signer = parse_signer(stderr).unwrap();
        assert_eq!(signer, "alice@example.com");
    }

    #[test]
    fn parse_signer_returns_none_for_no_signature() {
        // verify-commit writes nothing parseable for unsigned commits.
        assert!(parse_signer("").is_none());
        assert!(parse_signer("error: no signature").is_none());
    }

    #[test]
    fn driver_construction_smoke() {
        // No git invocation — just verify the constructor stores fields.
        let driver = GitPollDriver::new(
            "/tmp/gitops/test-repo",
            "https://github.com/example/repo.git",
            "main",
            "waf.yaml",
        );
        assert_eq!(driver.work_dir(), Path::new("/tmp/gitops/test-repo"));
        assert_eq!(driver.repo_url, "https://github.com/example/repo.git");
        assert_eq!(driver.branch, "main");
        assert_eq!(driver.config_path, "waf.yaml");
    }

    /// Live integration test: clones a tiny public repo, reads
    /// HEAD, asserts we got back something resembling a SHA.
    /// Gated on `AEGIS_GITOPS_INTEGRATION_TEST=1` because it
    /// needs network access + a `git` binary in PATH.
    ///
    /// Run with:
    ///
    /// ```sh
    /// AEGIS_GITOPS_INTEGRATION_TEST=1 \
    ///   cargo test -p aegis-control \
    ///     --lib gitops::poll_driver::tests::live_clone_and_fetch
    /// ```
    #[tokio::test]
    async fn live_clone_and_fetch() {
        if std::env::var("AEGIS_GITOPS_INTEGRATION_TEST").is_err() {
            eprintln!(
                "[gitops::poll_driver] skipped — set AEGIS_GITOPS_INTEGRATION_TEST=1 to run"
            );
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let driver = GitPollDriver::new(
            tmp.path().join("repo"),
            // git's own (tiny) self-hosted repo as a stable target.
            "https://github.com/git/git.git",
            "master",
            "README.md",
        );
        driver.ensure_clone().await.expect("clone");
        let head = driver.fetch_head().await.expect("fetch_head");
        assert_eq!(head.sha.len(), 40, "SHA-1 hash should be 40 hex chars");
        assert!(!head.author.is_empty());
        // README.md exists on git's master branch.
        let body = driver
            .read_file(&head.sha, "README.md")
            .await
            .expect("read_file");
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn read_file_against_unclonned_repo_errors_actionably() {
        // Construct a driver pointing at a never-cloned dir.
        // The `git -C` invocation should fail with a clear
        // error rather than panic.
        let tmp = tempfile::tempdir().expect("tempdir");
        let driver = GitPollDriver::new(
            tmp.path().join("does-not-exist"),
            "https://example.com/repo.git",
            "main",
            "waf.yaml",
        );
        let err = driver
            .read_file("0000000000000000000000000000000000000000", "waf.yaml")
            .await
            .unwrap_err();
        match err {
            GitOpsError::FetchFailed(msg) => {
                assert!(
                    msg.contains("git show") || msg.contains("not a git repository") || msg.contains("does-not-exist"),
                    "expected actionable error, got: {msg}"
                );
            }
            other => panic!("expected FetchFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_methods_return_explicit_error() {
        let driver = GitPollDriver::new(
            "/tmp/aegis-gitops-test-readonly",
            "https://example.com/repo.git",
            "main",
            "waf.yaml",
        );

        for result in [
            driver.create_branch("feature").await,
            driver
                .commit_and_push("feature", "waf.yaml", "x: 1", "test")
                .await
                .map(|_| ()),
            driver
                .open_pr("feature", "main", "title", "body")
                .await
                .map(|_| ()),
        ] {
            assert!(result.is_err(), "write methods must error");
        }
    }
}
