---
id: 2026-05-17-high-gitops-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: GitOps · config sync
component: crates/aegis-control/src/gitops/mod.rs · crates/aegis-control/src/gitops/poll_driver.rs
interop_contract: §5.9 bonus + security posture
status: open
test_mode: source-review
---

# F-HIGH-gitops bundle — 4 issues in GitOps loader (beyond F-CRITICAL-005 dead-code core)

These items only matter once F-CRITICAL-005 is fixed (wire GitOps).
Filing them now so the fix lands with the right hardening included.

---

## G-01 · `git clone` runs synchronously on the tokio runtime with no timeout

**Component:** [gitops/poll_driver.rs:115-138](aegis-gate/crates/aegis-control/src/gitops/poll_driver.rs#L115-L138)

`git clone` shells out as a sync subprocess. The await pattern
masks this but the underlying `Command::status()` blocks. No timeout
configured.

A malicious / hanging git remote stalls the spawning task indefinitely.
Combined with shallow-clone depth of `50` (fine in practice) and no
disk-quota check on `work_dir`, this is remote-controlled DoS.

**Fix:**

```diff
-let status = Command::new("git")
-    .args(["clone", "--depth=50", &repo_url, work_dir.as_os_str()])
-    .status()
+let status = tokio::time::timeout(
+    cfg.gitops.clone_timeout.unwrap_or(Duration::from_secs(60)),
+    tokio::process::Command::new("git")
+        .args(["clone", "--depth=50", &repo_url, work_dir.as_os_str()])
+        .status()
+)
+.await
+.map_err(|_| GitOpsError::CloneTimeout)?
 .map_err(GitOpsError::GitFailed)?;
```

Add a disk-quota check before clone (refuse if `work_dir` parent has
< 2 GiB free).

---

## G-02 · `break_glass_edit` accepts X-Actor verbatim → markdown injection in PR body + branch-name pollution

**Component:** [gitops/mod.rs:308-343](aegis-gate/crates/aegis-control/src/gitops/mod.rs#L308-L343)

`break_glass_edit` embeds operator-supplied `actor` into:

- Branch name: `format!("break-glass/{}-{}", actor, ...)` — git
  tolerates most chars but `actor = "main; rm -rf /"` is fine for
  git itself (single arg), `actor = "*"` does weird globbing on the
  remote side.
- Markdown PR body: `format!("Direct API edit by **{actor}**...")`
  with no escaping → `actor = "<script>x</script>"` lands in GitHub
  PR markdown.

Combined with F-CRITICAL-004 (X-Actor spoof, proxy audit) and
F-CRITICAL-002 (no admin auth): unauthenticated attacker can craft
PRs in the source-of-truth repo with any author identity they choose.

**Fix:**

```rust
fn sanitize_actor(actor: &str) -> Result<String> {
    if actor.len() > 64 { return Err(BadActor); }
    if !actor.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '@' || c == '.') {
        return Err(BadActor);
    }
    Ok(actor.to_string())
}
```

Apply at entry to `break_glass_edit`. Escape MD in PR body
(`html_escape::encode_text` or similar).

Cross-fix with F-CRITICAL-004: actor should come from authenticated
session, not the X-Actor header.

---

## G-03 · `poll_driver::read_file` shells out `git show <sha>:<path>` with operator-controlled `path`

**Component:** [gitops/poll_driver.rs:297-302](aegis-gate/crates/aegis-control/src/gitops/poll_driver.rs#L297-L302)

`path` includes `..` is harmless to git (resolves inside repo) but
`path = "-"` makes git read stdin. `path = "--upload-pack=..."` is
passed as a single arg so command injection is not exploitable, but
the flag-injection class needs care.

**Fix:** pin the path character set:

```rust
if !path.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.') {
    return Err(BadPath);
}
if path.starts_with('-') {
    return Err(BadPath);
}
```

---

## G-04 · GitOps signed-commit verification implemented but unused

**Component:** [gitops/poll_driver.rs:220-255](aegis-gate/crates/aegis-control/src/gitops/poll_driver.rs#L220-L255)

Signed-commit verification code is complete and tested. The wiring
to actually invoke it on every sync is missing — because the whole
sync path is dead (F-CRITICAL-005).

When F-CRITICAL-005 lands, MUST also wire signed-commit verification:

```rust
async fn sync(...) {
    let head = client.head_sha(...).await?;
    if cfg.gitops.require_signed_commits {
        client.verify_signature(&head, &cfg.gitops.allowed_gpg_keys).await?;
    }
    ...
}
```

The README claim about "trusted-signed commits" only holds when this
is wired.

---

## Severity rationale

HIGH. All four are deferred until F-CRITICAL-005 lands (the core
GitOps wiring), but each must be addressed in the same PR or
GitOps becomes the attack surface that delivers the dashboard
exploits.
