# Disaster Recovery & Backup (v2, enterprise)

> **Enterprise addendum.** RPO / RTO targets, backup surfaces, and
> restore drills for audit logs, state backend, secrets, and config.

## Purpose

Survive region loss, state-backend corruption, or accidental admin
destruction without losing audit evidence or security posture. Back
up what cannot be reconstructed; restore in a known order.

## What gets backed up

| Surface | Where | RPO | RTO | Notes |
|---|---|---|---|---|
| Config | Git repo (GitOps) | 0 | minutes | Signed commits |
| Admin change log | S3 + external witness | minutes | minutes | Tamper-evident |
| Security audit log | SIEM + S3 Object Lock | minutes | hours | Hash-chained |
| State backend (Redis/Raft) | Snapshot + AOF | 5 min | 30 min | Per-AZ |
| Secrets | Provider-native backup | n/a | minutes | Vault/KMS |
| TLS certs | Secrets provider | 0 | minutes | ACME re-issue if needed |
| Threat-intel cache | Re-fetched on startup | — | minutes | Not backed up |
| Device fingerprints | Best effort | — | hours | Regenerates naturally |

## Targets

- **RPO** ≤ 5 minutes for security state (blocks, risk, nonces)
- **RPO** = 0 for config (Git + signed commits)
- **RTO** ≤ 30 minutes for a region failover
- **RTO** ≤ 4 hours for a full cold-start region rebuild

## Cold-start order

1. Provision state backend (Redis / Raft) in the new region
2. Restore secrets provider access (Vault unseal / KMS IAM)
3. Start WAF nodes in warm-up mode (not-ready health probe)
4. Rehydrate state backend from snapshot
5. Pull latest config from Git
6. Run dry-run validator; abort cold start on failure
7. Restore TLS certs (file copy or ACME re-issue)
8. `/healthz/ready` passes; L4 LB adds nodes

## Audit log restore

Audit evidence is the hardest backup to replace. The sink stack
guarantees at-least-once delivery to the SIEM + S3 Object Lock, and
the hash chain is signed + witnessed externally. Restore procedure:

1. Fetch the S3 archive
2. Run `waf audit verify` to validate the chain against the witness
3. Replay into the SIEM in restore mode if needed

## State backend snapshots

- Redis: RDB snapshot every 5 min + AOF every 1 s, replicated across
  two AZs; S3 archive hourly
- Raft: log compaction + snapshot, replicated by consensus; S3 archive
  every compaction
- In-memory: not backed up (dev only)

## Secrets recovery

Secrets are never exported. Recovery is via the provider's own
mechanisms:

- Vault: Raft snapshot + unseal quorum
- AWS SM: KMS + IAM; restore from region replica
- GCP SM: version history
- Azure KV: soft-delete recovery
- PKCS#11 HSM: vendor's clustering / backup-card procedure

## Restore drills

A quarterly drill rebuilds a DR region from cold start and validates:

- Config applies clean
- State backend rehydrates
- Audit log verifies (hash chain + witness)
- Dashboard login via OIDC works
- Data plane accepts traffic within RTO

Drill results are themselves audit-logged as `operational` events
for SOC 2 evidence.

## Configuration

```yaml
dr:
  rpo_targets:
    config: 0
    state_backend_s: 300
    audit_log_s: 300
  rto_targets:
    failover_s: 1800
    cold_start_s: 14400
  snapshots:
    redis:
      rdb_interval_s: 300
      aof_sync: everysec
      s3_archive_interval_s: 3600
      s3_bucket: "waf-state-snapshots"
```

## Implementation

- `src/dr/snapshot.rs` — state-backend snapshot driver
- `src/dr/restore.rs` — rehydrate orchestrator
- `src/dr/drill.rs` — scripted drill harness
- `src/dr/audit_verify.rs` — hash-chain verifier CLI

## Performance notes

- Backups run off-hot-path on leader nodes
- AOF `everysec` adds ≤ 1 ms write latency
- Cold-start warm-up blocks readiness, never the data plane
