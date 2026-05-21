---
id: 2026-05-17-audit-witness-dead-code
date: 2026-05-17T00:00Z
severity: CRITICAL
area: audit chain · witness export
component: crates/aegis-control/src/audit/witness.rs · crates/aegis-control/src/api/audit.rs (witness endpoint)
interop_contract: README claim "witness export" · Architecture rubric 15/120
status: open
test_mode: source-review (spot-verified via grep)
---

# F-CRITICAL-006 · `audit/witness.rs` is dead code — README's "witness export" claim is false; HMAC key has no source at all

## Summary

README claims the audit chain offers tamper-evident **witness export**:

> *Audit chain — SHA-256 hash-chained NDJSON sink with daily rotation
> + retention TTL, 8 SIEM sink formats, tamper-evident, **witness
> export**, CLI verifier.*

Spot-verified via `grep -rn "sign_chain_head\|WitnessState::update" crates/`:

All hits are inside `crates/aegis-control/src/audit/witness.rs:48-83`
— `#[cfg(test)]` blocks only. ZERO production callers.

Also: `sign_chain_head(head_hash, key: &[u8; 32], ...)` requires a
32-byte HMAC key. No config field, no env var, no key derivation, no
rotation path — i.e. **even if someone wired it, the key has no
source**.

The `/api/audit/witness` REST endpoint (per Agent A reading) always
returns `{last_signature_ts: null, ...}` because `WitnessState::update`
is never invoked.

## Observed code path

[audit/witness.rs:18](../../../../crates/aegis-control/src/audit/witness.rs#L18):

```rust
pub fn sign_chain_head(head_hash: &str, key: &[u8; 32], node_id: &str, entry_count: u64) -> WitnessRecord {
    // computes HMAC-SHA256(key, head_hash || node_id || entry_count) → WitnessRecord
}
```

```sh
$ grep -rn "sign_chain_head" crates/ --include="*.rs"
crates/aegis-control/src/audit/witness.rs:18:pub fn sign_chain_head(...)
crates/aegis-control/src/audit/witness.rs:48:        let record = sign_chain_head("abc123", &TEST_KEY, "node-1", 100);
crates/aegis-control/src/audit/witness.rs:54: ...
crates/aegis-control/src/audit/witness.rs:61: ...
# All tests. Zero production callers.
```

Same for `WitnessState::update` — only invoked from witness.rs's own
tests.

## Impact

- **README veracity** — "witness export" is a documented feature
  that doesn't exist at runtime.
- **Architecture rubric 15/120** — claim of "tamper-evident witness"
  is a graded item if BTC probes it.
- **Tamper-evidence ladder** — without periodic external witness
  signing, an attacker with file access can rewrite the entire chain
  in place (no off-system anchor to detect). The hash chain alone
  protects against MID-CHAIN tampering, not END tampering.
- **Combined with F-CRITICAL-013** (audit chain on disk uses bare
  `AuditEvent` not `ChainEntry`): even the basic on-disk tamper
  evidence is broken; the witness layer would have been the backstop.

## Suggested fix

### Path A — Wire it

1. Add `cfg.audit.witness.key_file: PathBuf` for the HMAC key (read
   once at boot; reject if missing or wrong size).
2. Spawn a periodic task that calls:

```rust
let head = chain_writer.head_hash();
let count = chain_writer.entry_count();
let record = sign_chain_head(&head, &key, &node_id, count);
witness_state.update(record);
```

   ...every N minutes (configurable, e.g. 5 min).

3. Expose `/api/audit/witness` already exists; it'll start returning
   real signatures once `update` runs.

4. Optionally export to an external witness service (Sigstore,
   timestamp authority) for end-to-end attestation.

### Path B — Delete

If witness export is out of scope for the deadline:
- Delete `audit/witness.rs` and its REST endpoint.
- Remove "witness export" from the README's audit-chain bullet.

The half-shipped state is the worst option — operators reading the
README assume it works.

## Verification

After Path A:

```sh
sleep 600   # wait for one witness tick

curl -sk "$HOST/api/audit/witness" | jq
# Expect:
# {
#   "last_signature_ts": "2026-05-17T01:23:45Z",
#   "head_hash": "abc123...",
#   "entry_count": 1234,
#   "node_id": "...",
#   "signature": "...",
# }
# Today: { "last_signature_ts": null, ... }
```

## Severity rationale

CRITICAL on README-veracity grounds + Architecture-rubric impact.
Dead-code module that the README explicitly claims as a feature.
~80 LoC to wire (key file + periodic task), or 50 LoC + README edit
to remove.
