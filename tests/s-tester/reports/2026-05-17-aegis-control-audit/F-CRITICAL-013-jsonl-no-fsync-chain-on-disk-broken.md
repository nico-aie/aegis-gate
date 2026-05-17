---
id: 2026-05-17-jsonl-sink-no-fsync-no-chain
date: 2026-05-17T00:00Z
severity: CRITICAL
area: audit chain · persistent NDJSON sink
component: crates/aegis-control/src/audit/sinks/jsonl.rs · crates/aegis-control/src/audit/verify.rs · crates/aegis-control/src/audit/chain.rs
interop_contract: README "tamper-evident" claim · §6 audit log integrity · daily rotation
status: open
test_mode: source-review
---

# F-CRITICAL-013 · jsonl sink has NO fsync; chain on disk uses bare `AuditEvent` (not `ChainEntry`); cross-day chain linkage BROKEN

## Summary

Three compound bugs in the audit-on-disk path:

### Bug 1 — No fsync

[jsonl.rs:193-265](aegis-gate/crates/aegis-control/src/audit/sinks/jsonl.rs#L193-L265) calls `BufWriter::flush()` only. That drains the user-space
buffer into the kernel, NOT to disk. Power loss / OOM-kill loses up
to `max_batch = 100` events. README claims "tamper-evident audit log"
— operators reasonably assume durability that isn't there.

### Bug 2 — Disk format ≠ verifier format

The in-process `ChainWriter` at `audit/chain.rs:39` stores `ChainEntry`
(with `prev_hash` field linking to previous entry). But the jsonl
sink serializes plain `AuditEvent`s with NO `prev_hash` field
([jsonl.rs:262-264](aegis-gate/crates/aegis-control/src/audit/sinks/jsonl.rs#L262-L264)).

The verifier (`verify.rs:34`) deserializes each line as `ChainEntry`
and links via `prev_hash`. So:

- Running `waf audit verify --from /path/to/audit-YYYY-MM-DD.ndjson`
  on a sink-produced file → `ParseError` on every line.

The hash-chain integrity story breaks at the persistence layer.

### Bug 3 — Cross-day chain linkage broken

[verify.rs:25](aegis-gate/crates/aegis-control/src/audit/verify.rs#L25) starts every file at `genesis_hash()`. Daily rotation
creates a fresh file at midnight; the new file's first entry's
`prev_hash` should link to the LAST entry of the previous file —
but doesn't.

An attacker who can write to the audit directory can DELETE an
entire day's `audit-YYYY-MM-DD.ndjson` file → remaining files
individually verify clean (each restarts at genesis) → no detection.

## Observed code path

[jsonl.rs:262-264](aegis-gate/crates/aegis-control/src/audit/sinks/jsonl.rs#L262-L264):

```rust
writer.write_all(line.as_bytes())?;
writer.write_all(b"\n")?;
// NO writer.get_ref().sync_data() — buffer only.
// `line` is plain AuditEvent JSON, no prev_hash field.
```

[verify.rs:25,34](aegis-gate/crates/aegis-control/src/audit/verify.rs#L25):

```rust
let mut prev_hash = genesis_hash();   // always starts at genesis
for line in reader.lines() {
    let entry: ChainEntry = serde_json::from_str(&line)?;   // expects prev_hash field
    if entry.prev_hash != prev_hash { return Err(ChainBroken); }
    prev_hash = entry.hash;
}
```

`ChainEntry` expected on disk, `AuditEvent` actually written.

## Impact

- **README "tamper-evident"** — false at the persistence layer.
- **Architecture rubric 15/120** — claim of hash-chained NDJSON fails on inspection.
- **Operator durability story** — operators tuning retention TTLs and counting on append-only audit get up to 100 events of data loss per crash.
- **Multi-day attack masking** — deleting any single day's file leaves remaining days individually verify-clean.
- **CLI verifier currently fails on every file produced by the sink** — the verifier and sink agree on filename + line format but disagree on schema.

## Suggested fix

### Make the sink persist ChainEntry (not AuditEvent)

```diff
 // jsonl.rs::write_event
-let line = serde_json::to_string(&ev)?;
+// Wrap event in a ChainEntry linked to the running prev_hash.
+let chain_entry = self.chain_writer.append(ev);
+let line = serde_json::to_string(&chain_entry)?;
 writer.write_all(line.as_bytes())?;
 writer.write_all(b"\n")?;
```

`self.chain_writer` is the existing `ChainWriter` — make it live
alongside the sink (Arc-shared, single producer).

### fsync after batch

```diff
 // After batch loop ends:
+writer.flush()?;
+writer.get_ref().sync_data()?;   // O_DSYNC equivalent — durable to disk
```

Trade-off: per-batch fsync adds ~5 ms latency on rotational disks.
For SSD it's <1 ms. Operators can tune `max_batch` (already exists)
to amortize.

### Cross-day chain linkage

On daily rotation, the new file's first entry's `prev_hash` must
equal the last `entry.hash` of the previous file:

```rust
fn open_new_daily_file(prev_file_path: &Path, new_path: &Path) -> Result<(File, String)> {
    let prev_hash = if prev_file_path.exists() {
        // Tail the previous file, read its last line, extract `hash` field.
        tail_last_chain_entry(prev_file_path)?.hash
    } else {
        genesis_hash()
    };
    let file = File::options().append(true).create(true).open(new_path)?;
    Ok((file, prev_hash))
}
```

Update verifier to walk files in date order, propagating `prev_hash`
across file boundaries.

### Combine writes

[jsonl.rs:262-264](aegis-gate/crates/aegis-control/src/audit/sinks/jsonl.rs#L262-L264) does two `write_all` calls (line + `\n`). Not atomic — a torn write leaves a half-line. Combine:

```rust
let mut buf = line.into_bytes();
buf.push(b'\n');
writer.write_all(&buf)?;
```

## Verification

After all fixes:

```sh
# 1. Generate audit traffic.
make mock-load     # produces ~500 audit lines.

# 2. Verifier passes on the produced file.
./waf audit verify --from ./waf_audit.log
# Today: ParseError on line 1.
# After fix: "verified N entries from genesis at 2026-05-17T00:00:00 to hash abc..."

# 3. Cross-day: stop WAF at midnight, restart, generate more traffic.
# Verify across both files.
./waf audit verify --dir ./audit-logs/
# After fix: walks files in date order, asserts chain across rotation.

# 4. Tamper test: delete an audit line from the middle.
sed -i '5d' ./waf_audit.log
./waf audit verify --from ./waf_audit.log
# Expect: ChainBroken at line 5.
```

## Severity rationale

CRITICAL. Three compounding bugs in the audit-on-disk story. The
README's "tamper-evident" claim is the foundation of the
Architecture-rubric pitch. Today the verifier doesn't work on files
the sink produces. ~250 LoC to re-architect.
