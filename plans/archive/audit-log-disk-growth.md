# Audit-log disk growth under sustained load

> **Status (2026-05-20): Designed, not started.** Surfaced by a
> memory soak (73k RPS attack flood for 90s) which grew
> `./waf_audit.log` to **9.1 GB in 90 seconds** (≈ 6 GB/min). Not
> a memory leak (the file write isn't RSS), but an unbounded
> **disk** growth vector under attack flood that matters for a
> benchmark/prod run.
>
> **Hard constraint — this is a committee requirement.** v2.5
> contract §6 is explicit:
>
> > `reset_state` MUST NOT delete, truncate, rotate, rewrite, or
> > otherwise modify `./waf_audit.log` or the configured audit-log
> > file. The audit log is evidence for organizer-side
> > correlation, backup verification, and post-run inspection, so
> > it MUST remain append-only across WAF state resets.
>
> So the obvious fix (in-run rotation/truncation) is **forbidden**
> for the contract evidence file during a run. That's why this is a
> design plan, not a quick patch.

## Why

- At 73k RPS of Detection traffic, every blocked request writes a
  JSONL line (~1.4 KB). 90s → ~6.6M lines → 9.1 GB.
- A judging host with a modest disk fills in minutes under an
  Attack-Battle flood, which could crash the WAF (write failures)
  mid-evaluation — ironically a worse contract failure than the
  disk pressure itself.
- Sampling / dropping audit lines is NOT an option: §6 + §5 require
  every request be correlatable (`X-WAF-Request-Id` ↔ audit
  `request_id`). Dropping lines breaks correlation scoring.

## Code anchor

- `crates/aegis-control/src/interop/audit.rs` — `MinimalJsonlSink`
  (`open()` uses `OpenOptions::append(true)`; one JSON line per
  Detection event). This is the contract evidence sink.
- `crates/aegis-proxy/src/run.rs` — sink opened at boot from
  `cfg.interop.audit_path` (default `./waf_audit.log`).
- `crates/aegis-control/src/api/attacks.rs` — the in-memory
  rolling-window aggregator is SEPARATE and now count-capped
  (`MAX_EVENTS`, 2026-05-20). This plan is only about the on-disk
  contract log.

## What we can and can't do

| Approach | Allowed by §6? | Verdict |
|---|---|---|
| In-run rotate/truncate `./waf_audit.log` | ❌ forbidden | Out |
| Sample / drop audit lines under flood | ❌ breaks correlation | Out |
| Compress the live file in place | ❌ "rewrite" | Out |
| Put the audit path on a large/sized volume | ✅ | **Yes — primary** |
| Rotate BETWEEN runs (operator action, WAF stopped) | ✅ (not a `reset_state` op) | **Yes — tooling** |
| Stream a *copy* to cold tier while keeping the live append-only file | ✅ (additive) | Yes — see cold-tier plan |
| Cap line size (truncate oversized field values per line) | ✅ (per-line, not the file) | Yes — bounds worst-case line, not count |

## Future plan

### Phase 1 — Operator guidance + boot-time disk guard (docs + ~40 LoC)

- Document the disk requirement in `deploy/STAGING-BENCHMARK.md`:
  size the audit-log volume for `peak_rps × line_bytes ×
  run_seconds` (worst case), e.g. ≥ 20 GB headroom for an
  Attack-Battle flood. Recommend a dedicated volume / tmpfs sized
  to the run.
- At boot, log the audit path's available disk and emit a WARN if
  it's below a configurable floor (`cfg.interop.audit_min_free_gb`,
  default 10). Cheap `statvfs`-style check; no behaviour change.
- Add a background low-disk WARN (re-check every N seconds) so the
  operator sees pressure before the write fails. This routes
  naturally into the new `AlertEvent` surface
  (`plans/future/alerts-refactor.md`) as a `DiskPressure` variant.

### Phase 2 — Per-line size bound (~30 LoC + test)

- Cap each JSONL line at a max byte length (e.g. 8 KB): truncate
  oversized field values with an explicit `"_truncated": true`
  marker. Bounds the worst-case line (a giant request body echoed
  into a field) without dropping the line — keeps correlation
  intact. This bounds line *size*, not line *count*.

### Phase 3 — Between-run rotation tooling (~60 LoC)

- A `waf audit rotate` subcommand (operator-invoked, WAF stopped or
  explicitly between runs — NOT a `reset_state` path) that
  timestamps + moves the current log and starts a fresh one.
  Documented as "only between benchmark runs; never during a run."
- Optionally gzip the rotated segment. The live file the contract
  points at is never touched mid-run.

### Phase 4 — Additive cold-tier stream (cross-ref)

- `plans/future/audit-cold-tier-export.md` already covers streaming
  audit data to S3/SFTP. Streaming a *copy* off-box (while the
  append-only file stays intact) lets the live file live on a
  smaller volume because the durable archive is elsewhere. Keep
  the two plans aligned.

## Restoration checklist

1. **Re-confirm the §6 wording in the current contract** before
   building — the "no rotate/truncate/rewrite" clause is the whole
   constraint. If a future contract revision relaxes it, Phase 3
   could become in-run.
2. **Disk guard must fail SAFE**, not fail the request path. A
   full disk should degrade the audit sink (WARN + drop-with-count,
   surfaced as a contract risk) rather than 500 the data plane —
   but confirm the OC's preference, since dropping audit lines is
   itself a §6 violation. The honest answer is "size the volume";
   the guard is a last-resort signal.
3. **Don't touch the `attacks.rs` aggregator** — already
   count-capped 2026-05-20; this plan is on-disk only.

## Sizing

| Piece | Est. LoC | Est. days |
|---|---|---|
| 1 — boot disk check + WARN + DiskPressure alert | ~60 | 1 |
| 2 — per-line size bound + test | ~40 | 0.5 |
| 3 — `waf audit rotate` subcommand | ~80 | 1 |
| 4 — cold-tier copy stream | (in cold-tier plan) | — |
| Docs (STAGING-BENCHMARK sizing) | ~20 | 0.5 |
| **Total (excl. cold-tier)** | **~200** | **~3 days** |

## Related

- `plans/future/audit-cold-tier-export.md` — off-box archival.
- `plans/future/alerts-refactor.md` — `DiskPressure` alert variant.
- v2.5 contract §6 (`Hackathon_Doc/EN_waf_interop_contract_v2.5.md`)
  — the binding append-only constraint.
